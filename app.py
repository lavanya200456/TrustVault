import resend
import mimetypes
import os
import secrets
import base64
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, abort, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


app = Flask(__name__, instance_relative_config=True)
os.makedirs(app.instance_path, exist_ok=True)
os.makedirs(os.path.join(app.instance_path, "uploads"), exist_ok=True)

app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + os.path.join(app.instance_path, "trustvault.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = os.path.join(app.instance_path, "uploads")

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
CSRFProtect(app)

ALLOWED_EXTENSIONS = {"pdf", "txt", "docx", "xlsx", "png", "jpg", "jpeg"}


# ---------- DATABASE MODELS ----------

class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="viewer", nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=False)


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), unique=True, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=False)


class DocumentPermission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("document.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    can_download = db.Column(db.Boolean, default=False, nullable=False)

    __table_args__ = (db.UniqueConstraint("document_id", "user_id"),)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    company_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(80), nullable=False)
    details = db.Column(db.String(255), nullable=False)
    result = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


# ---------- HELPERS ----------

def normalize_company_name(name):
    return " ".join((name or "").split()).casefold()


def get_company(company_id):
    return db.session.get(Company, company_id)


def same_company(company_id_a, company_id_b):
    company_a = get_company(company_id_a)
    company_b = get_company(company_id_b)
    return bool(
        company_a and company_b
        and normalize_company_name(company_a.name)
        == normalize_company_name(company_b.name)
    )


def company_ids_for(company_id):
    company = get_company(company_id)
    if not company:
        return []
    target_name = normalize_company_name(company.name)
    return [
        item.id for item in Company.query.all()
        if normalize_company_name(item.name) == target_name
    ]


@login_manager.user_loader
def load_user(user_id):
    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


def audit(action, details, result="SUCCESS"):
    log = AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        company_id=current_user.company_id if current_user.is_authenticated else None,
        action=action,
        details=details[:255],
        result=result,
    )
    db.session.add(log)
    db.session.commit()


def roles_required(*roles):
    def decorator(function):
        @wraps(function)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.role not in roles:
                audit("ACCESS_DENIED", request.path, "DENIED")
                abort(403)
            return function(*args, **kwargs)
        return wrapper
    return decorator


def safe_local_next_url(target):
    """Accept only a local path, never an external redirect."""
    if not target:
        return None
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        return None
    return target


def get_document(document_id):
    document = db.session.get(Document, document_id)
    if document is None:
        abort(404)

    # Supports existing databases where the same company name has duplicate rows.
    if not same_company(document.company_id, current_user.company_id):
        audit("CROSS_COMPANY_ACCESS", f"Document {document_id}", "DENIED")
        abort(404)

    permission = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=current_user.id,
    ).first()

    is_owner = document.owner_id == current_user.id
    is_admin = current_user.role == "admin"
    if not (is_owner or is_admin or permission):
        audit("DOCUMENT_ACCESS", f"Document {document_id}", "DENIED")
        abort(403)

    return document, permission, is_owner, is_admin


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def send_share_email(to_email, document_name, share_url, file_path):
    """Send the shared document using the Resend email API.

    Configure RESEND_API_KEY and TRUSTVAULT_EMAIL_FROM in the environment.
    TRUSTVAULT_EMAIL_FROM must be a sender/domain authorized by your Resend
    account. Attachments are base64-encoded as required by the email API.
    """
    api_key = os.environ.get("RESEND_API_KEY", "").strip()
    sender = os.environ.get("TRUSTVAULT_EMAIL_FROM", "").strip()

    if not api_key:
        raise RuntimeError("RESEND_API_KEY is missing.")
    if not sender:
        raise RuntimeError("TRUSTVAULT_EMAIL_FROM is missing.")
    if not os.path.isfile(file_path):
        raise FileNotFoundError("Document file not found.")

    # Keep the configured API key local to this process.
    resend.api_key = api_key

    with open(file_path, "rb") as document_file:
        encoded_attachment = base64.b64encode(document_file.read()).decode("ascii")

    result = resend.Emails.send({
        "from": sender,
        "to": [to_email],
        "subject": "TrustVault: Document shared with you",
        "text": (
            f'Hello,\\n\\n'
            f'The document "{document_name}" has been shared with you '
            f'through TrustVault.\\n\\n'
            f"Open TrustVault here:\\n{share_url}\\n\\n"
            "Sign in with your registered account to access the shared document.\\n"
            "The shared document is also attached to this email."
        ),
        "attachments": [{
            "filename": document_name,
            "content": encoded_attachment,
        }],
    })

    # The API accepting the request is not a guarantee of inbox delivery.
    app.logger.info("Resend accepted TrustVault share email; response: %s", result)


def external_trustvault_url(endpoint, **values):
    """Use a configured public URL (e.g. deployed HTTPS URL or ngrok URL)."""
    base_url = os.environ.get("TRUSTVAULT_BASE_URL", "").strip().rstrip("/")
    if base_url:
        return base_url + url_for(endpoint, **values)
    return url_for(endpoint, _external=True, **values)


# ---------- REGISTRATION AND LOGIN ----------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        company_name = " ".join(request.form.get("company", "").split())

        if not all([name, email, password, company_name]):
            flash("Please fill in every field.")
            return redirect(url_for("register"))

        if len(password) < 12:
            flash("Use a password with at least 12 characters.")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("An account with that email already exists.")
            return redirect(url_for("register"))

        # Reuse company records when names match, ignoring case/extra spaces.
        company = next(
            (item for item in Company.query.all()
             if normalize_company_name(item.name) == normalize_company_name(company_name)),
            None,
        )
        if company is None:
            company = Company(name=company_name)
            db.session.add(company)
            db.session.flush()

        user = User(
            name=name,
            email=email,
            password_hash=generate_password_hash(password),
            role="admin",
            company_id=company.id,
        )
        db.session.add(user)
        db.session.commit()

        login_user(user)
        audit("REGISTER", "User registered")
        return redirect(url_for("dashboard"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            audit("LOGIN", "User logged in")
            next_url = safe_local_next_url(request.args.get("next"))
            return redirect(next_url or url_for("dashboard"))

        audit("LOGIN", "Invalid login attempt", "DENIED")
        flash("Invalid email or password.")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("LOGOUT", "User logged out")
    logout_user()
    return redirect(url_for("login"))


# ---------- DOCUMENT DASHBOARD ----------

@app.route("/")
@login_required
def dashboard():
    permissions = DocumentPermission.query.filter_by(user_id=current_user.id).all()
    shared_ids = [permission.document_id for permission in permissions]
    matching_company_ids = company_ids_for(current_user.company_id)

    query = Document.query.filter(Document.company_id.in_(matching_company_ids))
    if current_user.role != "admin":
        query = query.filter(
            db.or_(
                Document.owner_id == current_user.id,
                Document.id.in_(shared_ids),
            )
        )

    documents = query.order_by(Document.id.desc()).all()
    return render_template("dashboard.html", documents=documents)


# ---------- UPLOAD DOCUMENTS ----------

@app.route("/upload", methods=["POST"])
@roles_required("admin", "manager")
def upload():
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Choose a file first.")
        return redirect(url_for("dashboard"))

    if not allowed_file(file.filename):
        flash("This file type is not allowed.")
        audit("UPLOAD", "Rejected file type", "DENIED")
        return redirect(url_for("dashboard"))

    original_name = secure_filename(file.filename)
    if not original_name:
        flash("Invalid filename.")
        return redirect(url_for("dashboard"))

    stored_name = secrets.token_hex(16) + "_" + original_name
    path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)

    document = Document(
        original_name=original_name,
        stored_name=stored_name,
        owner_id=current_user.id,
        company_id=current_user.company_id,
    )

    try:
        file.save(path)
        db.session.add(document)
        db.session.flush()
        db.session.add(AuditLog(
            user_id=current_user.id,
            company_id=current_user.company_id,
            action="UPLOAD",
            details=f"Document {document.id}",
            result="SUCCESS",
        ))
        db.session.commit()
        flash("Document uploaded successfully.")
    except Exception:
        db.session.rollback()
        if os.path.exists(path):
            os.remove(path)
        app.logger.exception("Document upload failed")
        flash("Upload failed. Please try again.")

    return redirect(url_for("dashboard"))


# ---------- SHARE DOCUMENT AND EMAIL PUBLIC LINK ----------

@app.route("/share/<int:document_id>", methods=["POST"])
@roles_required("admin", "manager")
def share(document_id):
    document = db.session.get(Document, document_id)
    if document is None or not same_company(document.company_id, current_user.company_id):
        abort(404)

    if current_user.role != "admin" and document.owner_id != current_user.id:
        audit("SHARE", f"Document {document_id}", "DENIED")
        abort(403)

    email = request.form.get("email", "").strip().lower()
    user = User.query.filter_by(email=email).first()

    if not user:
        flash("No registered account found for that email. Ask the recipient to register first.")
        return redirect(url_for("dashboard"))

    if not same_company(user.company_id, current_user.company_id):
        flash("That account is registered under a different company name.")
        return redirect(url_for("dashboard"))

    if user.id == document.owner_id:
        flash("The owner already has access.")
        return redirect(url_for("dashboard"))

    permission = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=user.id,
    ).first()

    if permission is None:
        permission = DocumentPermission(document_id=document.id, user_id=user.id)
        db.session.add(permission)

    permission.can_download = request.form.get("can_download") == "yes"

    db.session.add(AuditLog(
        user_id=current_user.id,
        company_id=current_user.company_id,
        action="SHARE",
        details=f"Document {document.id} shared with user {user.id}",
        result="SUCCESS",
    ))
    db.session.commit()

    try:
        # Email links must use the public HTTPS deployment URL, never localhost.
        base_url = os.environ.get("TRUSTVAULT_BASE_URL", "").strip().rstrip("/")
        if not base_url.startswith("https://"):
            raise RuntimeError(
                "Set TRUSTVAULT_BASE_URL to your public HTTPS TrustVault URL."
            )
        share_url = base_url + url_for("login", next=url_for("dashboard"))

        
        file_path = os.path.join(
            app.config["UPLOAD_FOLDER"],
            document.stored_name
        )

        send_share_email(
            user.email,
            document.original_name,
            share_url,
            file_path
        )

        audit("SHARE_EMAIL", f"Notification sent for document {document.id}")
        flash("Document shared and email sent successfully.")

    except Exception:
        app.logger.exception("TrustVault email delivery failed")
        audit(
            "SHARE_EMAIL",
            f"Email delivery failed for document {document.id}",
            "FAILED",
        )
        flash("Permission saved, but email failed. Check the terminal for details.")

    return redirect(url_for("dashboard"))



# ---------- SECURE DOWNLOAD ----------

@app.route("/download/<int:document_id>")
@login_required
def download(document_id):
    document, permission, is_owner, is_admin = get_document(document_id)

    if not (is_owner or is_admin or (permission and permission.can_download)):
        audit("DOWNLOAD", f"Document {document_id}", "DENIED")
        abort(403)

    path = os.path.join(app.config["UPLOAD_FOLDER"], document.stored_name)
    if not os.path.isfile(path):
        abort(404)

    audit("DOWNLOAD", f"Document {document.id}")
    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document.stored_name,
        as_attachment=True,
        download_name=document.original_name,
    )


# ---------- AUDIT LOG ----------

@app.route("/audit")
@roles_required("admin")
def audit_page():
    logs = AuditLog.query.filter_by(
        company_id=current_user.company_id
    ).order_by(AuditLog.id.desc()).limit(200).all()
    return render_template("audit.html", logs=logs)


# ---------- ADMIN: CREATE EMPLOYEES ----------

@app.route("/users", methods=["POST"])
@roles_required("admin")
def create_user():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer").strip().lower()

    if not name or not email or len(password) < 12:
        flash("Enter a name, email, and password of at least 12 characters.")
        return redirect(url_for("dashboard"))

    if role not in {"manager", "viewer"}:
        flash("Choose a valid employee role.")
        return redirect(url_for("dashboard"))

    if User.query.filter_by(email=email).first():
        flash("An account with that email already exists.")
        return redirect(url_for("dashboard"))

    user = User(
        name=name,
        email=email,
        password_hash=generate_password_hash(password),
        role=role,
        company_id=current_user.company_id,
    )
    db.session.add(user)
    db.session.commit()
    audit("USER_CREATED", f"Created {role} account")
    flash("Employee account created.")
    return redirect(url_for("dashboard"))


# ---------- ERROR HANDLING ----------

@app.errorhandler(403)
def forbidden(error):
    return "Access denied. You do not have permission.", 403


@app.errorhandler(404)
def not_found(error):
    return "Resource not found.", 404


@app.errorhandler(413)
def too_large(error):
    return "File exceeds the 10 MB limit.", 413


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    print("TrustVault starting on port 5000...", flush=True)
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
