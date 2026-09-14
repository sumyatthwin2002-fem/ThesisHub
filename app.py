import io
import os
import re
import random
from functools import wraps
from datetime import datetime, timezone
import boto3
from botocore.exceptions import NoCredentialsError
from dotenv import load_dotenv
from flask import Flask, flash, redirect, render_template, request, session, url_for, send_file, abort
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Load Environment Variables
load_dotenv()

app = Flask(__name__)

# Security Hardening for Flask Session
app.secret_key = os.getenv("FLASK_SECRET_KEY", "default_secret_key_change_in_production")
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 1800

# Database Credentials
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "my_project_thesishub")

# MySQL Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# File Upload Configuration
ALLOWED_EXTENSIONS = {'pdf'}
MAX_FILE_SIZE = 16 * 1024 * 1024
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# AWS S3 Configuration
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-2")
S3_BUCKET = os.getenv("S3_BUCKET")

s3_client = boto3.client(
    's3',
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)

# Department Keys
ADMIN_DEPARTMENT_KEYS = {
    "PRINCIPAL": os.getenv("ADMIN_KEY_PRINCIPAL"),
    "EC": os.getenv("ADMIN_KEY_EC"),
    "EP": os.getenv("ADMIN_KEY_EP"),
    "MP": os.getenv("ADMIN_KEY_MP"),
    "CIVIL": os.getenv("ADMIN_KEY_CIVIL")
}

TEACHER_DEPARTMENT_KEYS = {
    "EC": os.getenv("TEACHER_KEY_EC"),
    "EP": os.getenv("TEACHER_KEY_EP"),
    "MP": os.getenv("TEACHER_KEY_MP"),
    "CIVIL": os.getenv("TEACHER_KEY_CIVIL")
}

# Email Configuration
app.config["MAIL_SERVER"] = os.getenv("MAIL_SERVER")
app.config["MAIL_PORT"] = int(os.getenv("MAIL_PORT", 587))
app.config["MAIL_USE_TLS"] = os.getenv("MAIL_USE_TLS", "True") == "True"
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")

mail = Mail(app)
db = SQLAlchemy(app)

# Security Decorators
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin_id" not in session:
            flash("Unauthorized access! Please login as an admin.", "error")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function

def teacher_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "teacher_id" not in session:
            flash("Unauthorized access! Please login as a teacher.", "error")
            return redirect(url_for("teacher_login"))
        return f(*args, **kwargs)
    return decorated_function

def student_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "student_id" not in session:
            flash("Unauthorized access! Please login as a student.", "error")
            return redirect(url_for("student_login"))
        return f(*args, **kwargs)
    return decorated_function

# ORM Models
class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Teacher(db.Model):
    __tablename__ = 'teachers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    roll_no = db.Column(db.String(50), nullable=False)
    department = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    search_logs = db.relationship('SearchHistory', backref='student', lazy=True)

class Category(db.Model):
    __tablename__ = 'categories'
    id = db.Column(db.Integer, primary_key=True)
    department = db.Column(db.String(50), nullable=False)
    category_name = db.Column(db.String(100), nullable=False)
    __table_args__ = (
        db.UniqueConstraint('department', 'category_name', name='unique_dept_category'),
    )

class ThesisFile(db.Model):
    __tablename__ = 'thesis_files'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    uploaded_by = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(500), nullable=True)
    author = db.Column(db.String(500), nullable=True)
    pub_year = db.Column(db.Integer, nullable=True)
    abstract = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class SearchHistory(db.Model):
    __tablename__ = 'search_history'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=True)
    student_name = db.Column(db.String(100), nullable=True)
    roll_no = db.Column(db.String(100), nullable=True)
    department = db.Column(db.String(100), nullable=True)
    search_keyword = db.Column(db.String(255), nullable=False)
    searched_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class Feedback(db.Model):
    __tablename__ = 'feedbacks'
    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(100), nullable=False)
    user_role = db.Column(db.String(50), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# Helper Functions
def allowed_file(file_input):
    if isinstance(file_input, str):
        filename = file_input
        file_storage = None
    else:
        file_storage = file_input
        filename = file_storage.filename if file_storage else ""

    is_ext_valid = '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
    if not is_ext_valid:
        return False
    if file_storage and hasattr(file_storage, 'read'):
        header = file_storage.read(4)
        file_storage.seek(0)
        return header == b'%PDF'
    return True

# Updated send_email with reply_to support
def send_email(to_email, subject, body, reply_to=None):
    try:
        with app.app_context():
            msg = Message(
                subject,
                sender=os.getenv("MAIL_USERNAME"),
                recipients=[to_email],
                reply_to=reply_to
            )
            msg.body = body
            mail.send(msg)
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def validate_password(password):
    if len(password) < 6:
        return False, "Password must be at least 6 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password):
        return False, "Password must contain at least one special character."
    return True, ""

def redirect_admin_dashboard():
    if session.get("admin_dept", "").upper() == "PRINCIPAL":
        return redirect(url_for("principal_dashboard"))
    return redirect(url_for("dept_admin_dashboard"))

# General Routes
@app.route('/')
def home():
    return render_template('welcome.html')

@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if 'student_id' not in session:
        flash("You are not registered yet, so you cannot use this service. Please register first.", "error")
        return redirect(url_for('student_register')) # သင့် project ရှိ student register သို့မဟုတ် login route အမည်ဖြင့် ပြောင်းလဲနိုင်ပါသည်

    if request.method == 'POST':
        user_name = session.get('student_name', 'Student').strip()
        user_role = 'Student'
        rating = request.form.get('rating')
        comment = request.form.get('comment', '').strip()

        if not rating or not comment:
            flash("Please provide both a rating and a comment.", "error")
            return redirect(url_for('feedback'))

        try:
            new_feedback = Feedback(
                user_name=user_name,
                user_role=user_role,
                rating=int(rating),
                comment=comment
            )
            db.session.add(new_feedback)
            db.session.commit()

            admin_emails = [admin.email for admin in Admin.query.all() if admin.email]
            if not admin_emails:
                fallback_email = os.getenv("MAIL_USERNAME")
                if fallback_email:
                    admin_emails = [fallback_email]

            rating_num = int(rating)
            stars = "★" * rating_num + "☆" * (5 - rating_num)
            email_body = f"""New User Feedback Received on ThesisHub!\nName: {user_name}\nRole: {user_role}\nRating: {stars} ({rating_num}/5)\nComment:\n{comment}"""

            for admin_email in admin_emails:
                send_email(
                    to_email=admin_email,
                    subject=f"[ThesisHub Feedback] New Review from {user_name}",
                    body=email_body
                )

            flash("Thank you! Your feedback has been submitted successfully.", "success")
            return redirect(url_for('feedback'))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred while submitting feedback.", "error")

    all_feedbacks = Feedback.query.order_by(Feedback.created_at.desc()).all()
    return render_template('feedback.html', feedbacks=all_feedbacks)


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if 'student_id' not in session:
        flash("You are not registered yet, so you cannot use this service. Please register first.", "error")
        return redirect(url_for('student_register'))

    if request.method == 'POST':
        sender_name = request.form.get('name', '').strip()
        sender_email = request.form.get('email', '').strip()
        subject = request.form.get('subject', 'ThesisHub Contact Message').strip()
        message_body = request.form.get('message', '').strip()
        department = request.form.get('department', '').strip().upper()

        if not message_body or not sender_email:
            flash("Please fill in all required fields including your email.", "error")
            return redirect(url_for('contact'))

        # Database မှ Department နှင့် ကိုက်ညီသော Admin ကို ရှာမည်
        target_admin = Admin.query.filter(db.func.upper(db.func.trim(Admin.department)) == department).first()

        # Terminal တွင် Admin တွေ့မတွေ့ စစ်ဆေးရန် (Debug)
        print(
            f"--- DEBUG --- Selected Dept: {department}, Found Admin: {target_admin}, Admin Email: {target_admin.email if (target_admin and target_admin.email) else 'None'}")

        if target_admin and target_admin.email:
            recipient_email = target_admin.email.strip()
        else:
            recipient_email = os.getenv("MAIL_USERNAME")
            print(
                f"--- WARNING --- Admin not found or email is empty for {department}. Falling back to MAIL_USERNAME: {recipient_email}")

        full_email_body = f"Department: {department}\nSender Name: {sender_name}\nSender Email: {sender_email}\n\nMessage:\n{message_body}"

        email_sent = send_email(
            to_email=recipient_email,
            subject=f"[ThesisHub Inquiry] {subject}",
            body=full_email_body,
            reply_to=sender_email
        )

        if email_sent:
            flash(f'Your message has been sent successfully to the {department} administrator.', 'success')
        else:
            flash('Failed to send email. Please try again later.', 'error')

        return redirect(url_for('contact'))

    return render_template('contact.html')

@app.route("/thesis/abstract/<int:thesis_id>")
def thesis_abstract(thesis_id):
    thesis = ThesisFile.query.get_or_404(thesis_id)
    return render_template("thesis_abstract.html", thesis=thesis)

@app.route("/thesis/download_abstract/<int:thesis_id>")
def download_abstract_pdf(thesis_id):
    thesis = ThesisFile.query.get_or_404(thesis_id)
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    p.setFont("Helvetica-Bold", 16)
    p.drawString(100, 750, f"Title: {thesis.title}")
    p.setFont("Helvetica", 12)
    p.drawString(100, 725, f"Author: {thesis.author or 'N/A'}")
    p.drawString(100, 705, f"Department: {thesis.department}")
    p.drawString(100, 685, f"Category: {thesis.category or 'General'}")
    p.drawString(100, 665, f"Publication Year: {thesis.pub_year or 'N/A'}")
    p.line(100, 650, 500, 650)
    p.setFont("Helvetica-Bold", 14)
    p.drawString(100, 625, "Abstract:")
    p.setFont("Helvetica", 10)
    text_object = p.beginText(100, 605)
    text_object.setLeading(14)
    abstract_text = thesis.abstract or "No abstract content available."
    words = abstract_text.split()
    line = ""
    for word in words:
        if len(line + word) < 80:
            line += word + " "
        else:
            text_object.textLine(line)
            line = word + " "
    if line:
        text_object.textLine(line)
    p.drawText(text_object)
    p.showPage()
    p.save()
    buffer.seek(0)
    safe_title = "".join(c for c in thesis.title if c.isalnum() or c in (' ', '_')).rstrip()
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"{safe_title}_Abstract.pdf",
        mimetype="application/pdf"
    )

@app.route("/thesis/stream/<int:thesis_id>")
def stream_thesis_pdf(thesis_id):
    if "teacher_id" not in session and "student_id" not in session:
        flash("Please log in to view the document.", "error")
        return redirect(url_for("student_login"))
    thesis = ThesisFile.query.get_or_404(thesis_id)
    if S3_BUCKET and S3_BUCKET in thesis.file_path:
        s3_key = thesis.file_path.split(f"{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/")[-1]
    else:
        s3_key = thesis.file_path
    try:
        s3_obj = s3_client.get_object(Bucket=S3_BUCKET, Key=s3_key)
        return send_file(
            io.BytesIO(s3_obj['Body'].read()),
            mimetype='application/pdf',
            as_attachment=False,
            download_name=f"{thesis.title}.pdf"
        )
    except Exception as e:
        flash("Failed to load PDF file from S3 storage.", "error")
        if session.get("role") == "teacher":
            return redirect(url_for("teacher_dashboard"))
        return redirect(url_for("student_main"))

# Admin Routes
@app.route("/admin/register", methods=["GET", "POST"])
def admin_register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        department = request.form.get("department", "").strip().upper()
        email = request.form.get("email", "").strip()
        access_key = request.form.get("access_key", "").strip()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for("admin_register"))

        is_valid, msg = validate_password(password)
        if not is_valid:
            flash(msg, "error")
            return redirect(url_for("admin_register"))

        current_admin_count = Admin.query.filter(
            db.func.upper(Admin.department) == department
        ).count()
        if current_admin_count >= 1:
            flash(f"Admin limit reached! Only 1 admin is allowed for {department}.", "error")
            return redirect(url_for("admin_register"))

        expected_key = ADMIN_DEPARTMENT_KEYS.get(department)
        if not expected_key or access_key != expected_key:
            flash(f"Invalid Admin Access Key for {department} department!", "error")
            return redirect(url_for("admin_register"))

        if Admin.query.filter_by(email=email).first():
            flash("This email address is already registered!", "error")
            return redirect(url_for("admin_register"))

        try:
            hashed_password = generate_password_hash(password)
            new_admin = Admin(name=name, department=department, email=email, password=hashed_password)
            db.session.add(new_admin)
            db.session.commit()
            flash("Admin registration successful! Please log in.", "success")
            return redirect(url_for("admin_login"))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred during registration.", "error")
    return render_template("admin_register.html")

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password")
        access_key = request.form.get("access_key", "").strip()

        admin = Admin.query.filter_by(email=email, name=name).first()
        if not admin:
            flash("Your account is not registered yet. Please register first.", "error")
            return redirect(url_for("admin_login"))
        if admin.name.strip() != name:
            flash("Invalid Admin Name!", "error")
            return redirect(url_for("admin_login"))

            # Password မကိုက်ညီပါက စစ်ဆေးရန်
        if not check_password_hash(admin.password, password):
            flash("Invalid Password!", "error")
            return redirect(url_for("admin_login"))
        if admin and check_password_hash(admin.password, password):
            dept_upper = admin.department.strip().upper()
            expected_key = ADMIN_DEPARTMENT_KEYS.get(dept_upper)
            if not expected_key or access_key != expected_key:
                flash("Invalid Access Key for your assigned department!", "error")
                return redirect(url_for("admin_login"))

            otp = str(random.randint(100000, 999999))
            session["pending_admin_id"] = admin.id
            session["pending_admin_name"] = admin.name
            session["pending_admin_email"] = admin.email
            session["admin_dept"] = dept_upper
            session["admin_otp"] = otp

            send_email(
                admin.email,
                "ThesisHub Admin Verification Code",
                f"Hello {admin.name},\n\nYour Admin Verification Code is: {otp}\n\nPlease enter this code to access your {dept_upper} Admin Dashboard."
            )
            flash("A verification code has been sent to your email address.", "info")
            return redirect(url_for("admin_verify_otp"))
        else:
            flash("Invalid Admin Name, Email, or Password!", "error")
    return render_template("admin_login.html")

@app.route("/admin/verify-otp", methods=["GET", "POST"])
def admin_verify_otp():
    if "pending_admin_id" not in session:
        flash("Please log in first!", "error")
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        user_otp = request.form.get("otp", "").strip()
        if user_otp and user_otp == session.get("admin_otp"):
            session["admin_id"] = session.get("pending_admin_id")
            session["admin_name"] = session.get("pending_admin_name")
            session["admin_email"] = session.get("pending_admin_email")
            admin_dept = session.get("admin_dept", "")

            login_time = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")
            send_email(
                session["admin_email"],
                "ThesisHub Admin Login Alert",
                f"Hello {session['admin_name']},\n\nYou logged into {admin_dept} Admin Account at {login_time}."
            )

            session.pop("admin_otp", None)
            session.pop("pending_admin_id", None)
            session.pop("pending_admin_name", None)
            session.pop("pending_admin_email", None)

            flash("Logged in successfully!", "success")
            return redirect_admin_dashboard()
        else:
            flash("Invalid verification code! Please try again.", "error")
    return render_template("admin_verify_otp.html")

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    return redirect_admin_dashboard()

@app.route("/admin/principal/dashboard")
@admin_required
def principal_dashboard():
    if session.get("admin_dept", "").upper() != "PRINCIPAL":
        flash("Access restricted to Principal Super Admin.", "error")
        return redirect(url_for("dept_admin_dashboard"))

    all_theses = ThesisFile.query.order_by(ThesisFile.id.desc()).all()
    all_admins = Admin.query.order_by(Admin.id.desc()).all()
    all_teachers = Teacher.query.order_by(Teacher.id.desc()).all()
    all_students = Student.query.order_by(Student.id.desc()).all()

    return render_template("principal_dashboard.html", theses=all_theses, admins=all_admins, teachers=all_teachers, students=all_students)

@app.route("/admin/principal/dept-admin/delete/<int:admin_id>", methods=["POST"])
@admin_required
def delete_dept_admin(admin_id):
    if session.get("admin_dept") != "PRINCIPAL":
        flash("Access restricted to Principal Super Admin.", "error")
        return redirect(url_for("dept_admin_dashboard"))

    admin_to_delete = Admin.query.get(admin_id)

    # Self-deletion guard
    if admin_to_delete and admin_to_delete.id == session.get("admin_id"):
        flash("You cannot delete your own Principal account!", "error")
        return redirect(url_for("principal_dashboard"))

    if admin_to_delete:
        try:
            db.session.delete(admin_to_delete)
            db.session.commit()
            flash(f"Department Admin '{admin_to_delete.name}' ({admin_to_delete.department}) deleted successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error deleting admin: {str(e)}", "error")
    else:
        flash("Admin account not found!", "error")

    return redirect(url_for("principal_dashboard"))


@app.route("/admin/dept/dashboard")
@admin_required
def dept_admin_dashboard():
    admin_dept = (session.get("admin_dept") or "").strip()
    is_principal = admin_dept.upper() in ["PRINCIPAL", "ALL", "ADMIN"]

    if is_principal:
        dept_theses = ThesisFile.query.order_by(ThesisFile.id.desc()).all()
        dept_students = Student.query.order_by(Student.id.desc()).all()
        dept_teachers = Teacher.query.order_by(Teacher.id.desc()).all()
        categories = Category.query.all()
        # Principal က အားလုံးရဲ့ search history ကို ကြည့်နိုင်သည်
        search_logs = SearchHistory.query.order_by(SearchHistory.id.desc()).all()
    else:
        dept_theses = ThesisFile.query.filter(
            db.func.lower(db.func.trim(ThesisFile.department)) == admin_dept.lower()
        ).order_by(ThesisFile.id.desc()).all()
        dept_students = Student.query.filter(
            db.func.lower(db.func.trim(Student.department)) == admin_dept.lower()
        ).order_by(Student.id.desc()).all()
        dept_teachers = Teacher.query.filter(
            db.func.lower(db.func.trim(Teacher.department)) == admin_dept.lower()
        ).order_by(Teacher.id.desc()).all()
        categories = Category.query.filter(
            db.func.lower(db.func.trim(Category.department)) == admin_dept.lower()
        ).all()

        # [ပြင်ဆင်ချက်] Department Admin သည် မိမိမေဂျာမှ ကျောင်းသားများ၏ search history ကိုသာ ကြည့်ရှုရန် စစ်ထုတ်ခြင်း
        search_logs = SearchHistory.query.filter(
            db.func.lower(db.func.trim(SearchHistory.department)) == admin_dept.lower()
        ).order_by(SearchHistory.id.desc()).all()

    return render_template(
        "dept_admin_dashboard.html",
        thesis_files=dept_theses,
        theses=dept_theses,
        registered_students=dept_students,
        students=dept_students,
        teachers=dept_teachers,
        search_logs=search_logs,
        department=admin_dept,
        categories=categories
    )

@app.route("/admin/thesis/upload", methods=["POST"])
@admin_required
def upload_thesis():
    title = request.form.get("title", "").strip()
    selected_categories = request.form.getlist("categories")
    category = ", ".join(selected_categories) if selected_categories else "General"
    author = request.form.get("author", "").strip()
    pub_year = request.form.get("year", "").strip()
    abstract = request.form.get("abstract", "").strip()
    department = session.get("admin_dept")
    uploaded_by = session.get("admin_name")

    if 'pdf_file' not in request.files:
        flash("No file was selected for upload!", "error")
        return redirect(url_for('dept_admin_dashboard'))

    file = request.files['pdf_file']
    if file and file.filename != '' and allowed_file(file):
        filename = secure_filename(file.filename)
        s3_key = f"theses/{department}/{filename}"
        try:
            s3_client.upload_fileobj(file, S3_BUCKET, s3_key, ExtraArgs={"ContentType": "application/pdf"})
            s3_file_url = f"https://{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/{s3_key}"

            new_thesis = ThesisFile(
                title=title,
                category=category,
                author=author,
                pub_year=int(pub_year) if pub_year and pub_year.isdigit() else None,
                abstract=abstract,
                department=department,
                file_path=s3_file_url,
                uploaded_by=uploaded_by
            )
            db.session.add(new_thesis)
            db.session.commit()
            flash("Thesis uploaded successfully!", "success")
            return redirect(url_for('dept_admin_dashboard'))
        except NoCredentialsError:
            flash("AWS credentials error!", "error")
        except Exception as e:
            db.session.rollback()
            flash(f"An error occurred during file upload: {str(e)}", "error")
    else:
        flash("Invalid file format or corrupted file! Please upload a valid PDF.", "error")
    return redirect(url_for('dept_admin_dashboard'))

@app.route("/admin/thesis/delete/<int:thesis_id>", methods=["POST"])
@admin_required
def delete_thesis(thesis_id):
    thesis = ThesisFile.query.get(thesis_id)
    if thesis:
        try:
            if S3_BUCKET and S3_BUCKET in thesis.file_path:
                s3_key = thesis.file_path.split(f"{S3_BUCKET}.s3.{AWS_REGION}.amazonaws.com/")[-1]
            else:
                s3_key = thesis.file_path

            if S3_BUCKET and s3_key:
                s3_client.delete_object(Bucket=S3_BUCKET, Key=s3_key)

            db.session.delete(thesis)
            db.session.commit()
            flash("Thesis file deleted successfully from both S3 and Database!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error occurred while deleting thesis: {str(e)}", "error")
    else:
        flash("Thesis file not found!", "error")
    return redirect_admin_dashboard()

@app.route("/admin/teacher/delete/<int:teacher_id>", methods=["POST"])
@admin_required
def delete_teacher(teacher_id):
    teacher = Teacher.query.get(teacher_id)
    if teacher:
        try:
            db.session.delete(teacher)
            db.session.commit()
            flash("Teacher record deleted successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error occurred while deleting teacher: {str(e)}", "danger")
    else:
        flash("Teacher not found!", "danger")
    return redirect_admin_dashboard()

@app.route("/admin/student/delete/<int:student_id>", methods=["POST"])
@admin_required
def delete_student(student_id):
    student = Student.query.get(student_id)
    if student:
        try:
            db.session.delete(student)
            db.session.commit()
            flash("Student record deleted successfully!", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error occurred while deleting student: {str(e)}", "danger")
    else:
        flash("Student not found!", "danger")
    return redirect_admin_dashboard()


@app.route("/admin/change-password", methods=["POST"])
@admin_required
def admin_change_password():
    current_password = request.form.get("current_password")
    new_password = request.form.get("new_password")
    confirm_password = request.form.get("confirm_password")

    if new_password != confirm_password:
        flash("New passwords do not match!", "error")
        return redirect_admin_dashboard()

    is_valid, msg = validate_password(new_password)
    if not is_valid:
        flash(msg, "error")
        return redirect_admin_dashboard()

    admin = Admin.query.get(session.get("admin_id"))
    if admin and check_password_hash(admin.password, current_password):
        admin.password = generate_password_hash(new_password)
        db.session.commit()

        # Message ကို Logout ခိုင်းသည့် စာသားမှ အောင်မြင်ကြောင်း စာသားသို့ ပြောင်းပါ
        flash("Password updated successfully!", "success")

        # admin_logout သို့ မလွှတ်တော့ဘဲ Dashboard သို့ ပြန်ညွှန်းပါ
        return redirect_admin_dashboard()
    else:
        flash("Incorrect current password!", "error")

    return redirect_admin_dashboard()


@app.route("/principal/delete_account", methods=["POST"])
def delete_principal():
    # Principal ဟုတ်မဟုတ် စစ်ဆေးခြင်း
    if session.get("admin_dept") != "PRINCIPAL":
        flash("Unauthorized action!", "error")
        return redirect(url_for("admin_login"))

    principal_id = session.get("admin_id")
    if principal_id:
        principal = Admin.query.get(principal_id)
        if principal:
            db.session.delete(principal)
            db.session.commit()

    # Session များကို ရှင်းလင်းခြင်း
    session.clear()
    flash("Principal account deleted successfully. A new principal can now register.", "success")
    return redirect(url_for("admin_register"))

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    flash("Admin logged out successfully!", "info")
    return redirect(url_for("home"))

# Teacher Routes
@app.route("/teacher/register", methods=["GET", "POST"])
def teacher_register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        department = request.form.get("department", "").strip().upper()
        email = request.form.get("email", "").strip()
        access_key = request.form.get("access_key", "").strip()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for("teacher_register"))

        is_valid, msg = validate_password(password)
        if not is_valid:
            flash(msg, "error")
            return redirect(url_for("teacher_register"))

        dept_teacher_count = Teacher.query.filter(
            db.func.upper(Teacher.department) == department
        ).count()
        if dept_teacher_count >= 10:
            flash(f"Teacher limit reached for {department} department.", "error")
            return redirect(url_for("teacher_register"))

        expected_key = TEACHER_DEPARTMENT_KEYS.get(department)
        if not expected_key or access_key != expected_key:
            flash(f"Invalid Teacher Access Key for {department} department!", "error")
            return redirect(url_for("teacher_register"))

        if Teacher.query.filter_by(email=email).first():
            flash("This email address is already registered!", "error")
            return redirect(url_for("teacher_register"))

        try:
            hashed_password = generate_password_hash(password)
            new_teacher = Teacher(name=name, department=department, email=email, password=hashed_password)
            db.session.add(new_teacher)
            db.session.commit()
            flash("Teacher registration successful! Please log in.", "success")
            return redirect(url_for("teacher_login"))
        except Exception as e:
            db.session.rollback()
            flash("An error occurred during registration.", "error")
    return render_template("teacher_register.html")

@app.route("/teacher/login", methods=["GET", "POST"])
def teacher_login():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password")
        access_key = request.form.get("access_key", "").strip()

        teacher = Teacher.query.filter_by(email=email, name=name).first()
        if not teacher:
            flash("Your account is not registered yet. Please register first.", "error")  # ပြင်ဆင်ထားသည့် စာသား
            return redirect(url_for("teacher_login"))
        if teacher.name.strip() != name:
            flash("Invalid Teacher Name!", "error")
            return redirect(url_for("teacher_login"))

            # Password မကိုက်ညီပါက စစ်ဆေးရန်
        if not check_password_hash(teacher.password, password):
            flash("Invalid Password!", "error")
            return redirect(url_for("teacher_login"))
        if teacher and check_password_hash(teacher.password, password):
            dept_upper = teacher.department.strip().upper()
            expected_key = TEACHER_DEPARTMENT_KEYS.get(dept_upper)
            if not expected_key or access_key != expected_key:
                flash(f"Invalid Access Key for department: {dept_upper}!", "error")
                return redirect(url_for("teacher_login"))

            otp = str(random.randint(100000, 999999))
            session["pending_teacher_id"] = teacher.id
            session["pending_teacher_name"] = teacher.name
            session["pending_teacher_email"] = teacher.email
            session["pending_teacher_dept"] = dept_upper
            session["teacher_otp"] = otp

            send_email(
                teacher.email,
                "ThesisHub Teacher Verification Code",
                f"Hello {teacher.name},\n\nYour Teacher Verification Code is: {otp}\n\nPlease enter this code to complete your login."
            )
            flash("A verification code has been sent to your email address.", "info")
            return redirect(url_for("teacher_verify_otp"))
        else:
            flash("Invalid Name, Email, or Password!", "error")
    return render_template("teacher_login.html")

@app.route("/teacher/verify-otp", methods=["GET", "POST"])
def teacher_verify_otp():
    if "pending_teacher_id" not in session:
        flash("Please log in first!", "error")
        return redirect(url_for("teacher_login"))

    if request.method == "POST":
        user_otp = request.form.get("otp", "").strip()
        if user_otp and user_otp == session.get("teacher_otp"):
            session["teacher_id"] = session.get("pending_teacher_id")
            session["teacher_name"] = session.get("pending_teacher_name")
            session["teacher_email"] = session.get("pending_teacher_email")
            session["teacher_dept"] = session.get("pending_teacher_dept")
            session["role"] = "teacher"

            login_time = datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")
            send_email(
                session["teacher_email"],
                "ThesisHub Teacher Login Alert",
                f"Hello {session['teacher_name']},\n\nYou logged into your Teacher Account at {login_time}."
            )

            session.pop("teacher_otp", None)
            session.pop("pending_teacher_id", None)
            session.pop("pending_teacher_name", None)
            session.pop("pending_teacher_email", None)
            session.pop("pending_teacher_dept", None)

            flash("Logged in successfully!", "success")
            return redirect(url_for("teacher_dashboard"))
        else:
            flash("Invalid verification code! Please try again.", "error")
    return render_template("teacher_verify_otp.html")


@app.route("/teacher/dashboard")
@teacher_required
def teacher_dashboard():
    teacher_dept = (session.get("teacher_dept") or "").strip()

    student_count = Student.query.filter(
        db.func.lower(db.func.trim(Student.department)) == teacher_dept.lower()
    ).count()

    registered_students = Student.query.filter(
        db.func.lower(db.func.trim(Student.department)) == teacher_dept.lower()
    ).order_by(Student.roll_no.asc()).all()

    # [ပြင်ဆင်ချက်] Teacher သည် မိမိမေဂျာမှ ကျောင်းသားများ၏ search history ကိုသာ ကြည့်ရှုရန် စစ်ထုတ်ခြင်း
    search_logs = SearchHistory.query.filter(
        db.func.lower(db.func.trim(SearchHistory.department)) == teacher_dept.lower()
    ).order_by(SearchHistory.id.desc()).all()

    return render_template(
        "teacher_dashboard.html",
        student_count=student_count,
        registered_students=registered_students,
        search_logs=search_logs,
        teacher_dept=teacher_dept
    )


@app.route("/teacher/major/<dept>")
@teacher_required
def teacher_major_display(dept):
    search_query = request.args.get("q", "").strip()
    dept_upper = dept.upper()

    # 1. Database ထဲက သက်ဆိုင်ရာ မေဂျာအလိုက် Categories များကို အရင်ဆွဲထုတ်ခြင်း
    db_categories = Category.query.filter(
        db.func.lower(db.func.trim(Category.department)) == dept.lower()
    ).all()
    categorized_theses = {cat.category_name: [] for cat in db_categories}

    # 2. သက်ဆိုင်ရာ မေဂျာ၏ Thesis များကို Query တည်ဆောက်ခြင်း (Publication Year ပါ ရှာနိုင်ရန် cast ထည့်သွင်းထားပြီး)
    query = ThesisFile.query.filter(
        db.func.lower(db.func.trim(ThesisFile.department)) == dept.lower()
    )

    if search_query:
        search_pattern = f"%{search_query}%"
        query = query.filter(
            (ThesisFile.title.ilike(search_pattern)) |
            (ThesisFile.category.ilike(search_pattern)) |
            (ThesisFile.author.ilike(search_pattern)) |
            (db.cast(ThesisFile.pub_year, db.String).ilike(search_pattern))
        )

    theses = query.order_by(ThesisFile.created_at.desc()).all()

    for item in theses:
        item_categories = [c.strip().lower() for c in (item.category or "").split(",") if c.strip()]
        for cat_name in categorized_theses.keys():
            if any(cat_name.lower() in ic or ic in cat_name.lower() for ic in item_categories):
                categorized_theses[cat_name].append(item)

    return render_template(
        "teacher_major_display.html",
        department=dept_upper,
        categorized_theses=categorized_theses,
        theses=theses,
        search_query=search_query
    )
@app.route("/teacher/read/<int:thesis_id>")
@teacher_required
def teacher_read_full_thesis(thesis_id):
    thesis = ThesisFile.query.get_or_404(thesis_id)
    return render_template("teacher_read_full_thesis.html", thesis=thesis)

@app.route("/teacher/change-password", methods=["POST"])
@teacher_required
def teacher_change_password():
    old_password = request.form.get("old_password")
    new_password = request.form.get("new_password")

    is_valid, msg = validate_password(new_password)
    if not is_valid:
        flash(msg, "error")
        return redirect(url_for("teacher_dashboard"))

    teacher = Teacher.query.get(session.get("teacher_id"))
    if teacher and check_password_hash(teacher.password, old_password):
        teacher.password = generate_password_hash(new_password)
        db.session.commit()
        flash("Password updated successfully! Please log in with your new password.", "success")
        return redirect(url_for("teacher_dashboard"))
    else:
        flash("Incorrect current password!", "error")
    return redirect(url_for("teacher_dashboard"))

@app.route("/teacher/logout")
def teacher_logout():
    session.clear()
    flash("Logged out successfully!", "info")
    return redirect(url_for("home"))

# Student Routes
@app.route("/student/register", methods=["GET", "POST"])
def student_register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        roll_no = request.form.get("roll_no", "").strip()
        department = request.form.get("department", "").strip().upper()
        email = request.form.get("email", "").strip()
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # ၁။ Confirm Password တိုက်ဆိုင်မှု စစ်ဆေးခြင်း
        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for("student_register"))

        # ၂။ Password သတ်မှတ်ချက် စစ်ဆေးခြင်း
        is_valid, msg = validate_password(password)
        if not is_valid:
            flash(msg, "error")
            return redirect(url_for("student_register"))

        # ၃။ Roll Number Format စစ်ဆေးခြင်း
        roll_pattern = r'^[I|V|X|i|v|x]+[\s-]*[A-Za-z]+-\d+\(\d{4}-\d{2}\)$'
        if not re.match(roll_pattern, roll_no):
            flash("Invalid Roll Number! Format must be like IEC-1(2025-26) or VI-EC-1(2020-21).", "error")
            return redirect(url_for("student_register"))

        # ၄။ Email အဟောင်း ရှိမရှိ စစ်ဆေးခြင်း
        if Student.query.filter_by(email=email).first():
            flash("This email address is already registered!", "error")
            return redirect(url_for("student_register"))

        try:
            hashed_password = generate_password_hash(password)
            new_student = Student(
                name=name,
                roll_no=roll_no,
                department=department,
                email=email,
                password=hashed_password
            )
            db.session.add(new_student)
            db.session.commit()

            # ===== ဤနေရာတွင် Session ကိုပါ တစ်ခါတည်း သိမ်းပေးပါ =====
            session["student_id"] = new_student.id
            session["student_name"] = new_student.name
            session["student_roll"] = new_student.roll_no
            session["student_dept"] = new_student.department
            session["role"] = "student"
            # ==================================================

            flash("Student registration successful!", "success")
            return redirect(url_for("student_main")) # Register ပြီးတာနဲ့ Main page ဆီ တန်းသွားမည်
        except Exception as e:
            db.session.rollback()
            flash("An error occurred during registration.", "error")
            return redirect(url_for("student_register"))

    return render_template("student_register.html")

@app.route("/student/login", methods=["GET", "POST"])
def student_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password")

        student = Student.query.filter_by(email=email).first()
        if not student:
            flash("Your account is not registered yet. Please register first.", "error")  # ပြင်ဆင်ထားသည့် စာသား
            return redirect(url_for("student_login"))
           # Password မကိုက်ညီပါက စစ်ဆေးရန်
        if not check_password_hash(student.password, password):
            flash("Invalid Password!", "error")
            return redirect(url_for("student_login"))
        if student and check_password_hash(student.password, password):
            session["student_id"] = student.id
            session["student_name"] = student.name
            session["student_roll"] = student.roll_no
            session["student_dept"] = student.department
            session["role"] = "student"
            flash("Logged in successfully!", "success")
            return redirect(url_for("student_main"))
        else:
            flash("Invalid Email or Password!", "error")
            return redirect(url_for("student_login"))
    return render_template("student_login.html")

@app.route("/student/main")
@student_required
def student_main():
    student_dept = session.get("student_dept", "").strip()
    search_query = request.args.get("q", "").strip()

    if search_query:
        try:
            new_log = SearchHistory(
                student_id=session.get("student_id"),
                student_name=session.get("student_name"),
                roll_no=session.get("student_roll"),
                department=student_dept.upper(),
                search_keyword=search_query
            )
            db.session.add(new_log)
            db.session.commit()
        except Exception as e:
            db.session.rollback()

        search_pattern = f"%{search_query}%"
        theses = ThesisFile.query.filter(
            db.func.lower(db.func.trim(ThesisFile.department)) == student_dept.lower(),
            (
                (ThesisFile.title.ilike(search_pattern)) |
                (ThesisFile.category.ilike(search_pattern)) |
                (ThesisFile.author.ilike(search_pattern)) |
                (db.cast(ThesisFile.pub_year, db.String).ilike(search_pattern))
            )
        ).order_by(ThesisFile.created_at.desc()).all()
    else:
        theses = ThesisFile.query.filter(
            db.func.lower(db.func.trim(ThesisFile.department)) == student_dept.lower()
        ).order_by(ThesisFile.created_at.desc()).all()

    return render_template("student_main.html", theses=theses, search_query=search_query)

@app.route("/student/major/<dept>")
@student_required
def student_major_display(dept):
    search_query = request.args.get("q", "").strip()
    dept_upper = dept.upper()

    if search_query:
        try:
            new_log = SearchHistory(
                student_id=session.get("student_id"),
                student_name=session.get("student_name"),
                roll_no=session.get("student_roll"),
                department=dept_upper,
                search_keyword=search_query
            )
            db.session.add(new_log)
            db.session.commit()
        except Exception as e:
            db.session.rollback()

    db_categories = Category.query.filter(
        db.func.lower(db.func.trim(Category.department)) == dept.lower()
    ).all()

    categorized_theses = {cat.category_name: [] for cat in db_categories}

    query = ThesisFile.query.filter(
        db.func.lower(db.func.trim(ThesisFile.department)) == dept.lower()
    )

    if search_query:
        search_pattern = f"%{search_query}%"
        query = query.filter(
            (ThesisFile.title.ilike(search_pattern)) |
            (ThesisFile.category.ilike(search_pattern)) |
            (ThesisFile.author.ilike(search_pattern)) |
            (db.cast(ThesisFile.pub_year, db.String).ilike(search_pattern))
        )

    theses = query.order_by(ThesisFile.created_at.desc()).all()

    for item in theses:
        item_categories = [c.strip().lower() for c in (item.category or "").split(",") if c.strip()]
        for cat_name in categorized_theses.keys():
            if any(cat_name.lower() in ic or ic in cat_name.lower() for ic in item_categories):
                categorized_theses[cat_name].append(item)

    return render_template(
        "student_major_display.html",
        department=dept_upper,
        categorized_theses=categorized_theses,
        theses=theses,
        search_query=search_query
    )

@app.route("/student/read/<int:thesis_id>")
@student_required
def student_read_full_thesis(thesis_id):
    thesis = ThesisFile.query.get_or_404(thesis_id)
    return render_template("student_read_full_thesis.html", thesis=thesis)


@app.route("/student/change-password", methods=["POST"])
@student_required
def student_change_password():
    old_password = request.form.get("old_password")
    new_password = request.form.get("new_password")

    is_valid, msg = validate_password(new_password)
    if not is_valid:
        flash(msg, "error")
        return redirect(url_for("student_main"))

    student = Student.query.get(session.get("student_id"))
    if student and check_password_hash(student.password, old_password):
        student.password = generate_password_hash(new_password)
        db.session.commit()

        # Session မပျောက်စေရန် သေချာအောင် explicit မာကင်ပေးပါ
        session["student_id"] = student.id
        session.modified = True

        flash("Password updated successfully!", "success")
        return redirect(url_for("student_main"))
    else:
        flash("Incorrect current password!", "error")
        return redirect(url_for("student_main"))

@app.route("/student/logout")
def student_logout():
    session.clear()
    flash("Logged out successfully!", "info")
    return redirect(url_for("home"))

def init_db():
    try:
        with app.app_context():
            db.create_all()
            default_categories = [
                ('EC', 'Robotics & Automation'),
                ('EC', 'Embedded Systems & IoT'),
                ('EC', 'Networking'),
                ('EC', 'Solar System'),
                ('EC', 'Programmable Logic Controller (PLC)'),
                ('EC', 'Arduino Microcontroller'),
                ('EC', 'Raspberry Pi Controller'),
                ('EC', 'PIC Microcontroller'),
                ('EC', 'ESP 32 Microcontroller'),
                ('EP', 'PLC & Industrial Control'),
                ('EP', 'Power System & Protection'),
                ('EP', 'Renewable Energy Systems'),
                ('EP', 'High Voltage Engineering'),
                ('MP', 'Automotive Technology'),
                ('MP', 'Manufacturing Technology'),
                ('MP', 'Fluid Mechanics & Turbomachinery'),
                ('MP', 'Refrigerator & Air Conditioning Technology'),
                ('Civil', 'Structural Engineering'),
                ('Civil', 'Geotechnical Engineering'),
                ('Civil', 'Water Resources Engineering'),
                ('Civil', 'Transportation Engineering'),
                ('Civil', 'Construction Management'),
                ('Civil', 'Environmental Engineering')
            ]
            for dept, cat_name in default_categories:
                existing = Category.query.filter_by(department=dept, category_name=cat_name).first()
                if not existing:
                    db.session.add(Category(department=dept, category_name=cat_name))
            db.session.commit()
            print("Database & Default Categories Initialized Successfully!")
    except Exception as e:
        db.session.rollback()
        print(f"Database Initialization Error: {e}")

if __name__ == "__main__":
    with app.app_context():
        new_categories = [
            ('EC', 'ESP 32 Microcontroller')
        ]
        for dept, cat_name in new_categories:
            existing = Category.query.filter_by(department=dept, category_name=cat_name).first()
            if not existing:
                db.session.add(Category(department=dept, category_name=cat_name))
        db.session.commit()
        print("New Categories Checked & Added Successfully!")

    app.run(debug=True, host="0.0.0.0", port=5000)

