import os, uuid, smtplib, ssl
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_pymongo import PyMongo
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ------------------- APP SETUP -------------------
load_dotenv()
app = Flask(__name__)

# Secret key for sessions
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# MongoDB setup (optional)
MONGO_URI = os.getenv("MONGO_URI")
app.config["MONGO_URI"] = MONGO_URI or ""
if MONGO_URI:
    mongo = PyMongo(app)
    db = mongo.db
else:
    db = None
    IN_MEMORY = {"contacts": [], "incidents": [], "users": []}

# Email setup
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

# Login setup
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ------------------- USER CLASS -------------------
class User(UserMixin):
    def __init__(self, user_id, username, email, password_hash):
        self.id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    u = next((u for u in IN_MEMORY["users"] if u["id"] == user_id), None)
    if u:
        return User(u["id"], u["username"], u["email"], u["password_hash"])
    return None

# ------------------- AUTH ROUTES -------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        if any(u["email"] == email for u in IN_MEMORY["users"]):
            flash("Email already registered", "danger")
            return redirect(url_for("register"))

        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        user_id = str(uuid.uuid4())
        IN_MEMORY["users"].append({
            "id": user_id,
            "username": username,
            "email": email,
            "password_hash": pw_hash
        })
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        u = next((u for u in IN_MEMORY["users"] if u["email"] == email), None)
        if u and bcrypt.check_password_hash(u["password_hash"], password):
            login_user(User(u["id"], u["username"], u["email"], u["password_hash"]))
            flash("Login successful!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid email or password", "danger")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out", "info")
    return redirect(url_for("login"))

# ------------------- DB HELPERS -------------------
def add_contact(contact):
    contact["id"] = str(uuid.uuid4())
    IN_MEMORY["contacts"].append(contact)
    return contact["id"]

def list_contacts():
    return IN_MEMORY["contacts"]

def save_incident(inc):
    IN_MEMORY["incidents"].append(inc)

def list_incidents():
    return IN_MEMORY["incidents"]

# ------------------- EMAIL -------------------
def send_email(to_email, subject, body):
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_USER
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, to_email, msg.as_string())
        print(f"✅ Email sent to {to_email}")
    except Exception as e:
        print(f"❌ Email failed: {e}")

# ------------------- MAIN ROUTES -------------------
@app.route("/")
@login_required
def index():
    return render_template("index.html", contacts=list_contacts())

@app.route("/contacts", methods=["GET", "POST"])
@login_required
def contacts():
    if request.method == "POST":
        data = request.form
        contact = {"name": data.get("name"), "phone": data.get("phone"), "email": data.get("email")}
        add_contact(contact)
        return redirect(url_for("contacts"))
    return render_template("contacts.html", contacts=list_contacts())

@app.route("/dashboard")
@login_required
def dashboard():
    incidents = sorted(list_incidents(), key=lambda x: x["timestamp"], reverse=True)
    return render_template("dashboard.html", incidents=incidents, contacts=list_contacts())

# ------------------- API ROUTES -------------------
@app.route("/api/report-accident", methods=["POST"])
def report_accident():
    payload = request.get_json(force=True)
    incident = {
        "id": str(uuid.uuid4()),
        "user_id": payload.get("user_id", "anonymous"),
        "location": {"lat": payload.get("lat"), "lng": payload.get("lng")},
        "accel_mag": payload.get("accel_mag"),
        "speed": payload.get("speed"),
        "metadata": payload.get("metadata", {}),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": "pending_verification",
        "notified": False,
    }
    save_incident(incident)
    return jsonify({"ok": True, "incident_id": incident["id"]}), 201

# ------------------- NOTIFY -------------------
def notify_contacts(incident):
    for c in list_contacts():
        if c.get("email"):
            body = f"🚨 EMERGENCY ALERT 🚨\nIncident ID: {incident['id']}\nLocation: {incident['location']}"
            send_email(c["email"], "Emergency Alert", body)

# ------------------- RUN -------------------
if __name__ == "__main__":
    app.run(debug=True, port=5000)
