app.py




import os, uuid, requests
from datetime import datetime
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_pymongo import PyMongo
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, current_user
)
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

# ------------------- APP SETUP -------------------
load_dotenv()
app = Flask(_name_)

# Secret key for sessions
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# MongoDB setup
MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise ValueError("❌ MONGO_URI is missing in your .env file")

app.config["MONGO_URI"] = MONGO_URI
mongo = PyMongo(app)
db = mongo.db

# Brevo setup
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
BREVO_URL = "https://api.brevo.com/v3/smtp/email"

# Login setup
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ------------------- USER CLASS -------------------
class User(UserMixin):
    def _init_(self, user_id, username, email, password_hash):
        self.id = user_id
        self.username = username
        self.email = email
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    u = db.users.find_one({"id": user_id})
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

        if db.users.find_one({"email": email}):
            flash("Email already registered", "danger")
            return redirect(url_for("register"))

        pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
        user_id = str(uuid.uuid4())

        db.users.insert_one({
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

        u = db.users.find_one({"email": email})
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
    db.contacts.insert_one(contact)
    return contact["id"]

def list_contacts():
    return list(db.contacts.find({}, {"_id": 0}))

def save_incident(inc):
    db.incidents.insert_one(inc)

def list_incidents():
    return list(db.incidents.find({}, {"_id": 0}))

# ------------------- EMAIL (via Brevo) -------------------
def send_email(to_email, subject, body):
    try:
        BREVO_API_KEY = os.getenv("BREVO_API_KEY")
        url = "https://api.brevo.com/v3/smtp/email"
        payload = {
            "sender": {"name": "SwiftAid Alert", "email": "vijaymh041@gmail.com"},
            "to": [{"email": to_email}],
            "subject": subject,
            "textContent": body
        }
        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "api-key": BREVO_API_KEY
        }
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()
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
        contact = {
            "name": data.get("name"),
            "phone": data.get("phone"),
            "email": data.get("email")
        }
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
    contacts = list_contacts()
    if not contacts:
        print("❌ No contacts found. SOS not sent.")
        return

    for c in contacts:
        if c.get("email"):
            body = (
                f"🚨 EMERGENCY ALERT 🚨\n\n"
                f"Incident ID: {incident['id']}\n"
                f"User: {incident.get('user_id')}\n"
                f"Location: {incident['location']}\n"
                f"Acceleration: {incident.get('accel_mag')}\n"
                f"Speed: {incident.get('speed')}\n"
                f"Status: {incident['status']}\n"
                f"Time: {incident['timestamp']}"
            )
            send_email(c["email"], "Emergency Alert", body)


# ------------------- MANUAL SOS -------------------
@app.route("/manual-sos", methods=["POST"])
@login_required
def manual_sos():
    incident = {
        "id": str(uuid.uuid4()),
        "user_id": current_user.id,
        "location": {"lat": request.form.get("lat"), "lng": request.form.get("lng")},
        "accel_mag": request.form.get("accel_mag"),
        "speed": request.form.get("speed"),
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": "manual_sos",
        "notified": True,
    }
    save_incident(incident)
    notify_contacts(incident)
    flash("🚨 Manual SOS sent to your contacts!", "success")
    return redirect(url_for("index"))


# ------------------- RUN -------------------
if _name_ == "_main_":
    app.run(debug=True, port=5000, host="0.0.0.0")
