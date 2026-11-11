
import os
import re
import secrets
from decimal import Decimal, InvalidOperation

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "local-development-key-change-this"
)

database_url = os.environ.get("DATABASE_URL", "sqlite:///mugz_pay.db")

# Render database URLs may use postgres://.
if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://", "postgresql+psycopg://", 1
    )
elif database_url.startswith("postgresql://"):
    database_url = database_url.replace(
        "postgresql://", "postgresql+psycopg://", 1
    )

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("RENDER") == "true"
)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

PAYMENT_METHODS = [
    "EcoCash", "OneMoney", "Bank transfer", "Card"
]


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    mugz_id = db.Column(db.String(40), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)


class PaymentRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    currency = db.Column(db.String(3), default="USD", nullable=False)
    method = db.Column(db.String(30), nullable=False)
    status = db.Column(db.String(40), default="REQUESTED - NOT PAID")
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    sender = db.relationship("User", foreign_keys=[sender_id])
    recipient = db.relationship("User", foreign_keys=[recipient_id])


def current_user():
    user_id = session.get("user_id")
    return db.session.get(User, user_id) if user_id else None


def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not current_user():
            return jsonify({"error": "Please log in first."}), 401
        return function(*args, **kwargs)
    return wrapper


@app.route("/")
def home():
    user = current_user()
    payments = []

    if user:
        payments = (
            PaymentRequest.query
            .filter(
                db.or_(
                    PaymentRequest.sender_id == user.id,
                    PaymentRequest.recipient_id == user.id
                )
            )
            .order_by(PaymentRequest.created_at.desc())
            .limit(30)
            .all()
        )

    return render_template(
        "index.html",
        user=user,
        payments=payments,
        methods=PAYMENT_METHODS
    )


@app.route("/register", methods=["POST"])
def register():
    name = request.form.get("name", "").strip()
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")

    if not name or not re.fullmatch(r"[a-z0-9_]{3,24}", username):
        flash("Enter a name and a username with 3–24 letters, numbers or underscores.")
        return redirect(url_for("home"))

    if len(password) < 8:
        flash("Your password must contain at least 8 characters.")
        return redirect(url_for("home"))

    mugz_id = "@" + username

    if User.query.filter_by(mugz_id=mugz_id).first():
        flash("That MUGZ ID is already taken.")
        return redirect(url_for("home"))

    user = User(
        name=name,
        mugz_id=mugz_id,
        password_hash=generate_password_hash(password)
    )

    db.session.add(user)
    db.session.commit()

    session.clear()
    session["user_id"] = user.id
    flash("Your MUGZ PAY account has been created.")
    return redirect(url_for("home"))


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")

    user = User.query.filter_by(mugz_id="@" + username.lstrip("@")).first()

    if not user or not check_password_hash(user.password_hash, password):
        flash("Incorrect MUGZ ID or password.")
        return redirect(url_for("home"))

    session.clear()
    session["user_id"] = user.id
    return redirect(url_for("home"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


@app.route("/api/search")
@login_required
def search_recipients():
    query = request.args.get("q", "").strip().lower()

    if len(query) < 2:
        return jsonify([])

    users = (
        User.query
        .filter(
            db.or_(
                User.mugz_id.ilike(f"%{query}%"),
                User.name.ilike(f"%{query}%")
            )
        )
        .limit(10)
        .all()
    )

    return jsonify([
        {"name": u.name, "mugz_id": u.mugz_id}
        for u in users
        if u.id != current_user().id
    ])


@app.route("/api/wave", methods=["POST"])
@login_required
def create_wave_request():
    data = request.get_json(silent=True) or {}

    recipient_id = str(data.get("recipient", "")).strip().lower()
    method = str(data.get("method", "")).strip()
    raw_amount = str(data.get("amount", "")).strip()

    if method not in PAYMENT_METHODS:
        return jsonify({"error": "Choose a valid payment method."}), 400

    try:
        amount = Decimal(raw_amount).quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        return jsonify({"error": "Enter a valid amount."}), 400

    if amount <= 0 or amount > Decimal("100000"):
        return jsonify({"error": "Amount must be above zero and below 100,000."}), 400

    recipient = User.query.filter_by(mugz_id=recipient_id).first()

    if not recipient:
        return jsonify({"error": "Recipient not found. Search for their MUGZ ID."}), 404

    sender = current_user()

    if recipient.id == sender.id:
        return jsonify({"error": "You cannot create a payment request to yourself."}), 400

    payment = PaymentRequest(
        sender_id=sender.id,
        recipient_id=recipient.id,
        amount=amount,
        method=method,
        status="REQUESTED - NOT PAID"
    )

    db.session.add(payment)
    db.session.commit()

    return jsonify({
        "message": "Payment request saved. No money has been transferred.",
        "reference": payment.id
    }), 201


@app.errorhandler(400)
def bad_request(error):
    return jsonify({"error": "Invalid request. Refresh the page and try again."}), 400


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)
