"""
Swinger dating web application
--------------------------------

This Flask application implements a minimal dating platform inspired by popular
apps like Tinder but tailored to an adult swinging community.  It supports
user registration, login/logout, profile editing, browsing other profiles,
liking and matching functionality, simple messaging, and a subscription flag
that can be toggled for premium features.  No payment integration is
implemented – subscription status is stored in the database and can be
manually activated via a dummy route.  This is a prototype to demonstrate
core functionality and does not include production‑grade security or
performance optimisations.

The application uses Flask with SQLAlchemy for ORM and Flask‑Login for
authentication.  Passwords are stored using werkzeug's secure hash.  The
database is SQLite, making it easy to run locally.  To start the app,
install the requirements listed in requirements.txt and run `python app.py`.

This code intentionally avoids any third‑party payment processing and does
not collect sensitive personal data beyond basic profile information.  It is
meant for demonstration only.
"""

from __future__ import annotations

import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev_secret_key")
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + os.path.join(basedir, "app.db")
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


###############################################################################
# Database models
###############################################################################

class User(UserMixin, db.Model):
    """User model representing each registered member."""

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    gender = db.Column(db.String(32))
    orientation = db.Column(db.String(32))
    location = db.Column(db.String(120))
    bio = db.Column(db.Text)
    is_subscribed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    sent_likes = db.relationship(
        "Like", foreign_keys="Like.user_id", backref="liker", lazy="dynamic"
    )
    received_likes = db.relationship(
        "Like", foreign_keys="Like.liked_id", backref="liked", lazy="dynamic"
    )
    sent_messages = db.relationship(
        "Message", foreign_keys="Message.sender_id", backref="sender", lazy="dynamic"
    )
    received_messages = db.relationship(
        "Message", foreign_keys="Message.receiver_id", backref="receiver", lazy="dynamic"
    )

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def has_liked(self, other: "User") -> bool:
        """Check if the user has liked another user."""
        return self.sent_likes.filter_by(liked_id=other.id).first() is not None

    def is_matched_with(self, other: "User") -> bool:
        """Check if there is a mutual like between two users."""
        if not self.has_liked(other):
            return False
        return other.sent_likes.filter_by(liked_id=self.id).first() is not None


class Like(db.Model):
    """Model representing a like (swipe right)."""

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    liked_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    """Model representing a message between two users."""

    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id: str) -> User | None:
    return User.query.get(int(user_id))


###############################################################################
# Routes
###############################################################################

@app.route("/")
def index():
    """Home page. If logged in, redirects to browse. Otherwise show landing."""
    if current_user.is_authenticated:
        return redirect(url_for("browse"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register new user."""
    if current_user.is_authenticated:
        return redirect(url_for("browse"))
    if request.method == "POST":
        username = request.form.get("username").strip()
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")
        confirm = request.form.get("confirm")
        # Basic validations
        if not username or not email or not password:
            flash("Todos los campos son obligatorios.", "warning")
        elif password != confirm:
            flash("Las contraseñas no coinciden.", "warning")
        elif User.query.filter(
            (User.username == username) | (User.email == email)
        ).first():
            flash("El nombre de usuario o correo ya existe.", "warning")
        else:
            user = User(username=username, email=email)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            login_user(user)
            flash("Registro exitoso. Ahora puedes crear tu perfil.", "success")
            return redirect(url_for("edit_profile"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """User login."""
    if current_user.is_authenticated:
        return redirect(url_for("browse"))
    if request.method == "POST":
        email = request.form.get("email").strip().lower()
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Has iniciado sesión correctamente.", "success")
            return redirect(url_for("browse"))
        flash("Correo o contraseña incorrectos.", "danger")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Log out the current user."""
    logout_user()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("index"))


@app.route("/edit_profile", methods=["GET", "POST"])
@login_required
def edit_profile():
    """Create or edit the current user's profile."""
    if request.method == "POST":
        current_user.gender = request.form.get("gender")
        current_user.orientation = request.form.get("orientation")
        current_user.location = request.form.get("location")
        current_user.bio = request.form.get("bio")
        db.session.commit()
        flash("Perfil actualizado con éxito.", "success")
        return redirect(url_for("profile", user_id=current_user.id))
    return render_template("edit_profile.html")


@app.route("/profile/<int:user_id>")
@login_required
def profile(user_id: int):
    """View another user's profile or your own."""
    user = User.query.get_or_404(user_id)
    is_match = current_user.is_matched_with(user) if current_user.id != user.id else False
    has_liked = current_user.has_liked(user) if current_user.id != user.id else False
    return render_template(
        "profile.html",
        user=user,
        has_liked=has_liked,
        is_match=is_match,
    )


@app.route("/like/<int:user_id>")
@login_required
def like(user_id: int):
    """Record a like from the current user to another user."""
    if user_id == current_user.id:
        flash("No puedes darte me gusta a ti mismo.", "warning")
        return redirect(url_for("browse"))
    user = User.query.get_or_404(user_id)
    if current_user.has_liked(user):
        flash("Ya has dado me gusta a esta persona.", "info")
    else:
        like = Like(liker=current_user, liked=user)
        db.session.add(like)
        db.session.commit()
        if user.has_liked(current_user):
            flash(f"¡Es un match con {user.username}!", "success")
        else:
            flash("Like enviado.", "info")
    return redirect(url_for("profile", user_id=user_id))


@app.route("/browse")
@login_required
def browse():
    """Browse other user profiles. Simple filter by gender/orientation or location."""
    # Filter parameters from query
    gender = request.args.get("gender")
    orientation = request.args.get("orientation")
    location = request.args.get("location")
    query = User.query.filter(User.id != current_user.id)
    if gender:
        query = query.filter(User.gender == gender)
    if orientation:
        query = query.filter(User.orientation == orientation)
    if location:
        # Basic case‑insensitive substring search
        query = query.filter(User.location.ilike(f"%{location}%"))
    users = query.order_by(User.created_at.desc()).all()
    return render_template(
        "browse.html",
        users=users,
        gender=gender,
        orientation=orientation,
        location=location,
    )


@app.route("/matches")
@login_required
def matches():
    """List current user's matches (mutual likes)."""
    # All users liked by current_user with reciprocal like
    matches_list = []
    for like in current_user.sent_likes:
        other = like.liked
        if other.has_liked(current_user):
            matches_list.append(other)
    return render_template("matches.html", matches=matches_list)


@app.route("/messages/<int:user_id>", methods=["GET", "POST"])
@login_required
def messages(user_id: int):
    """Messaging between matched users. Only accessible for matches."""
    other = User.query.get_or_404(user_id)
    if not current_user.is_matched_with(other):
        flash("Solo puedes chatear con tus matches.", "warning")
        return redirect(url_for("browse"))
    # Only subscribed users can send unlimited messages; non‑subscribed limit messages
    if request.method == "POST":
        content = request.form.get("content", "").strip()
        if content:
            # Check message limit for free users
            if not current_user.is_subscribed:
                # Free users may send up to 5 messages per day
                today = datetime.utcnow().date()
                count = (
                    Message.query.filter_by(sender_id=current_user.id, receiver_id=other.id)
                    .filter(Message.timestamp >= datetime(today.year, today.month, today.day))
                    .count()
                )
                if count >= 5:
                    flash(
                        "Has alcanzado el límite de mensajes para hoy. Suscríbete para mensajes ilimitados.",
                        "warning",
                    )
                    return redirect(url_for("messages", user_id=user_id))
            msg = Message(sender=current_user, receiver=other, content=content)
            db.session.add(msg)
            db.session.commit()
            flash("Mensaje enviado.", "success")
            return redirect(url_for("messages", user_id=user_id))
    # Retrieve conversation messages
    conversation = (
        Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == other.id))
            | ((Message.sender_id == other.id) & (Message.receiver_id == current_user.id))
        )
        .order_by(Message.timestamp.asc())
        .all()
    )
    return render_template(
        "messages.html",
        other=other,
        conversation=conversation,
    )


@app.route("/subscribe")
@login_required
def subscribe():
    """Dummy subscription route. Sets subscription flag on user."""
    current_user.is_subscribed = True
    db.session.commit()
    flash("¡Gracias por suscribirte! Ahora tienes acceso a mensajes ilimitados.", "success")
    return redirect(url_for("browse"))


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    # Create database if not exists
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, port=port, host="0.0.0.0")