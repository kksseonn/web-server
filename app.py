import os
import sys
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash


db = SQLAlchemy()


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)


class Employee(db.Model):
    __tablename__ = "employees"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    position = db.Column(db.String(120), nullable=False)
    department = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-on-production")
    app.config["SQLALCHEMY_DATABASE_URI"] = get_database_url()
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    db.init_app(app)
    register_routes(app)

    return app


def get_database_url():
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL environment variable is required")

    # Accept both common variants, while SQLAlchemy expects postgresql://.
    if database_url.startswith("postgres://"):
        database_url = database_url.replace("postgres://", "postgresql://", 1)

    return database_url


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def register_routes(app):
    @app.route("/")
    def index():
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if "user_id" in session:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password_hash, password):
                session.clear()
                session["user_id"] = user.id
                session["username"] = user.username
                return redirect(url_for("dashboard"))

            flash("Неверный логин или пароль", "error")

        return render_template("login.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        employees = Employee.query.order_by(Employee.id.asc()).all()
        return render_template("dashboard.html", employees=employees)

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))


def init_db():
    db.create_all()

    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            password_hash=generate_password_hash("admin123"),
        )
        db.session.add(admin)

    if Employee.query.count() == 0:
        db.session.add_all(
            [
                Employee(
                    full_name="Анна Иванова",
                    position="Project Manager",
                    department="Operations",
                    email="anna.ivanova@example.com",
                ),
                Employee(
                    full_name="Сергей Петров",
                    position="Backend Developer",
                    department="Engineering",
                    email="sergey.petrov@example.com",
                ),
                Employee(
                    full_name="Мария Смирнова",
                    position="Accountant",
                    department="Finance",
                    email="maria.smirnova@example.com",
                ),
            ]
        )

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        raise


app = create_app()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "init-db":
        with app.app_context():
            init_db()
        print("Database initialized. Test user: admin / admin123")
    else:
        app.run(host="127.0.0.1", port=5000)
