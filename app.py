import os
import sys
from functools import wraps

from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_sqlalchemy import SQLAlchemy
from ldap3 import Connection, Server
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars
from sqlalchemy.exc import IntegrityError


db = SQLAlchemy()


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
        if "username" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def admin_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if session.get("role") != "admin":
            flash("У вас нет прав для выполнения этого действия", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped_view


def normalize_username(username):
    normalized_username = username.strip()

    if "\\" in normalized_username:
        normalized_username = normalized_username.split("\\", 1)[1]

    if "@" in normalized_username:
        normalized_username = normalized_username.split("@", 1)[0]

    return normalized_username


def get_ad_upn_suffix():
    domain_parts = []
    for component in os.getenv("AD_BASE_DN", "").split(","):
        key, _, value = component.strip().partition("=")
        if key.upper() == "DC" and value:
            domain_parts.append(value)

    return ".".join(domain_parts)


def resolve_role(group_dns):
    admin_group = os.getenv("AD_ADMIN_GROUP", "IT_Admins").lower()
    user_group = os.getenv("AD_USER_GROUP", "Employees").lower()

    normalized_groups = [group_dn.lower() for group_dn in group_dns]

    if any(group_dn.startswith(f"cn={admin_group},") for group_dn in normalized_groups):
        return "admin"

    if any(group_dn.startswith(f"cn={user_group},") for group_dn in normalized_groups):
        return "user"

    return None


def authenticate_ad(username, password):
    normalized_username = normalize_username(username)
    if not normalized_username or not password:
        return None

    ad_server = os.getenv("AD_SERVER", "").strip()
    ad_domain = os.getenv("AD_DOMAIN", "").strip()
    ad_base_dn = os.getenv("AD_BASE_DN", "").strip()
    upn_suffix = get_ad_upn_suffix()
    if not ad_server or not ad_domain or not ad_base_dn or not upn_suffix:
        return None

    # Bind via UPN so the form can accept a plain login like "ivanov".
    bind_username = f"{normalized_username}@{upn_suffix}"
    server = Server(ad_server, connect_timeout=5)

    try:
        with Connection(
            server,
            user=bind_username,
            password=password,
            auto_bind=True,
            receive_timeout=5,
        ) as connection:
            search_filter = f"(sAMAccountName={escape_filter_chars(normalized_username)})"
            found_user = connection.search(
                search_base=ad_base_dn,
                search_filter=search_filter,
                attributes=["memberOf"],
            )
            if not found_user or len(connection.entries) != 1:
                return None

            entry = connection.entries[0]
            group_dns = entry.entry_attributes_as_dict.get("memberOf", [])
    except (LDAPException, OSError):
        return None

    role = resolve_role(group_dns)
    if not role:
        return None

    return {"username": normalized_username, "role": role}


def get_employee_form_data():
    return {
        "full_name": request.form.get("full_name", "").strip(),
        "position": request.form.get("position", "").strip(),
        "department": request.form.get("department", "").strip(),
        "email": request.form.get("email", "").strip(),
    }


def register_routes(app):
    @app.route("/")
    def index():
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if "username" in session:
            return redirect(url_for("dashboard"))

        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")

            auth_result = authenticate_ad(username, password)
            if auth_result:
                session.clear()
                session["username"] = auth_result["username"]
                session["role"] = auth_result["role"]
                return redirect(url_for("dashboard"))

            flash("Неверный логин, пароль или нет прав доступа", "error")

        return render_template("login.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        employees = Employee.query.order_by(Employee.id.asc()).all()
        role = session.get("role")
        return render_template(
            "dashboard.html",
            employees=employees,
            username=session.get("username"),
            role=role,
            role_label="Администратор" if role == "admin" else "Пользователь",
            is_admin=role == "admin",
        )

    @app.route("/employees/new", methods=["GET", "POST"])
    @login_required
    @admin_required
    def new_employee():
        form_data = {
            "full_name": "",
            "position": "",
            "department": "",
            "email": "",
        }

        if request.method == "POST":
            form_data = get_employee_form_data()
            if not all(form_data.values()):
                flash("Заполните все поля сотрудника", "error")
            else:
                db.session.add(Employee(**form_data))
                db.session.commit()
                flash("Сотрудник добавлен", "success")
                return redirect(url_for("dashboard"))

        return render_template(
            "employee_form.html",
            title="Новый сотрудник",
            submit_label="Добавить запись",
            form_action=url_for("new_employee"),
            employee=form_data,
        )

    @app.route("/employees/<int:employee_id>/edit", methods=["GET", "POST"])
    @login_required
    @admin_required
    def edit_employee(employee_id):
        employee = Employee.query.get_or_404(employee_id)

        if request.method == "POST":
            form_data = get_employee_form_data()
            if not all(form_data.values()):
                flash("Заполните все поля сотрудника", "error")
            else:
                employee.full_name = form_data["full_name"]
                employee.position = form_data["position"]
                employee.department = form_data["department"]
                employee.email = form_data["email"]
                db.session.commit()
                flash("Запись обновлена", "success")
                return redirect(url_for("dashboard"))

        return render_template(
            "employee_form.html",
            title="Редактирование сотрудника",
            submit_label="Сохранить изменения",
            form_action=url_for("edit_employee", employee_id=employee.id),
            employee=employee,
        )

    @app.route("/employees/<int:employee_id>/delete", methods=["POST"])
    @login_required
    @admin_required
    def delete_employee(employee_id):
        employee = Employee.query.get_or_404(employee_id)
        db.session.delete(employee)
        db.session.commit()
        flash("Запись удалена", "success")
        return redirect(url_for("dashboard"))

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))


def init_db():
    db.create_all()

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
        print("Database initialized. Employees table is ready.")
    else:
        app.run(host="127.0.0.1", port=5000)
