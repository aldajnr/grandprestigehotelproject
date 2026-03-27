# Authentication: login, OTP verification, logout, password reset

import time
from flask import (Blueprint, render_template, request, redirect,
                   url_for, flash, session, current_app)
from utils.validators import is_zetech_email
from models.user_model import get_user_by_username, verify_password, update_user_password
from services.auth_service import generate_otp, is_expired, send_otp_email, send_password_reset_otp
from services.audit_service import log as audit

auth_bp = Blueprint("auth", __name__)


# ── Login ────────────────────────────────────────────────────────────────────
@auth_bp.route("/", methods=["GET", "POST"])
def login():
    if session.get("user_id") and session.get("otp_verified"):
        return redirect(url_for("dashboard.home"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        password = request.form.get("password") or ""

        if not is_zetech_email(username):
            flash("Email must end with @zetech.ac.ke", "danger")
            return render_template("index.html")

        user = get_user_by_username(username)
        if not user or not verify_password(user["password_hash"], password):
            audit("LOGIN_FAILED", notes="Invalid credentials for: " + username)
            flash("Incorrect email or password.", "danger")
            return render_template("index.html")

        otp = generate_otp()
        session.clear()
        session["user_id"]       = user["id"]
        session["username"]      = user["username"]
        session["role"]          = user["role"]
        session["otp_code"]      = otp
        session["otp_created_at"] = time.time()
        session["otp_verified"]  = False

        # Send OTP to the staff member's own registered email
        email_sent = send_otp_email(current_app._get_current_object(), user["username"], otp)
        session["email_sent"] = email_sent
        if not email_sent:
            flash("Email delivery is temporarily unavailable. Use the code shown on the OTP page.", "warning")

        audit("LOGIN_PASSWORD_OK", notes="Password verified. OTP dispatched.")
        return redirect(url_for("auth.otp"))

    return render_template("index.html")


# ── OTP verification ─────────────────────────────────────────────────────────
@auth_bp.route("/otp", methods=["GET", "POST"])
def otp():
    if not session.get("user_id"):
        return redirect(url_for("auth.login"))

    stored_otp   = session.get("otp_code")
    created_at   = session.get("otp_created_at")
    email_sent   = session.get("email_sent", False)
    mail_enabled = current_app.config.get("MAIL_ENABLED", False)
    demo_otp     = None if (mail_enabled and email_sent) else stored_otp

    if request.method == "POST":
        code = (request.form.get("otp") or "").strip()

        if is_expired(created_at, current_app.config.get("OTP_EXPIRY_SEC", 300)):
            session.clear()
            audit("OTP_EXPIRED", notes="OTP timed out")
            flash("OTP expired. Please login again.", "danger")
            return redirect(url_for("auth.login"))

        if code != stored_otp:
            audit("OTP_INVALID", notes="Wrong OTP submitted")
            flash("Invalid OTP — please check and try again.", "danger")
            return render_template("otp.html", demo_otp=demo_otp,
                                   mail_enabled=mail_enabled, email_sent=email_sent)

        session["otp_verified"] = True
        audit("LOGIN_SUCCESS", notes="OTP verified. Access granted.")
        return redirect(url_for("dashboard.home"))

    return render_template("otp.html", demo_otp=demo_otp,
                           mail_enabled=mail_enabled, email_sent=email_sent)


# ── Forgot password — request OTP ────────────────────────────────────────────
@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip().lower()
        if not is_zetech_email(username):
            flash("Enter a valid @zetech.ac.ke email address.", "danger")
            return render_template("forgot_password.html")

        user = get_user_by_username(username)
        # Always show success message to prevent user enumeration
        if user:
            otp = generate_otp()
            session["reset_user_id"]  = user["id"]
            session["reset_username"] = user["username"]
            session["reset_otp"]      = otp
            session["reset_otp_at"]   = time.time()
            sent = send_password_reset_otp(current_app._get_current_object(), user["username"], otp)
            session["reset_email_sent"] = sent
            if not sent:
                flash("Email delivery is temporarily unavailable. Use the reset code shown on the next page.", "warning")
            audit("PASSWORD_RESET_REQUESTED", notes="Reset OTP sent to: " + username)

        flash("If that email is registered, a reset code has been sent to it.", "info")
        return redirect(url_for("auth.reset_password"))

    return render_template("forgot_password.html")


# ── Forgot password — enter OTP + new password ───────────────────────────────
@auth_bp.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if not session.get("reset_otp"):
        return redirect(url_for("auth.forgot_password"))

    mail_enabled   = current_app.config.get("MAIL_ENABLED", False)
    email_sent     = session.get("reset_email_sent", False)
    demo_otp       = None if (mail_enabled and email_sent) else session.get("reset_otp")

    if request.method == "POST":
        code     = (request.form.get("otp") or "").strip()
        new_pass = request.form.get("new_password") or ""
        confirm  = request.form.get("confirm_password") or ""

        if is_expired(session.get("reset_otp_at"), current_app.config.get("OTP_EXPIRY_SEC", 300)):
            session.pop("reset_otp", None)
            flash("Reset code expired. Please try again.", "danger")
            return redirect(url_for("auth.forgot_password"))

        if code != session.get("reset_otp"):
            flash("Invalid reset code.", "danger")
            return render_template("reset_password.html", demo_otp=demo_otp,
                                   mail_enabled=mail_enabled, email_sent=email_sent)

        if len(new_pass) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("reset_password.html", demo_otp=demo_otp,
                                   mail_enabled=mail_enabled, email_sent=email_sent)

        if new_pass != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("reset_password.html", demo_otp=demo_otp,
                                   mail_enabled=mail_enabled, email_sent=email_sent)

        update_user_password(session["reset_user_id"], new_pass)
        audit("PASSWORD_RESET_SUCCESS", notes="Password reset for: " + session.get("reset_username", ""))
        session.pop("reset_user_id", None)
        session.pop("reset_username", None)
        session.pop("reset_otp", None)
        session.pop("reset_otp_at", None)
        session.pop("reset_email_sent", None)
        flash("Password reset successfully. Please login.", "success")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html", demo_otp=demo_otp,
                           mail_enabled=mail_enabled, email_sent=email_sent)


# ── Logout ───────────────────────────────────────────────────────────────────
@auth_bp.route("/logout")
def logout():
    audit("LOGOUT", notes="User logged out")
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))
