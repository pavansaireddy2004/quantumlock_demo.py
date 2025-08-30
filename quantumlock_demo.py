# questionlock_demo.py
# Single-file Streamlit app: Account creation + 2FA-style login (password + secret code) + local file locker

import streamlit as st
from pathlib import Path
import json
import hashlib
import secrets
import re
from datetime import date
import os

# -----------------------------
# Paths & simple JSON "database"
# -----------------------------
BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "users.json"
FILES_ROOT = BASE_DIR / "user_files"
FILES_ROOT.mkdir(exist_ok=True)

def load_users():
    if not DB_PATH.exists():
        return {}
    try:
        return json.loads(DB_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}

def save_users(users: dict):
    DB_PATH.write_text(json.dumps(users, indent=2), encoding="utf-8")

# -----------------------------
# Security helpers (hashing)
# -----------------------------
def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def hash_with_salt(secret: str, salt: str | None = None):
    salt = salt or secrets.token_hex(16)
    return salt, sha256_hex(salt + secret)

def verify_with_salt(secret: str, salt: str, digest: str) -> bool:
    return sha256_hex(salt + secret) == digest

# -----------------------------
# Password policy & feedback
# -----------------------------
PW_MIN_LEN = 12

def password_issues(pw: str):
    issues = []
    if len(pw) < PW_MIN_LEN:
        issues.append(f"Password must be at least {PW_MIN_LEN} characters.")
    if not re.search(r"[A-Z]", pw):
        issues.append("Add uppercase letters (A–Z).")
    if not re.search(r"[a-z]", pw):
        issues.append("Add lowercase letters (a–z).")
    if not re.search(r"\d", pw):
        issues.append("Add numbers (0–9).")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\+=/\\\$\$;'`~]", pw):
        issues.append("Add special characters (e.g., ! @ # $ % ^ & *).")
    # discourage obvious/common patterns
    if re.fullmatch(r"(?:password|qwerty|letmein|123456|123456789|admin)", pw, re.IGNORECASE):
        issues.append("Avoid common passwords (password, 123456, qwerty, letmein…).")
    # discourage personal info (very basic checks; real system would be stronger)
    # (We’ll just warn if it looks like an email)
    if "@" in pw and "." in pw:
        issues.append("Avoid including your email/personal info in the password.")
    return issues

def password_strength_score(pw: str) -> int:
    score = 0
    if len(pw) >= PW_MIN_LEN: score += 1
    if re.search(r"[A-Z]", pw): score += 1
    if re.search(r"[a-z]", pw): score += 1
    if re.search(r"\d", pw): score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\+=/\\\$\$;'`~]", pw): score += 1
    return score  # 0–5

# -----------------------------
# Simple user model in JSON
# users = {
#   username: {
#     profile: {...},
#     pw_salt: "...",
#     pw_hash: "...",
#     sc_salt: "...",   # secret-code salt
#     sc_hash: "...",   # secret-code hash
#   }
# }
# -----------------------------

def username_exists(users, username: str) -> bool:
    return any(username.lower() == u.lower() for u in users.keys())

def get_user(users, username: str):
    for k, v in users.items():
        if k.lower() == username.lower():
            return k, v
    return None, None

# -----------------------------
# Username validation (added)
# -----------------------------
def valid_username(username: str) -> bool:
    # Allow 3-20 chars: letters, numbers, underscore, dash only
    return bool(re.fullmatch(r"[A-Za-z0-9_-]{3,20}", username))

# -----------------------------
# File helpers
# -----------------------------
def user_folder(username: str) -> Path:
    folder = FILES_ROOT / username
    folder.mkdir(exist_ok=True, parents=True)
    return folder

def human_size(num_bytes: int) -> str:
    for unit in ["B","KB","MB","GB","TB"]:
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"

# Filename sanitization (added)
def sanitize_filename(filename):
    return re.sub(r'[^A-Za-z0-9._-]', '_', filename)

# -----------------------------
# UI
# -----------------------------
st.set_page_config(page_title="QuantumLock: AI-Powered SafeVault", page_icon="🔒", layout="centered")
st.title("🔒 QuantumLock — SafeVault (Demo)")
st.caption("Single-file demo: Account creation → 2FA-style sign-in (Password + Secret Code) → Personal file locker")

# Session
if "auth_user" not in st.session_state:
    st.session_state.auth_user = None  # stores canonical username on login

# -----------------------------
# Tabs: Sign Up / Sign In / Reset
# -----------------------------
tab_signup, tab_signin, tab_reset = st.tabs(["Create Account", "Sign In", "Forgot Password"])

with tab_signup:
    st.subheader("Create Account")
    col1, col2, col3 = st.columns(3)
    with col1:
        first_name = st.text_input("First name")
    with col2:
        middle_name = st.text_input("Middle name (optional)")
    with col3:
        last_name = st.text_input("Last name")

    dob = st.date_input("Date of Birth", value=date(2000, 1, 1), format="DD/MM/YYYY")
    gender = st.selectbox("Gender", ["Male", "Female", "Other", "Prefer not to say"])

    username = st.text_input("Username (unique, used for login)")
    # Optional: a "secret phrase/name" (not required for login in this demo)
    secret_phrase = st.text_input("Secret phrase (optional, e.g., a memorable name)")

    st.markdown("#### Create Password")
    pw = st.text_input("Password", type="password", help=f"Minimum {PW_MIN_LEN} characters with UPPER/lowercase, numbers & special characters.")
    pw2 = st.text_input("Confirm Password", type="password")

    # live feedback
    if pw:
        issues = password_issues(pw)
        score = password_strength_score(pw)
        st.progress(score / 5.0, text=f"Password strength: {score}/5")
        if issues:
            st.warning("Suggestions:\n- " + "\n- ".join(issues))
        else:
            st.success("Looks good! Strong password ✅")

    if st.button("Create Account", type="primary"):
        users = load_users()
        if not username.strip():
            st.error("Username is required.")
        elif not valid_username(username.strip()):
            st.error("Username must be 3-20 characters: letters, numbers, underscore, or dash only.")
        elif username_exists(users, username.strip()):
            st.error("That username already exists. Choose another.")
        elif not first_name or not last_name:
            st.error("Please fill your name.")
        elif not pw or not pw2:
            st.error("Please enter and confirm your password.")
        elif pw != pw2:
            st.error("Passwords do not match.")
        else:
            issues = password_issues(pw)
            if issues:
                st.error("Please strengthen your password before continuing.")
            else:
                # Hash and store password
                pw_salt, pw_hash = hash_with_salt(pw)

                # Generate a Secret Code for login (like a 2nd factor)
                secret_code_plain = secrets.token_urlsafe(8)  # show to user once!
                sc_salt, sc_hash = hash_with_salt(secret_code_plain)

                # Save profile
                users[username] = {
                    "profile": {
                        "first_name": first_name,
                        "middle_name": middle_name,
                        "last_name": last_name,
                        "dob": dob.isoformat(),
                        "gender": gender,
                        "secret_phrase": secret_phrase,
                    },
                    "pw_salt": pw_salt,
                    "pw_hash": pw_hash,
                    "sc_salt": sc_salt,
                    "sc_hash": sc_hash,
                }
                save_users(users)

                st.success("Account created successfully! ✅")
                st.info("⚠️ Save your **Secret Code** safely. You’ll need it **along with your password** to sign in.")
                st.code(f"Your Secret Code: {secret_code_plain}", language="text")
                st.caption("Tip: Store this in a password manager or write it down in a safe place.")

with tab_signin:
    st.subheader("Sign In (requires Password + Secret Code)")
    li_username = st.text_input("Username", key="li_user")
    li_password = st.text_input("Password", type="password", key="li_pw")
    li_secret = st.text_input("Secret Code", type="password", help="The recovery code shown when you created the account.")

    # --- FIX: Strip whitespace from Secret Code input to avoid verification errors ---
    li_secret = li_secret.strip() if li_secret else ""

    if st.button("Sign In", type="primary"):
        users = load_users()
        uname_key, user = get_user(users, li_username.strip())
        if not user:
            st.error("User   not found.")
        else:
            ok_pw = verify_with_salt(li_password, user["pw_salt"], user["pw_hash"])
            ok_sc = verify_with_salt(li_secret, user["sc_salt"], user["sc_hash"])
            if not ok_pw:
                st.error("Incorrect password.")
            elif not ok_sc:
                st.error("Incorrect Secret Code.")
            else:
                st.session_state.auth_user = uname_key
                st.success(f"Welcome, {user['profile']['first_name']}! 🔓 You are signed in.")
                st.rerun()

with tab_reset:
    st.subheader("Forgot Password (use Secret Code to reset)")
    rp_user = st.text_input("Username", key="rp_user")
    rp_secret = st.text_input("Secret Code", type="password", key="rp_sc")
    new_pw = st.text_input("New Password", type="password")
    new_pw2 = st.text_input("Confirm New Password", type="password")
    if st.button("Reset Password"):
        users = load_users()
        uname_key, user = get_user(users, rp_user.strip())
        if not user:
            st.error("User   not found.")
        else:
            if not verify_with_salt(rp_secret, user["sc_salt"], user["sc_hash"]):
                st.error("Secret Code is incorrect.")
            elif new_pw != new_pw2:
                st.error("New passwords do not match.")
            else:
                issues = password_issues(new_pw)
                if issues:
                    st.error("Please choose a stronger password:\n- " + "\n- ".join(issues))
                else:
                    salt, digest = hash_with_salt(new_pw)
                    user["pw_salt"], user["pw_hash"] = salt, digest
                    users[uname_key] = user
                    save_users(users)
                    st.success("Password reset successful! You can now sign in.")

# -----------------------------
# Locker area (only after auth)
# -----------------------------
if st.session_state.auth_user:
    st.divider()
    st.header("🔐 Your Locker")
    st.caption("Upload files (docs, images, videos). They’re stored locally under your own folder on this machine.")

    colA, colB = st.columns([3,1])
    with colA:
        uploads = st.file_uploader("Upload files", accept_multiple_files=True)
    with colB:
        if st.button("Sign Out"):
            st.session_state.auth_user = None
            st.rerun()

    current_user = st.session_state.auth_user
    folder = user_folder(current_user)

    # Save new uploads
    if uploads:
        for up in uploads:
            dest = folder / sanitize_filename(up.name)  # sanitize filename to avoid issues
            with open(dest, "wb") as f:
                f.write(up.getbuffer())
        st.success(f"Uploaded {len(uploads)} file(s).")

    # List files
    files = sorted(folder.glob("*"))
    if not files:
        st.info("No files yet. Upload something to get started.")
    else:
        st.subheader("📂 Files")
        for file_path in files:
            size = human_size(file_path.stat().st_size)
            col1, col2, col3, col4 = st.columns([5,2,2,2])
            col1.write(f"**{file_path.name}**  \n<size: {size}>")
            with col2:
                with open(file_path, "rb") as f:
                    st.download_button("Download", data=f.read(), file_name=file_path.name)
            with col3:
                if st.button("Delete", key=f"del-{file_path.name}"):
                    try:
                        os.remove(file_path)
                        st.warning(f"Deleted {file_path.name}")
                        st.rerun()
                    except Exception as e:
                        st.error(f"Failed to delete: {e}")
            with col4:
                st.write("")  # spacer

    st.caption("Note: This demo stores data locally (JSON for users, per-user folder for files). For production, use a real database + encryption.")

else:
    st.info("Sign in to access your locker. New here? Create an account first.")
    st.markdown("**Security Tips (Recap):**")
    st.markdown("""
- Use **12–16+ characters** with UPPER/lowercase, numbers, and special characters.  
- Avoid common passwords or personal info.  
- Prefer **passphrases** (e.g., `BlueTiger!Dances123`).  
- Use **unique passwords** for different sites.  
- Save your **Secret Code** safely — it's required with your password to sign in.
""")