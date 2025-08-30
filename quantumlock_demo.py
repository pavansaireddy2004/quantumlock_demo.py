import streamlit as st
import json
import os

# ------------------------
# Helper functions
# ------------------------
def load_users():
    if os.path.exists("users.json"):
        with open("users.json", "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open("users.json", "w") as f:
        json.dump(users, f)

def save_user_notes(username, notes):
    os.makedirs(f"data/{username}", exist_ok=True)
    with open(f"data/{username}/notes.json", "w") as f:
        json.dump({"notes": notes}, f)

def load_user_notes(username):
    path = f"data/{username}/notes.json"
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f).get("notes", "")
    return ""

# ------------------------
# App start
# ------------------------
st.title("🔒 QuantumLock Demo")

menu = ["Sign Up", "Sign In", "Reset Password"]
choice = st.sidebar.selectbox("Menu", menu)

users = load_users()

# ------------------------
# Sign Up
# ------------------------
if choice == "Sign Up":
    st.subheader("Create New Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    secret_code = st.text_input("Set a Secret Code (for extra login security)")

    if st.button("Sign Up"):
        if username in users:
            st.error("Username already exists!")
        else:
            users[username] = {"password": password, "secret": secret_code}
            save_users(users)
            st.success("✅ Account created successfully!")
            st.info(f"Your Secret Code is: {secret_code} (save it safely!)")

# ------------------------
# Sign In
# ------------------------
elif choice == "Sign In":
    st.subheader("Login to Your Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    secret_code = st.text_input("Enter Your Secret Code")

    if st.button("Login"):
        if username in users and users[username]["password"] == password and users[username]["secret"] == secret_code:
            st.success(f"🎉 Welcome {username}!")
            
            # ---- Show Home Page ----
            st.header("🌐 Welcome to Cyber World")
            st.write("This is your Locker Dashboard.")

            # Notes Section
            st.subheader("📝 Save Your Important Notes")
            existing_notes = load_user_notes(username)
            notes = st.text_area("Write notes about your PINs, passwords, etc.", existing_notes, height=200)

            if st.button("Save Notes"):
                save_user_notes(username, notes)
                st.success("✅ Notes saved successfully!")

        else:
            st.error("Invalid username, password, or secret code!")

# ------------------------
# Reset Password
# ------------------------
elif choice == "Reset Password":
    st.subheader("Reset Password")
    username = st.text_input("Enter Your Username")
    secret_code = st.text_input("Enter Your Secret Code")
    new_password = st.text_input("Enter New Password", type="password")

    if st.button("Reset"):
        if username in users and users[username]["secret"] == secret_code:
            users[username]["password"] = new_password
            save_users(users)
            st.success("✅ Password reset successfully!")
        else:
            st.error("❌ Invalid username or secret code!")
