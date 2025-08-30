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

    # ---- Secret Code input (NEW) ----
    suggested_code = secrets.token_urlsafe(8)
    user_secret_code = st.text_input(
        "Enter a Secret Code (used at login)", 
        value=suggested_code, 
        help="Copy this somewhere safe! You'll need it along with your password to sign in."
    )

    if st.button("Create Account", type="primary"):
        users = load_users()
        if not username.strip():
            st.error("Username is required.")
        elif username_exists(users, username.strip()):
            st.error("That username already exists. Choose another.")
        elif not first_name or not last_name:
            st.error("Please fill your name.")
        elif not pw or not pw2:
            st.error("Please enter and confirm your password.")
        elif pw != pw2:
            st.error("Passwords do not match.")
        elif not user_secret_code.strip():
            st.error("Secret Code is required.")
        else:
            issues = password_issues(pw)
            if issues:
                st.error("Please strengthen your password before continuing.")
            else:
                # Hash password + secret code
                pw_salt, pw_hash = hash_with_salt(pw)
                sc_salt, sc_hash = hash_with_salt(user_secret_code.strip())

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

                st.success("✅ Account created successfully!")
                st.info("⚠️ Save your Secret Code safely. You’ll need it every time you sign in.")
                st.code(f"Your Secret Code: {user_secret_code.strip()}", language="text")
