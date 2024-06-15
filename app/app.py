import streamlit as st
import requests


def local_css(file_name):
    with open(file_name) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


local_css("style.css")

BASE_URL = "http://localhost:8000/api"
AUTH = "auth"
USERS = "users"


def register_user():
    st.subheader("Register")

    email = st.text_input("Email")
    name = st.text_input("Name")
    password = st.text_input("Password", type="password")
    password_confirm = st.text_input("Confirm Password", type="password")
    role = st.text_input("Role")

    if st.button("Register"):
        if password != password_confirm:
            st.error("Passwords do not match")
        else:
            payload = {
                "email": email,
                "name": name,
                "password": password,
                "passwordConfirm": password_confirm,
                "role": role
            }
            response = requests.post(f"{BASE_URL}/{AUTH}/register", json=payload)
            if response.status_code == 201:
                st.success("User registered successfully!")
            else:
                st.error(response.json().get("detail", "Registration failed"))


def login_user():
    st.subheader("Login")

    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        payload = {
            "email": email,
            "password": password
        }
        response = requests.post(f"{BASE_URL}/{AUTH}/login", json=payload)
        if response.status_code == 200:
            data = response.json()
            st.session_state['access_token'] = data['user_access_token']
            st.session_state['refresh_token'] = data['user_refresh_token']
            st.success("Logged in successfully!")
        else:
            st.error(response.json().get("detail", "Login failed"))


def refresh_token():
    st.subheader("Refresh Token")

    if st.button("Refresh Token"):
        headers = {"Authorization": f"Bearer {st.session_state.get('refresh_token')}"}
        response = requests.get(f"{BASE_URL}/{AUTH}/refresh", headers=headers)
        if response.status_code == 200:
            data = response.json()
            st.session_state['access_token'] = data['access_token']
            st.success("Access token refreshed successfully!")
        else:
            st.error(response.json().get("detail", "Token refresh failed"))


def logout_user():
    st.subheader("Logout")

    if st.button("Logout"):
        headers = {"Authorization": f"Bearer {st.session_state.get('access_token')}"}
        response = requests.get(f"{BASE_URL}/{AUTH}/logout", headers=headers)
        if response.status_code == 200:
            st.session_state.clear()
            st.success("Logged out successfully!")
        else:
            st.error(response.json().get("detail", "Logout failed"))


def get_me():
    st.subheader("Get My profile")

    headers = {"Authorization": f"Bearer {st.session_state.get('access_token')}"}
    response = requests.get(f"{BASE_URL}/{USERS}/me", headers=headers)
    if response.status_code == 200:
        user_info = response.json().get("user", {})
        if user_info:
            st.markdown("""
                        <style>
                        .user-info {
                            font-size: 24px;
                            color: white;
                            margin-bottom: 10px;
                        }
                        .user-info-label {
                            font-weight: bold;
                            color: #a0a0a0;
                        }
                        </style>
                    """, unsafe_allow_html=True)

            st.markdown(f"""
                        <div class="user-info"><span class="user-info-label">Name:</span> {user_info.get('name')}</div>
                        <div class="user-info"><span class="user-info-label">Email:</span> {user_info.get('email')}</div>
                        <div class="user-info"><span class="user-info-label">Role:</span> {user_info.get('role')}</div>
                        <div class="user-info"><span class="user-info-label">Verified:</span> {user_info.get('verified')}</div>
                        <div class="user-info"><span class="user-info-label">Created At:</span> {user_info.get('created_at')}</div>
                        <div class="user-info"><span class="user-info-label">Updated At:</span> {user_info.get('updated_at')}</div>
                    """, unsafe_allow_html=True)
        else:
            st.error("No user info available.")
    else:
        st.error(response.json().get("detail", "Failed to get user info"))


def delete_all_users():
    st.subheader("Delete All Users")

    if st.button("Delete All Users"):
        headers = {"Authorization": f"Bearer {st.session_state.get('access_token')}"}
        response = requests.delete(f"{BASE_URL}/{USERS}/delete-users", headers=headers)
        if response.status_code == 200:
            st.success("All users deleted successfully!")
        else:
            st.error(response.json().get("detail", "Failed to delete all users"))


def get_all_users():
    st.subheader("List of users")

    headers = {"Authorization": f"Bearer {st.session_state.get('access_token')}"}
    response = requests.get(f"{BASE_URL}/{USERS}/users-list/", headers=headers)
    if response.status_code == 200:
        users = response.json()

        # Check for expected data structure (optional)
        if all("id" in user for user in users):  # Uncomment if needed

            # Select desired columns efficiently using list comprehension
            selected_users = [
                {"ID": user["id"], "Email": user["email"], "Name": user.get("name", ""),
                 "Created at": user["created_at"]}
                for user in users
            ]
            # Check if selected_users has data
            if selected_users:
                # Try without width parameter initially
                st.table(selected_users)

            else:
                st.warning("No user data found.")
        else:
            st.error("Invalid response format. User objects must contain 'id' field.")

    else:
        st.error(response.json().get("detail", "Failed to get all users"))


def get_user_details():
    st.subheader("Get User Details")

    user_id = st.text_input("User ID")
    if st.button("Get User Details"):
        headers = {"Authorization": f"Bearer {st.session_state.get('access_token')}"}
        response = requests.get(f"{BASE_URL}/{USERS}/users-list/{user_id}", headers=headers)
        if response.status_code == 200:
            user_info = response.json()
            if user_info:
                st.markdown("""
                            <style>
                            .user-info {
                                font-size: 24px;
                                color: white;
                                margin-bottom: 10px;
                            }
                            .user-info-label {
                                font-weight: bold;
                                color: #a0a0a0;
                            }
                            </style>
                        """, unsafe_allow_html=True)

                st.markdown(f"""
                            <div class="user-info"><span class="user-info-label">Name:</span> {user_info.get('name')}</div>
                            <div class="user-info"><span class="user-info-label">Email:</span> {user_info.get('email')}</div>
                            <div class="user-info"><span class="user-info-label">Role:</span> {user_info.get('role')}</div>
                            <div class="user-info"><span class="user-info-label">Verified:</span> {user_info.get('verified')}</div>
                            <div class="user-info"><span class="user-info-label">Created At:</span> {user_info.get('created_at')}</div>
                            <div class="user-info"><span class="user-info-label">Updated At:</span> {user_info.get('updated_at')}</div>
                        """, unsafe_allow_html=True)
            else:
                st.error("No user info available.")
        else:
            st.error(response.json().get("detail", "Failed to get user info"))


def main():
    st.title("FastAPI with JWT Authentication")

    menu = ["Register", "Login", "Refresh Token", "Logout", "My profile", "Delete All Users", "Get All Users",
            "Get User Details"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Register":
        register_user()
    elif choice == "Login":
        login_user()
    elif choice == "Refresh Token":
        refresh_token()
    elif choice == "Logout":
        logout_user()
    elif choice == "My profile":
        get_me()
    elif choice == "Delete All Users":
        delete_all_users()
    elif choice == "Get All Users":
        get_all_users()
    elif choice == "Get User Details":
        get_user_details()


if __name__ == "__main__":
    main()
