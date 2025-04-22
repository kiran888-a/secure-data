import streamlit as st
import hashlib
from cryptography.fernet import Fernet

if 'KEY' not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()

cipher = Fernet(st.session_state.KEY)

# --- In-memory storage ---
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'authorized' not in st.session_state:
    st.session_state.authorized = True

# --- Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# --- Streamlit UI ---
st.title("🔒 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# --- Home Page ---
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Store and retrieve your sensitive data securely using passkeys.")

# --- Store Data Page ---
elif choice == "Store Data":
    st.subheader("📂 Store Data")
    user_data = st.text_area("Enter data to store:")
    passkey = st.text_input("Set a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(user_data)
            st.session_state.stored_data[encrypted] = {"encrypted_text": encrypted, "passkey": hashed}
            st.success("✅ Data encrypted and stored successfully.")
            st.code(encrypted, language="text")  # Show encrypted text to copy
        else:
            st.error("⚠ Please fill in both fields.")

# --- Retrieve Data Page ---
elif choice == "Retrieve Data":
    if not st.session_state.authorized:
        st.warning("🔐 Too many failed attempts. Please login first.")
        st.stop()

    st.subheader("🔍 Retrieve Data")
    encrypted_input = st.text_area("Enter Encrypted Text:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey:
            result = decrypt_data(encrypted_input, passkey)
            if result:
                st.success(f"✅ Decrypted Data: {result}")
            else:
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey. Attempts left: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    
        else:
            st.error("⚠ Both fields are required.")

# --- Login Page ---
elif choice == "Login":
    st.subheader("🔑 Login for Reauthorization")
    master_pass = st.text_input("Enter admin password:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.authorized = True
            st.success("✅ Reauthorized successfully.")
        else:
            st.error("❌ Incorrect password.")