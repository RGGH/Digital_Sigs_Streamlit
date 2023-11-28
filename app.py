import streamlit as st
from ecdsa import SigningKey, VerifyingKey, SECP256k1

st.title("ECDSA Signature Generator and Verifier")

# Define session state to store variables across sessions
if 'private_key' not in st.session_state:
    st.session_state.private_key = SigningKey.generate(curve=SECP256k1)

# Step 1: Generate a private key
st.header("Step 1: Generate a Private Key")
private_key_string = st.session_state.private_key.to_string().hex()

st.code(f"Private Key: {private_key_string}")

# Step 2: Get the corresponding public key
st.header("Step 2: Get the Corresponding Public Key")
public_key = st.session_state.private_key.get_verifying_key()
public_key_string = public_key.to_string().hex()

# Display the public key without "Public key:" text
st.write(f"Public Key: `{public_key_string}`")

# Step 3: User Input - Message to Sign
st.header("Step 3: User Input - Message to Sign")
message_to_sign = st.text_area("Enter your message to sign:")

# Step 4: Sign the message
if message_to_sign:
    st.header("Step 4: Sign the Message")
    message = message_to_sign.encode("utf-8")
    signature = st.session_state.private_key.sign(message)
    signature_string = signature.hex()

    st.code(f"Message: {message_to_sign}")
    st.code(f"Signature: {signature_string}")

    # Step 5: Verify the signature with user input public key
    st.header("Step 5: Verify the Signature")
    input_public_key = st.text_input("Enter the public key (hex format):")

    if input_public_key:
        try:
            input_public_key_bytes = bytes.fromhex(input_public_key)
            user_public_key = VerifyingKey.from_string(input_public_key_bytes, curve=SECP256k1)

            if user_public_key.verify(signature, message):
                st.success("Signature is valid for the provided public key.")
            else:
                st.error("Signature is not valid for the provided public key.")
        except ValueError:
            st.error("Invalid public key format. Please enter a valid hex-encoded public key.")

