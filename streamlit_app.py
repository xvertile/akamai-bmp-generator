import streamlit as st, requests, json

st.set_page_config("Akamai BMP Generator", layout="wide")
st.title("Akamai BMP Generator")

host = st.sidebar.text_input("Server URL", "http://localhost:1337")
version = st.sidebar.selectbox("BMP Version", [
    "4.0.2","3.3.9","3.3.4","3.3.1","3.3.0",
    "3.2.3","3.1.0","2.2.3","2.2.2","2.1.2"])
app  = st.sidebar.text_input("Package", "com.kohls.mcommerce.opal")
lang = st.sidebar.text_input("Locale", "en_US")
challenge = st.sidebar.checkbox("Proof‑of‑Work", False)
pow_url = st.sidebar.text_input("POW URL (if any)", "")

if st.button("Generate Sensor"):
    resp = requests.post(f"{host}/akamai/bmp", json={
        "app": app, "lang": lang, "version": version,
        "challenge": challenge, "powUrl": pow_url
    })
    if resp.ok:
        st.code(json.dumps(resp.json(), indent=2))
    else:
        st.error(f"{resp.status_code} {resp.text}") 