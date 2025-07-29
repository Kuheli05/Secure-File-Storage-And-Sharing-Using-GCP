from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")

def generate_keys():
    key = RSA.generate(2048)
    with open(f"{KEY_DIR}/private_key.pem", "wb") as f:
        f.write(key.export_key())
    with open(f"{KEY_DIR}/public_key.pem", "wb") as f:
        f.write(key.publickey().export_key())

def encrypt_file(filepath):
    data = open(filepath, 'rb').read()
    session_key = get_random_bytes(16)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    public_key = RSA.import_key(open(f"{KEY_DIR}/public_key.pem").read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    encrypted_path = filepath + ".enc"
    with open(encrypted_path, 'wb') as f:
        for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext):
            f.write(x)

    return encrypted_path, enc_session_key

def decrypt_file(enc_filepath):
    private_key = RSA.import_key(open(f"{KEY_DIR}/private_key.pem").read())

    with open(enc_filepath, 'rb') as f:
        enc_session_key = f.read(256)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    decrypted_path = enc_filepath.replace(".enc", ".dec")
    with open(decrypted_path, 'wb') as f:
        f.write(data)

    return decrypted_path
