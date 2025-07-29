from flask import Flask, render_template, request, redirect, session, send_file, jsonify
from flask_session import Session
import os
from db import get_db_connection
from crypto_utils import encrypt_file, decrypt_file
from gcs_utils import upload_to_gcs, download_from_gcs, generate_signed_url


app = Flask(__name__)
app.secret_key = "secret_key"
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        conn = get_db_connection()
        cursor = conn.cursor()
        username = request.form['username']
        password = request.form['password']
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
        conn.commit()
        cursor.close()
        conn.close()
        return redirect('/login')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        conn = get_db_connection()
        cursor = conn.cursor()
        username = request.form['username']
        password = request.form['password']
        cursor.execute("SELECT id FROM users WHERE username=%s AND password=%s", (username, password))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        if user:
            session['user_id'] = user[0]
            return redirect('/dashboard')
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        file = request.files['file']
        if file:
            filepath = os.path.join(UPLOAD_FOLDER, file.filename)
            file.save(filepath)

            # Encrypt the file
            enc_path, enc_key = encrypt_file(filepath)
            encrypted_filename = file.filename + ".enc"

            # Upload the encrypted file to GCS
            upload_to_gcs(enc_path, encrypted_filename)

            # Generate the signed URL for the uploaded file
            signed_url = generate_signed_url(encrypted_filename)

            # Return the signed URL and display it on the dashboard
            return render_template('dashboard.html', signed_url=signed_url, filename=encrypted_filename)

    return render_template('dashboard.html')

@app.route('/download', methods=['GET'])
def download():
    if 'user_id' not in session:
        return redirect('/login')

    # Get the filename from the query string (encrypted file name)
    filename = request.args.get('filename')

    if not filename:
        return "Filename is required", 400

    # The encrypted file's path
    enc_file_path = os.path.join(UPLOAD_FOLDER, filename)

    try:
        # Download the encrypted file from GCS
        download_from_gcs(filename, enc_file_path)
    except Exception as e:
        return f"Error downloading file: {e}", 500

    # Decrypt the file
    decrypted_file_path = decrypt_file(enc_file_path)

    # Send the decrypted file to the user for download
    return send_file(decrypted_file_path, as_attachment=True, download_name=f"decrypted_{filename.replace('.enc', '.txt')}")


if __name__ == '__main__':
    app.run(debug=True)
