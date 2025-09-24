from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3
import bcrypt
import smtplib
from email.mime.text import MIMEText
import random
import string
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)  # Allow frontend to communicate with backend

# Load environment variables
load_dotenv()

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-super-secret-jwt-key-change-in-production')  # Use .env for this
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)  # Token expires in 24 hours
jwt = JWTManager(app)

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        company TEXT NOT NULL,
        password TEXT NOT NULL,
        is_verified INTEGER DEFAULT 0
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS otps (
        email TEXT PRIMARY KEY,
        otp TEXT NOT NULL,
        expires_at TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()

init_db()

# Generate 6-digit OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Send OTP email
def send_otp_email(email, otp):
    smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    smtp_user = os.getenv('SMTP_USER')
    smtp_password = os.getenv('SMTP_PASSWORD')

    msg = MIMEText(f'Your StockFlow OTP is: {otp}. It expires in 10 minutes.')
    msg['Subject'] = 'StockFlow OTP Verification'
    msg['From'] = smtp_user
    msg['To'] = email

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

# Register endpoint
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    first_name = data.get('firstName')
    last_name = data.get('lastName')
    email = data.get('email')
    company = data.get('company')
    password = data.get('password')

    # Validate input
    if not all([first_name, last_name, email, company, password]):
        return jsonify({'error': 'All fields are required'}), 400

    # Check if email already exists
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT email FROM users WHERE email = ?', (email,))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'Email already exists'}), 400

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Store user (unverified)
    c.execute('INSERT INTO users (first_name, last_name, email, company, password, is_verified) VALUES (?, ?, ?, ?, ?, 0)',
              (first_name, last_name, email, company, hashed_password))
    conn.commit()

    # Generate and store OTP
    otp = generate_otp()
    expires_at = (datetime.now() + timedelta(minutes=10)).isoformat()  # Store as ISO string
    c.execute('INSERT OR REPLACE INTO otps (email, otp, expires_at) VALUES (?, ?, ?)',
              (email, otp, expires_at))
    conn.commit()
    conn.close()

    # Send OTP
    if not send_otp_email(email, otp):
        return jsonify({'error': 'Failed to send OTP'}), 500

    return jsonify({'message': 'OTP sent to email'}), 200

# OTP verification endpoint
@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT otp, expires_at FROM otps WHERE email = ?', (email,))
    result = c.fetchone()

    if not result:
        conn.close()
        return jsonify({'error': 'No OTP found for this email'}), 400

    stored_otp, expires_at = result
    expires_at = datetime.fromisoformat(expires_at)  # Parse ISO string

    if datetime.now() > expires_at:
        c.execute('DELETE FROM otps WHERE email = ?', (email,))
        conn.commit()
        conn.close()
        return jsonify({'error': 'OTP has expired'}), 400

    if otp != stored_otp:
        conn.close()
        return jsonify({'error': 'Invalid OTP'}), 400

    # Mark user as verified
    c.execute('UPDATE users SET is_verified = 1 WHERE email = ?', (email,))
    c.execute('DELETE FROM otps WHERE email = ?', (email,))
    conn.commit()
    conn.close()

    return jsonify({'message': 'Account verified successfully'}), 200

# Login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT id, first_name, email, password, is_verified FROM users WHERE email = ?', (email,))
    user_row = c.fetchone()
    conn.close()

    if not user_row:
        return jsonify({'error': 'Invalid email or password'}), 401

    user_id, first_name, stored_email, hashed_password, is_verified = user_row

    # Check if account is verified
    if not is_verified:
        return jsonify({'error': 'Please verify your email before logging in'}), 401

    # Verify password using bcrypt
    if not bcrypt.checkpw(password.encode('utf-8'), hashed_password):
        return jsonify({'error': 'Invalid email or password'}), 401

    # Generate JWT token
    access_token = create_access_token(identity={'user_id': user_id, 'email': stored_email, 'first_name': first_name})

    return jsonify({
        'message': 'Login successful',
        'access_token': access_token,
        'user': {'id': user_id, 'first_name': first_name, 'email': stored_email}
    }), 200

# Example protected route (add @jwt_required() to other endpoints as needed)
@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'message': 'This is a protected route', 'user': current_user}), 200

if __name__ == '__main__':
    app.run(port=5000, debug=True)