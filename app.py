from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
import smtplib
from email.mime.text import MIMEText
import random
import string
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from pymongo import MongoClient

app = Flask(__name__)
CORS(app, origins=["https://zenith-stock-suite.vercel.app"])  # Allow frontend to communicate with backend

# Load environment variables
load_dotenv()

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-super-secret-jwt-key-change-in-production')  # Use .env for this
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)  # Token expires in 24 hours
jwt = JWTManager(app)

# MongoDB setup
mongo_uri = os.getenv('MONGODB_URI')
if not mongo_uri:
    raise ValueError("MONGODB_URI not set in environment variables")
client = MongoClient(mongo_uri)
db = client['stockflow']  # Database name
users = db['users']
otps = db['otps']

# Initialize indexes
def init_db():
    users.create_index('email', unique=True)
    otps.create_index('email')

init_db()

# Generate 6-digit OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Send OTP email
def send_otp_email(email, otp, purpose='verification'):
    smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    smtp_user = os.getenv('SMTP_USER')
    smtp_password = os.getenv('SMTP_PASSWORD')

    if purpose == 'reset':
        message = f'Your StockFlow password reset OTP is: {otp}. It expires in 10 minutes.'
        subject = 'StockFlow Password Reset OTP'
    else:
        message = f'Your StockFlow OTP is: {otp}. It expires in 10 minutes.'
        subject = 'StockFlow OTP Verification'

    msg = MIMEText(message)
    msg['Subject'] = subject
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
    if users.find_one({'email': email}):
        return jsonify({'error': 'Email already exists'}), 400

    # Hash password (store as string)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Store user (unverified)
    users.insert_one({
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'company': company,
        'password': hashed_password,
        'is_verified': False
    })

    # Generate and store OTP
    otp = generate_otp()
    expires_at = datetime.now() + timedelta(minutes=10)
    otps.replace_one(
        {'email': email, 'purpose': 'verification'},
        {'email': email, 'otp': otp, 'expires_at': expires_at, 'purpose': 'verification'},
        upsert=True
    )

    # Send OTP
    if not send_otp_email(email, otp, 'verification'):
        return jsonify({'error': 'Failed to send OTP'}), 500

    return jsonify({'message': 'OTP sent to email'}), 200

# OTP verification endpoint
@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    otp_doc = otps.find_one({'email': email, 'purpose': 'verification'})

    if not otp_doc:
        return jsonify({'error': 'No OTP found for this email'}), 400

    if datetime.now() > otp_doc['expires_at']:
        otps.delete_one({'email': email, 'purpose': 'verification'})
        return jsonify({'error': 'OTP has expired'}), 400

    if otp != otp_doc['otp']:
        return jsonify({'error': 'Invalid OTP'}), 400

    # Mark user as verified
    users.update_one({'email': email}, {'$set': {'is_verified': True}})
    otps.delete_one({'email': email, 'purpose': 'verification'})

    return jsonify({'message': 'Account verified successfully'}), 200

# Forgot password endpoint (send reset OTP)
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    # Check if email exists
    if not users.find_one({'email': email}):
        return jsonify({'error': 'Email not found'}), 404

    # Generate and store OTP for reset
    otp = generate_otp()
    expires_at = datetime.now() + timedelta(minutes=10)
    otps.replace_one(
        {'email': email, 'purpose': 'reset'},
        {'email': email, 'otp': otp, 'expires_at': expires_at, 'purpose': 'reset'},
        upsert=True
    )

    # Send OTP
    if not send_otp_email(email, otp, 'reset'):
        return jsonify({'error': 'Failed to send OTP'}), 500

    return jsonify({'message': 'Reset OTP sent to email'}), 200

# Reset password endpoint
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    password = data.get('password')

    if not all([email, otp, password]):
        return jsonify({'error': 'Email, OTP, and password are required'}), 400

    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    otp_doc = otps.find_one({'email': email, 'purpose': 'reset'})

    if not otp_doc:
        return jsonify({'error': 'No reset OTP found for this email'}), 400

    if datetime.now() > otp_doc['expires_at']:
        otps.delete_one({'email': email, 'purpose': 'reset'})
        return jsonify({'error': 'OTP has expired'}), 400

    if otp != otp_doc['otp']:
        return jsonify({'error': 'Invalid OTP'}), 400

    # Hash new password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Update password
    users.update_one({'email': email}, {'$set': {'password': hashed_password}})
    otps.delete_one({'email': email, 'purpose': 'reset'})

    return jsonify({'message': 'Password reset successfully'}), 200

# Login endpoint
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = users.find_one({'email': email})

    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401

    # Check if account is verified
    if not user['is_verified']:
        return jsonify({'error': 'Please verify your email before logging in'}), 401

    # Verify password using bcrypt
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'error': 'Invalid email or password'}), 401

    # Generate JWT token
    access_token = create_access_token(identity={'user_id': str(user['_id']), 'email': user['email'], 'first_name': user['first_name']})

    return jsonify({
        'message': 'Login successful',
        'access_token': access_token,
        'user': {'id': str(user['_id']), 'first_name': user['first_name'], 'email': user['email']}
    }), 200

# Example protected route (add @jwt_required() to other endpoints as needed)
@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({'message': 'This is a protected route', 'user': current_user}), 200

# TODO: Future routes for additional pages - uncomment and implement as needed
# @app.route('/api/dashboard', methods=['GET'])
# @jwt_required()
# def dashboard():
#     current_user = get_jwt_identity()
#     # Fetch dashboard data for user
#     return jsonify({'message': 'Dashboard data', 'user': current_user})

# @app.route('/api/inventory', methods=['GET', 'POST'])
# @jwt_required()
# def inventory():
#     current_user = get_jwt_identity()
#     # Handle inventory CRUD
#     return jsonify({'message': 'Inventory endpoint'})

# @app.route('/api/reports', methods=['GET'])
# @jwt_required()
# def reports():
#     current_user = get_jwt_identity()
#     # Generate reports
#     return jsonify({'message': 'Reports endpoint'})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)