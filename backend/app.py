import logging
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import uuid
import os

# Setup logging
app = Flask(__name__, template_folder='templates')
app.logger.setLevel(logging.INFO)

# File logging setup
file_handler = logging.FileHandler('app.log')
file_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
app.logger.addHandler(file_handler)

app.config['SECRET_KEY'] = 'super-secret-key-2026-internship'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key-internship-2026'

jwt = JWTManager(app)
CORS(app)

# In-memory databases (production-ready demo)
users_db = {}
profiles_db = []

@app.route('/')
def index():
    app.logger.info("Dashboard accessed")
    return render_template('index.html')

@app.route('/api/register', methods=['POST'])
def register():
    app.logger.info(f"Register attempt: {request.json.get('email')}")
    data = request.json
    
    if data['email'] in users_db:
        app.logger.warning(f"Registration failed - duplicate email: {data['email']}")
        return jsonify({'error': 'User already exists'}), 400
    
    user_id = str(uuid.uuid4())
    users_db[data['email']] = {
        'id': user_id,
        'username': data['username'],
        'email': data['email'],
        'mobile': data.get('mobile', ''),
        'password': generate_password_hash(data['password']),
        'created_at': datetime.datetime.utcnow().isoformat()
    }
    
    app.logger.info(f"User registered successfully: {data['username']}")
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    app.logger.info(f"Login attempt: {request.json.get('email')}")
    data = request.json
    user = users_db.get(data['email'])
    
    if user and check_password_hash(user['password'], data['password']):
        token = create_access_token(identity={'email': user['email'], 'id': user['id']})
        app.logger.info(f"Login successful: {user['username']}")
        return jsonify({
            'token': token,
            'user': {'username': user['username'], 'email': user['email']}
        })
    app.logger.warning(f"Login failed: {data['email']}")
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/profiles', methods=['GET'])
@jwt_required()
def get_profiles():
    app.logger.info("Fetching all profiles")
    return jsonify([{
        '_id': str(p['id']),
        'username': p['username'],
        'email': p['email'],
        'mobile': p.get('mobile', ''),
        'created_at': p.get('created_at', datetime.datetime.utcnow().isoformat())
    } for p in profiles_db])

@app.route('/api/profiles', methods=['POST'])
@jwt_required()
def create_profile():
    app.logger.info(f"Creating profile: {request.json.get('username')}")
    data = request.json
    profile_id = str(uuid.uuid4())
    
    profile = {
        'id': profile_id,
        'username': data['username'],
        'email': data['email'],
        'mobile': data.get('mobile', ''),
        'created_at': datetime.datetime.utcnow().isoformat()
    }
    profiles_db.append(profile)
    
    app.logger.info(f"Profile created: {profile_id}")
    return jsonify({
        '_id': profile_id,
        'username': profile['username'],
        'email': profile['email'],
        'mobile': profile['mobile'],
        'created_at': profile['created_at']
    }), 201

@app.route('/api/profiles/<profile_id>', methods=['DELETE'])
@jwt_required()
def delete_profile(profile_id):
    app.logger.info(f"Deleting profile: {profile_id}")
    global profiles_db
    profiles_db = [p for p in profiles_db if p['id'] != profile_id]
    app.logger.info(f"Profile deleted: {profile_id}")
    return jsonify({'message': 'Profile deleted successfully'})

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """View recent logs for monitoring"""
    try:
        with open('app.log', 'r') as f:
            logs = f.read()[-2000:]  # Last 2000 chars
        return jsonify({'logs': logs})
    except:
        return jsonify({'logs': 'No logs yet'})

if __name__ == '__main__':
    app.logger.info("🚀 Profile Dashboard starting on port 5000")
    app.run(debug=True, host='0.0.0.0', port=5001)
