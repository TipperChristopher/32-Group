from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
import jwt
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Replace with a secure key in production
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# In-memory database for simplicity
users = {}
files = {}


# Helper function to generate JWT token
def generate_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')


# Middleware to verify JWT token
def token_required(f):
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 401
        try:
            data = jwt.decode(token.replace('Bearer ', ''), app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token'}), 401
        return f(*args, **kwargs)

    decorator.__name__ = f.__name__
    return decorator


# 1. POST /register - Register a new user
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    if username in users:
        return jsonify({'message': 'User already exists'}), 409

    user_id = str(uuid.uuid4())
    users[username] = {
        'user_id': user_id,
        'password': generate_password_hash(password)
    }
    return jsonify({'message': 'User registered successfully', 'user_id': user_id}), 201


# 2. POST /login - Authenticate user and return JWT token
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'message': 'Username and password are required'}), 400

    user = users.get(username)
    if not user or not check_password_hash(user['password'], password):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = generate_token(user['user_id'])
    return jsonify({'message': 'Login successful', 'token': token}), 200


# 3. POST /upload_file - Upload a file
@app.route('/upload_file', methods=['POST'])
@token_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({'message': 'No file provided'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'message': 'No file selected'}), 400

    file_id = str(uuid.uuid4())
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id + '_' + file.filename)
    file.save(file_path)

    files[file_id] = {
        'file_id': file_id,
        'filename': file.filename,
        'user_id': request.user_id,
        'upload_time': datetime.utcnow().isoformat()
    }
    return jsonify({'message': 'File uploaded successfully', 'file_id': file_id}), 201


# 4. GET /users - List all users (admin access simulation)
@app.route('/users', methods=['GET'])
@token_required
def get_users():
    return jsonify({'users': [{k: v['user_id']} for k, v in users.items()]}), 200


# 5. GET /user/<user_id> - Get user details
@app.route('/user/<user_id>', methods=['GET'])
@token_required
def get_user(user_id):
    if user_id != request.user_id:
        return jsonify({'message': 'Unauthorized access'}), 403

    for username, user in users.items():
        if user['user_id'] == user_id:
            return jsonify({'user_id': user_id, 'username': username}), 200
    return jsonify({'message': 'User not found'}), 404


# 6. PUT /user/<user_id> - Update user password
@app.route('/user/<user_id>', methods=['PUT'])
@token_required
def update_user(user_id):
    if user_id != request.user_id:
        return jsonify({'message': 'Unauthorized access'}), 403

    data = request.get_json()
    new_password = data.get('password')

    if not new_password:
        return jsonify({'message': 'New password is required'}), 400

    for username, user in users.items():
        if user['user_id'] == user_id:
            users[username]['password'] = generate_password_hash(new_password)
            return jsonify({'message': 'Password updated successfully'}), 200
    return jsonify({'message': 'User not found'}), 404


# 7. DELETE /user/<user_id> - Delete a user
@app.route('/user/<user_id>', methods=['DELETE'])
@token_required
def delete_user(user_id):
    if user_id != request.user_id:
        return jsonify({'message': 'Unauthorized access'}), 403

    for username, user in users.items():
        if user['user_id'] == user_id:
            del users[username]
            return jsonify({'message': 'User deleted successfully'}), 200
    return jsonify({'message': 'User not found'}), 404


# 8. GET /files - List all files uploaded by the user
@app.route('/files', methods=['GET'])
@token_required
def get_files():
    user_files = [file for file in files.values() if file['user_id'] == request.user_id]
    return jsonify({'files': user_files}), 200


# 9. GET /file/<file_id> - Get file details
@app.route('/file/<file_id>', methods=['GET'])
@token_required
def get_file(file_id):
    file = files.get(file_id)
    if not file:
        return jsonify({'message': 'File not found'}), 404
    if file['user_id'] != request.user_id:
        return jsonify({'message': 'Unauthorized access'}), 403
    return jsonify(file), 200


# 10. DELETE /file/<file_id> - Delete a file
@app.route('/file/<file_id>', methods=['DELETE'])
@token_required
def delete_file(file_id):
    file = files.get(file_id)
    if not file:
        return jsonify({'message': 'File not found'}), 404
    if file['user_id'] != request.user_id:
        return jsonify({'message': 'Unauthorized access'}), 403

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_id + '_' + file['filename'])
    if os.path.exists(file_path):
        os.remove(file_path)
    del files[file_id]
    return jsonify({'message': 'File deleted successfully'}), 200


if __name__ == '__main__':
    app.run(debug=True)