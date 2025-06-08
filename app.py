import pyodbc
from flask import Flask, request, jsonify
# from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

server = 'irc-gt.database.windows.net'
database = 'irc-gt'
username = 'adminircgt'
password = 'AstonMartinLMH25'
driver = '{ODBC Driver 17 for SQL Server}'

# Establish the Connection

try:
    connection = pyodbc.connect(
        f'DRIVER={driver};SERVER={server};DATABASE={database};UID={username};PWD={password}'
    )
    print("Connection Successful")
except pyodbc.Error as e:
    print("Error connecting to the database:", e)

query = "SELECT * FROM ircgt"

# Fetch the Data

try:
    cursor = connection.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()

    # Print results
    for row in rows:
        print(row)

    # Close the cursor and connection

    cursor.close()
    connection.close()
    print("Connection closed.")

except pyodbc.Error as e:
    print("Error fetching data:", e)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)


# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)


# Create database tables
with app.app_context():
    db.create_all()


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists'}), 400

    hashed_password = generate_password_hash(password)
    new_user = User(username=username, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Invalid username or password'}), 401

    return jsonify({'message': 'Login successful'}), 200


if __name__ == '__main__':
    app.run(debug=True)
