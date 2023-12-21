from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://username:password@db/mission'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    mission = db.Column(db.String(200))

# Routes
@app.route('/')
def main():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Extract data depending on content type
        if request.content_type == 'application/json':
            data = request.json
        else:  # Assume form data
            data = request.form

        username = data.get('username')
        password = data.get('password')

        # Basic validation
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        # Check if user exists
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # Login successful
            return jsonify({'message': 'Login successful', 'user_id': user.id}), 200
        else:
            # Invalid credentials
            return jsonify({'error': 'Invalid username or password'}), 401
    else:
        # GET request, show the login form
        return render_template('login.html')

# Implement registration logic using flask @app.route and sqlalchemy
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Extract data depending on content type
        if request.content_type == 'application/json':
            data = request.json
        else:  # Assume form data
            data = request.form

        username = data.get('username')
        password = data.get('password')

        # Basic validation
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        # Hash the password for security
        hashed_password = generate_password_hash(password)

        new_user = User(username=username, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': 'User registered successfully'}), 201
        except IntegrityError:
            return jsonify({'error': 'Username already exists'}), 409
    else:
        # GET request, show the registration form
        return render_template('register.html')



@app.route('/mission')
def mission():
    # Assuming user_id is passed as query parameter
    user_id = request.args.get('user_id')
    user = User.query.filter_by(id=user_id).first()
    if user:
        return jsonify({'mission': user.mission})
    else:
        return jsonify({'error': 'User not found'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
