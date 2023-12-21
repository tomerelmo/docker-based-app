from flask import Flask, request, jsonify, render_template , redirect, url_for , session , flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key122'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://username:password@db/mission'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    mission = db.Column(db.String(200))
    password = db.Column(db.String(200))


with app.app_context():
    db.create_all()

# Routes
@app.route('/')
def main():
    return render_template('index.html')

from flask import Flask, render_template, request, redirect, url_for, jsonify
from werkzeug.security import check_password_hash
# ... other imports and setup ...

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form  # Assuming you're using form data for login

        username = data.get('username')
        password = data.get('password')

        # Basic validation
        if not username or not password:
            return render_template('login.html', error='Username and password are required')

        # Check if user exists and password is correct
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # Login successful, redirect to mission page
            session['user_id'] = user.id
            return redirect(url_for('mission', user_id=user.id))
        else:
            # Invalid credentials, show an error
            return render_template('login.html', error='Invalid username or password')
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

@app.route('/logout')
def logout():
    session.pop('user_id', None)  # Remove user_id from session
    return redirect(url_for('main'))  # Redirect to the main page


@app.route('/add_mission', methods=['POST'])
def add_mission():
    # Check if user is logged in
    user_id = session.get('user_id')
    if not user_id:
        flash("You need to be logged in to add a mission.")
        return redirect(url_for('login'))

    # Get the new mission from form data
    new_mission = request.form.get('new_mission')

    # Basic validation
    if not new_mission:
        flash("Please enter a mission.")
        return redirect(url_for('mission', user_id=user_id))

    # Find the user and update the mission
    user = User.query.filter_by(id=user_id).first()
    if user:
        user.mission = new_mission
        db.session.commit()
        flash("Mission added successfully.")
        return redirect(url_for('mission', user_id=user_id))
    else:
        return render_template('error.html', message='User not found'), 404


@app.route('/delete_mission', methods=['POST'])
def delete_mission():
    user_id = request.args.get('user_id')
    user = User.query.filter_by(id=user_id).first()
    if user:
        user.mission = None
        db.session.commit()
        return redirect(url_for('mission', user_id=user_id))
    else:
        return render_template('error.html', message='User not found'), 404


@app.route('/mission')
def mission():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))  # Redirect to login if not logged in

    user = User.query.filter_by(id=user_id).first()
    if user:
        return render_template('mission.html', mission=user.mission)
    else:
        return render_template('error.html', message='User not found'), 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
