from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import text
import re
import os

app = Flask(__name__)
bcrypt = Bcrypt(app)

# Secret Key
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# Database Configuration using pymysql
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@127.0.0.1:3306/aidb'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User Model (for SQLAlchemy)
class User(db.Model):
    __tablename__ = "user"
    userid = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(255))
    role = db.Column(db.String(50))
    country = db.Column(db.String(100))

# Check if the user is logged in
def is_logged_in():
    return 'loggedin' in session

# Fetch user by email
def get_user_by_email(email):
    query = text("SELECT * FROM `user` WHERE email = :email")
    result = db.session.execute(query, {"email": email}).fetchone()
    return result

# Fetch user by ID
def get_user_by_id(user_id):
    query = text("SELECT * FROM `user` WHERE userid = :userid")
    result = db.session.execute(query, {"userid": user_id}).fetchone()
    return result

# Home Page
@app.route('/')
def index():
    if is_logged_in():
        user_details = {
            'name': session.get('name', 'Guest'),
            'role': session.get('role', 'User'),
            'email': session.get('email', ''),
            'userid': session.get('userid'),
        }
        return render_template('index.html', user=user_details)
    return redirect(url_for('login'))

# Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = get_user_by_email(email)

        if user and bcrypt.check_password_hash(user.password, password):
            session['loggedin'] = True
            session['userid'] = user.userid
            session['name'] = user.name
            session['role'] = user.role
            session['email'] = user.email
            flash('Login successful', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password!')
    return render_template('login.html')

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('login'))

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        country = request.form['country']

        if get_user_by_email(email):
            flash('User already exists!')
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            flash('Invalid email address!')
        elif not name or not password or not email:
            flash('Please fill out all fields!')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            query = text("INSERT INTO `user` (`name`, `email`, `password`, `role`, `country`) VALUES (:name, :email, :password, :role, :country)")
            db.session.execute(query, {
                "name": name,
                "email": email,
                "password": hashed_password,
                "role": role,
                "country": country
            })
            db.session.commit()
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))

    return render_template('register.html')

# View all users
@app.route('/users')
def users():
    if is_logged_in():
        query = text("SELECT * FROM `user`")
        users = db.session.execute(query).fetchall()
        return render_template('users.html', users=users)
    flash('You must log in to access this page.')
    return redirect(url_for('login'))

# Edit user
@app.route('/edit/<int:userid>', methods=['GET', 'POST'])
def edit(userid):
    if is_logged_in() and session['userid'] == userid:
        user = get_user_by_id(userid)
        if request.method == 'POST':
            name = request.form['name']
            role = request.form['role']
            country = request.form['country']

            if not re.match(r'[A-Za-z0-9 ]+', name):
                flash('Name must contain only letters, numbers, and spaces!')
            else:
                query = text("UPDATE `user` SET `name`=:name, `role`=:role, `country`=:country WHERE userid=:userid")
                db.session.execute(query, {"name": name, "role": role, "country": country, "userid": userid})
                db.session.commit()
                flash('User details updated successfully!')
                return redirect(url_for('index'))
        return render_template('edit.html', editUser=user)
    flash('Unauthorized access.')
    return redirect(url_for('index'))

# Change password
@app.route('/password_change/<int:userid>', methods=['GET', 'POST'])
def password_change(userid):
    if is_logged_in() and session['userid'] == userid:
        if request.method == 'POST':
            password = request.form['password']
            confirm_password = request.form['confirm_pass']

            if password != confirm_password:
                flash('Passwords do not match!')
            else:
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                query = text("UPDATE `user` SET `password`=:password WHERE userid=:userid")
                db.session.execute(query, {"password": hashed_password, "userid": userid})
                db.session.commit()
                flash('Password updated successfully!')
                return redirect(url_for('index'))
        return render_template('password_change.html', changePassUserId=userid)
    flash('Unauthorized access.')
    return redirect(url_for('login'))

# View user details
@app.route('/view/<int:userid>', methods=['GET'])
def view(userid):
    if is_logged_in():
        user = get_user_by_id(userid)
        if user:
            return render_template('view.html', user=user)
        flash('User not found.')
        return redirect(url_for('index'))
    flash('You must log in to view user details.')
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)
