import os, csv
import datetime
from flask import Flask, request, redirect, render_template, url_for, flash, session
from flask_cors import CORS
from sqlalchemy.exc import IntegrityError
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    set_access_cookies,
    unset_jwt_cookies,
    get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash

# Configure Flask App
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.root_path, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'MySecretKey'
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token'
app.config['JWT_REFRESH_COOKIE_NAME'] = 'refresh_token'
app.config["JWT_TOKEN_LOCATION"] = ["cookies", "headers"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(hours=15)
app.config["JWT_COOKIE_SECURE"] = True
app.config["JWT_SECRET_KEY"] = "super-secret"
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
app.config['JWT_HEADER_NAME'] = "Cookie"

# Initialize App 
db = SQLAlchemy(app)
app.app_context().push()
CORS(app)
jwt = JWTManager(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# User's Pokemon Model
class UserPokemon(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    pokemon_id = db.Column(db.Integer, nullable=False)
    name = db.Column(db.String(80), nullable=False)

# JWT Config to enable current_user
@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.get(identity)

@app.route('/init')
def init_route():
    db.drop_all()
    db.create_all()
    flash('Database Initialized!', 'info')
    return redirect(url_for('login_page'))

@app.route('/', methods=['GET'])
def login_page():
    return render_template("login.html")

@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template("signup.html")

@app.route('/signup', methods=['POST'])
def signup_action():
    try:
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        response = redirect(url_for('home_page'))
        token = create_access_token(identity=user)
        set_access_cookies(response, token)
        flash('Account created successfully!', 'success')
    except IntegrityError:
        flash('Username already exists', 'danger')
        response = redirect(url_for('signup_page'))
    return response

@app.route('/logout', methods=['GET'])
@jwt_required()
def logout_action():
    response = redirect(url_for('login_page'))
    unset_jwt_cookies(response)
    flash('Logged out', 'info')
    return response

@app.route('/app', methods=['GET'])
@app.route('/app/<int:pokemon_id>', methods=['GET'])
@jwt_required()
def home_page(pokemon_id=1):
    user_id = get_jwt_identity()
    user_pokemon = UserPokemon.query.filter_by(user_id=user_id).all()
    pokemon_list = [(i, f'https://raw.githubusercontent.com/PokeAPI/sprites/master/sprites/pokemon/{i}.png') for i in range(1, 802)]
    selected_pokemon = {'id': pokemon_id, 'image': f'https://raw.githubusercontent.com/PokeAPI/sprites/master/sprites/pokemon/{pokemon_id}.png'}
    return render_template("home.html", user_pokemon=user_pokemon, pokemon_list=pokemon_list, selected_pokemon=selected_pokemon)

@app.route('/login', methods=['POST'])
def login_action():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        session['jwt'] = access_token
        return redirect(url_for('home_page'))
    else:
        flash('Invalid credentials, try again.', 'danger')
        return redirect(url_for('login_page'))

@app.route('/pokemon/<int:pokemon_id>', methods=['POST'])
@jwt_required()
def capture_pokemon(pokemon_id):
    user_id = get_jwt_identity()
    new_pokemon = UserPokemon(user_id=user_id, pokemon_id=pokemon_id, name=f'Pokemon {pokemon_id}')
    db.session.add(new_pokemon)
    db.session.commit()
    flash('Pokemon captured!', 'success')
    return redirect(url_for('home_page'))

@app.route('/rename-pokemon/<int:user_poke_id>', methods=['POST'])
@jwt_required()
def rename_pokemon(user_poke_id):
    new_name = request.form['new_name']
    pokemon = UserPokemon.query.get(user_poke_id)
    if pokemon:
        pokemon.name = new_name
        db.session.commit()
        flash('Pokemon renamed successfully.', 'success')
    return redirect(url_for('home_page'))

@app.route('/release-pokemon/<int:user_poke_id>')
@jwt_required()
def release_pokemon(user_poke_id):
    pokemon = UserPokemon.query.get(user_poke_id)
    if pokemon:
        db.session.delete(pokemon)
        db.session.commit()
        flash('Pokemon released.', 'info')
    return redirect(url_for('home_page'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=8080)












