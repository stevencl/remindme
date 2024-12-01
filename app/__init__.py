print("app/__init__.py loaded!")

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_migrate import Migrate
from dotenv import load_dotenv
import os
from flask import request


load_dotenv()

db = SQLAlchemy()
jwt = JWTManager()
migrate = Migrate()

@jwt.user_identity_loader
def user_identity_lookup(user):
    print("Looking up the user")
    # Return the unique identifier of the user (e.g., user ID)
    return str(user.id)  # Ensure it is a string

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.get(identity)

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'  # Use SQLite for simplicity
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['JWT_SECRET_KEY'] = os.getenv("SECRET_KEY")
    app.config['JWT_TOKEN_LOCATION'] = ['headers']  # Default is cookies; we set it to headers
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False   # Disable CSRF protection for cookies
    app.config['JWT_ALGORITHM'] = 'HS256'
    app.config['PROPAGATE_EXCEPTIONS'] = True  # Ensures exceptions are shown
    app.config['DEBUG'] = True  # Enables Flask debugging
    app.config['ENV'] = 'development'  # Sets development mode

    db.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)

    from .routes import main
    app.register_blueprint(main)

    return app

# @app.before_request
# def log_request():
#     print(f"Incoming Request: {request.method} {request.url}")
#     print(f"Headers: {request.headers}")
#     print(f"Body: {request.get_data(as_text=True)}")
