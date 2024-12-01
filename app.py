from app import create_app

app = create_app()

from flask_jwt_extended import JWTManager
from flask_jwt_extended.exceptions import JWTExtendedException
from werkzeug.exceptions import HTTPException
from flask import jsonify

jwt = JWTManager(app)

@jwt.revoked_token_loader
def handle_revoked_token(jwt_header, jwt_payload):
    return jsonify({"error": "Token has been revoked"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(reason):
    print(f"Invalid token: {reason}")  # Print detailed reason
    return jsonify({"error": "Invalid token", "message": reason}), 422

@jwt.unauthorized_loader
def unauthorized_loader_callback(reason):
    print(f"Unauthorized request: {reason}")  # Print reason for rejection
    return jsonify({"error": "Unauthorized request", "message": reason}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    print(f"Expired token: {jwt_payload}")  # Log expired token details
    return jsonify({"error": "Token has expired"}), 401

@jwt.token_verification_failed_loader
def token_verification_failed_callback():
    print("Token verification failed")
    return jsonify({"error": "Token verification failed"}), 422

if __name__ == '__main__':
    app.run(debug=True)
