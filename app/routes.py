from flask import Blueprint, request, jsonify
from . import db
from .models import User, Note, Entity
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import os
import requests
import spacy

# Load the spaCy model
nlp = spacy.load("en_core_web_sm")

main = Blueprint('main', __name__)

# User Registration
@main.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "User already exists"}), 400

    hashed_password = generate_password_hash(password)
    user = User(username=username, password=hashed_password)
    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# User Login
@main.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.password, password):
        return jsonify({"error": "Invalid credentials"}), 401

    access_token = create_access_token(identity=str(user.id))  # Pass the user ID as a string
    return jsonify({"access_token": access_token}), 200

# @main.route('/note', methods=['POST'])
# def test_note():
#     print("Note endpoint hit!")
#     return jsonify({"message": "This is a test"}), 200

@main.route('/note', methods=['POST'])
@jwt_required()
def add_note():
    try:
        print("Authorization Header:", request.headers.get('Authorization'))
        
        # Decode the token and get the current user
        user_id = get_jwt_identity()
        print("Decoded user_id:", user_id)
        
        if not user_id:
            return jsonify({"error": "User ID not found in token"}), 401

        # Parse the request body
        data = request.json
        content = data.get('content')
        deadline = data.get('deadline')
        
        if not content:
            return jsonify({"error": "Content is required"}), 400

        # Use spaCy to parse the content and extract entities
        doc = nlp(content)
        entities = [(ent.text, ent.label_) for ent in doc.ents]
        print("Extracted entities:", entities)

        # Add note to database
        note = Note(user_id=user_id, content=content, deadline=deadline)
        db.session.add(note)
        db.session.commit()

        # Add entities to database
        for text, label in entities:
            entity = Entity(note_id=note.id, text=text, label=label)
            db.session.add(entity)
        
        db.session.commit()

        return jsonify({"message": "Note added successfully", "entities": entities}), 201

    except Exception as e:
        print("Error:", e)
        return jsonify({"error": str(e)}), 500

# Add Note
# @main.route('/note', methods=['POST'])
# @jwt_required()
# def add_note():
#     try:
#         # Check the token
#         print("Authorization Header:", request.headers.get('Authorization'))

#         # Get the user from the JWT token
#         user_id = get_jwt_identity()
#         print("Decoded user_id:", user_id)
        
#         print("Note endpoint hit!")
#         data = request.json
#         print("Parsed JSON:", data)
        
#         # Debugging: Print headers and raw data
#         print("Headers:", request.headers)
#         print("Raw Data:", request.data)  # Raw request body
#         print("JSON Parsed:", request.json)

#         data = request.json
#         if not data:
#             return jsonify({"error": "Request body must be JSON"}), 400

#         # Validate 'content'
#         content = data.get('content')
#         if not isinstance(content, str) or not content.strip():
#             return jsonify({"error": "Content must be a non-empty string"}), 400

#         # Validate 'deadline' (optional)
#         deadline = data.get('deadline')
#         if deadline and not isinstance(deadline, str):
#             return jsonify({"error": "Deadline must be a string"}), 400

#         # Save the note
#         user_id = get_jwt_identity()
#         print("Decoded user_id:", user_id)
#         note = Note(user_id=user_id, content=content, deadline=deadline)
#         db.session.add(note)
#         db.session.commit()

#         return jsonify({"message": "Note added successfully"}), 201

#     except Exception as e:
#         print("Error:", e)
#         return jsonify({"error": str(e)}), 500

# Retrieve Notes
@main.route('/notes', methods=['GET'])
@jwt_required()
def get_notes():
    user_id = get_jwt_identity()
    notes = Note.query.filter_by(user_id=user_id).all()
    return jsonify([{"id": note.id, "content": note.content, "deadline": note.deadline} for note in notes]), 200

# Query Azure OpenAI
@main.route('/query', methods=['POST'])
@jwt_required()
def query_openai():
    user_id = get_jwt_identity()
    data = request.json
    prompt = data.get('prompt')

    response = requests.post(
        os.getenv("AZURE_OPENAI_ENDPOINT"),
        headers={
            "Authorization": f"Bearer {os.getenv('AZURE_OPENAI_API_KEY')}",
            "Content-Type": "application/json"
        },
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7
        }
    )

    if response.status_code != 200:
        return jsonify({"error": "Failed to query OpenAI"}), 500

    result = response.json()
    return jsonify({"response": result.get('choices', [{}])[0].get('message', {}).get('content', "")}), 200

# @main.route('/test', methods=['GET'])
# def test_endpoint():
#     print("Test endpoint was hit!")
#     return jsonify({"message": "Test successful"}), 200

# @main.route('/decode', methods=['GET'])
# @jwt_required()
# def decode_token():
#     try:
#         user_id = get_jwt_identity()
#         return jsonify({"user_id": user_id}), 200
#     except Exception as e:
#         print(f"Token decode error: {e}")
#         return jsonify({"error": str(e)}), 500
    
# from flask_jwt_extended import decode_token

# @main.route('/decode-token', methods=['GET'])
# def decode_token_manually():
#     print("Decoding token")
#     auth_header = request.headers.get('Authorization', None)
#     if not auth_header or not auth_header.startswith("Bearer "):
#         return jsonify({"error": "Authorization header missing or improperly formatted"}), 401
    
#     token = auth_header.split(" ")[1]
    
#     try:
#         print("Trying to decode token")
#         decoded = decode_token(token, allow_expired=True)
#         return jsonify({"decoded_token": decoded}), 200
#     except Exception as e:
#         return jsonify({"error": str(e)}), 422


