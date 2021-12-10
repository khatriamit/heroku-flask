import validators
from flask import request, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from src.models.databases import User, db


def create_user():
    full_name = request.json["fullname"]
    username = request.json["username"]
    email = request.json["email"]
    password = request.json["password"]
    confirm_password = request.json["confirm_password"]
    if password != confirm_password:
        return jsonify({"error": "password did not match"}), 400

    if not validators.email(email):
        return jsonify({"error": "email is not valid"}), 400

    if User.query.filter_by(email=email).first() is not None:
        return jsonify({"error": "email already exists"}), 400

    if User.query.filter_by(username=username).first() is not None:
        return jsonify({"error": "username already exists"}), 400
    hash_pwd = generate_password_hash(password)
    user = User(
        full_name=full_name,
        username=username,
        email=email,
        password=hash_pwd
    )

    db.session.add(user)
    db.session.commit()
    return jsonify({
        "message": "user created",
        "user": {
            "fullname": full_name,
            "email": email,
            "username": username,
        }
    }), 201
