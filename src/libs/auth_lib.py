
import validators
from flask import jsonify
from flask_jwt_extended import create_access_token, create_refresh_token
from flask_jwt_extended.utils import get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
from src.models.databases import User


def generate_tokens(email, password):
    user = User.query.filter_by(email=email).first()
    if user:
        pass_check = check_password_hash(user.password, password)
        if pass_check:
            refresh = create_refresh_token(identity=user.id)
            access = create_access_token(identity=user.id)

            return jsonify(
                {
                    "refresh": refresh,
                    "access": access
                }
            ), 200
        return jsonify({"error": "password incorrect"}), 400
    return jsonify({"error": "user with this email does not exists"}), 400


def get_current_user():
    current_user = User.query.filter_by(id=get_jwt_identity()).first()
    return jsonify({
        "id": current_user.id,
        "fullname": current_user.full_name,
        "email": current_user.email,
        "username": current_user.username,
    }), 200


def check_duplicate_user(email, username):
    if not validators.email(email):
        return jsonify({"error": "email is not valid"}), 400
    if User.query.filter_by(email=email).first() is not None:
        return jsonify({"error": "email already exists"}), 400

    if User.query.filter_by(username=username).first() is not None:
        return jsonify({"error": "username already exists"}), 400


def create_db_object(table, **kwargs):
    pass


def refresh_token():
    identity = get_jwt_identity()
    access = create_access_token(identity=identity)
    return jsonify(
        {
            "access": access
        }
    ), 200


def hash_pwd(password):
    return generate_password_hash(password)


def get_all_data(model):
    data = []
    result = model.query.all()
    for item in result:
        data.append({
            "id": item.id,
            "fullname": item.full_name,
            "email": item.email,
            "username": item.username,
        })
    return data
