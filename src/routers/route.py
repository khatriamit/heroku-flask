
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required

from src.models.databases import User, db
from src.libs import auth_lib


auth = Blueprint("auth", __name__, url_prefix="/api/v1/auth")


@auth.route("/user/", methods=["POST", "GET"])
def user():
    if request.method == "POST":
        full_name = request.json.get("fullname")
        username = request.json.get("username")
        email = request.json.get("email")
        password = request.json.get("password")
        confirm_password = request.json.get("confirm_password")
        if password != confirm_password:
            return jsonify({"error": "password did not match"}), 400

        res = auth_lib.check_duplicate_user(email, username)
        if res:
            return res

        user = User(
            full_name=full_name,
            username=username,
            email=email,
            password=auth_lib.hash_pwd(password)
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
        })
    else:
        return jsonify(auth_lib.get_all_data(User))


@auth.post("/login/")
def login():
    email = request.json.get("email", '')
    password = request.json.get("password", '')
    return auth_lib.generate_tokens(email, password)


@auth.get("/current_user/")
@jwt_required()
def current_user():
    return auth_lib.get_current_user()


@auth.post("/token/refresh/")
@jwt_required(refresh=True)
def refresh():
    return auth_lib.refresh_token()
