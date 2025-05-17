import os
import jwt
from flask import Flask, request, jsonify
from requests import post, get
from time import time


JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable is not set")

IO_API_HOST = os.getenv("IO_API_HOST")
if not IO_API_HOST:
    raise ValueError("IO_API_HOST environment variable is not set")

IO_API_PORT = os.getenv("IO_API_PORT")
if not IO_API_PORT:
    raise ValueError("IO_API_PORT environment variable is not set")

IO_API_URL = f"http://{IO_API_HOST}:{IO_API_PORT}"

HOUR_IN_SECONDS = 60 * 60

app = Flask(__name__)


def token_expired(claims: dict) -> bool:
    """
    Check if the token is expired.
    """
    expiration_time = claims.get("exp")
    if not expiration_time:
        app.logger.error("Expiration time not found in token")
        return True

    current_time = time()
    return expiration_time - current_time < 0


def validate_token(token: str) -> dict:
    """
    Validate the JWT token and return the claims.
    """
    claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], verify=True)
    if not claims:
        app.logger.info("Token signature validation failed")
        return None

    return claims


def build_token(claims: dict) -> str:
    """
    Build a JWT token from the claims.
    """
    auth_token = jwt.encode(
        payload=claims,
        key=JWT_SECRET,
        algorithm="HS256",
        headers={"alg": "HS256", "typ": "JWT"},
    )
    return auth_token


@app.route("/health", methods=["GET"])
def health_check():
    """
    Health check endpoint to verify if the service is running.
    """
    return jsonify(""), 200


@app.route("/signup", methods=["POST"])
def signup():
    """
    Endpoint to handle user signup.
    """

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid input"}), 400

    email = data.get("email")
    passwd = data.get("passwd")
    if not email or not passwd:
        app.logger.info("Email or password not provided")
        return jsonify({"error": "email and password are required"}), 400
    is_publisher = data.get("is_publisher", False)

    io_resp = post(
        f"{IO_API_URL}/users",
        json={"email": email, "passwd": passwd, "is_publisher": is_publisher},
    )
    if io_resp.status_code != 201:
        app.logger.error(f"Failed to create user: {io_resp.text}")
        return io_resp.json(), io_resp.status_code

    uid = io_resp.json().get("uid")
    is_publisher = io_resp.json().get("is_publisher")
    is_admin = io_resp.json().get("is_admin")

    resp = jsonify({"message": "User created successfully"})
    resp.status_code = 201

    auth_token = build_token(
        claims={
            "uid": uid,
            "is_publisher": is_publisher,
            "is_admin": is_admin,
            "exp": time() + 2 * HOUR_IN_SECONDS,
        }
    )
    if not auth_token:
        app.logger.error("Failed to create auth token")
        return jsonify({"error": "internal server error"}), 500

    resp.set_cookie(
        key="auth_token",
        value=auth_token,
        httponly=True,
        secure=True,
        max_age=2 * HOUR_IN_SECONDS,
    )

    return resp


@app.route("/login", methods=["POST"])
def login():
    """
    Endpoint to handle user login.
    """

    data = request.get_json()
    if not data:
        return jsonify({"error": "invalid input"}), 400

    email = data.get("email")
    passwd = data.get("passwd")
    if not email or not passwd:
        app.logger.info("Email or password not provided")
        return jsonify({"error": "email and password are required"}), 400

    io_resp = post(
        f"{IO_API_URL}/users/validate",
        json={"email": email, "passwd": passwd},
    )
    if io_resp.status_code == 401:
        app.logger.info("Invalid credentials")
        return jsonify({"error": "invalid credentials"}), 401
    elif io_resp.status_code != 200:
        app.logger.info(f"Failed to validate user: {io_resp.text}")
        return jsonify({"error": "internal server error"}), 500

    uid = io_resp.json().get("uid")
    is_publisher = io_resp.json().get("is_publisher")
    is_admin = io_resp.json().get("is_admin")
    auth_token = build_token(
        claims={
            "uid": uid,
            "is_publisher": is_publisher,
            "is_admin": is_admin,
            "exp": time() + 2 * HOUR_IN_SECONDS,
        }
    )
    if not auth_token:
        app.logger.error("Failed to create auth token")
        return jsonify({"error": "internal server error"}), 500

    resp = jsonify({"message": "User logged in successfully"})
    resp.status_code = 200
    resp.set_cookie(
        key="auth_token",
        value=auth_token,
        httponly=True,
        secure=True,
        max_age=2 * HOUR_IN_SECONDS,
    )

    return resp, 200


@app.route("/logout", methods=["GET"])
def logout():
    """
    Endpoint to handle user logout.
    """

    auth_token = request.cookies.get("auth_token")
    if not auth_token:
        app.logger.info("Auth token not present in cookies, no session to logout from")
        return jsonify({"error": "no session to logout from"}), 400

    claims = validate_token(auth_token)
    if not claims:
        app.logger.info("Token validation failed")
        resp = jsonify({"error": "invalid token, removed from session"})
        resp.delete_cookie("auth_token")
        return resp, 401

    # superfluous check, but for safety
    if token_expired(claims):
        app.logger.info("Token expired")
        resp = jsonify({"error": "token expired, removed from session"})
        resp.delete_cookie("auth_token")
        return resp, 401

    resp = jsonify({"message": "User logged out successfully"})
    resp.delete_cookie("auth_token")

    return resp, 200


@app.route("/validate", methods=["POST"])
def validate():
    """
    Endpoint to validate user credentials.
    """

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid input"}), 400

    auth_token = data.get("auth_token")
    if not auth_token:
        app.logger.info("Auth token not provided")
        return jsonify({"error": "auth_token is required"}), 400

    claims = validate_token(auth_token)
    if not claims:
        app.logger.info("Token validation failed")
        return jsonify({"error": "invalid token"}), 401

    # superfluous check, but for safety
    if token_expired(claims):
        app.logger.info("Token expired")
        return jsonify({"error": "token expired"}), 401

    return jsonify(claims), 200
