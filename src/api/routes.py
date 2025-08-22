"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200


@api.route('/register', methods=['POST'])
def createUser():
    data_body = request.get_json()

    if not data_body["email"] or not data_body["password"]:
        return jsonify({"error": "email y password son obligatorio"}), 400

    user = User.query.filter_by(email=data_body["email"]).first()

    if user:
        return jsonify({"error": "Este email ya existe"}), 400

    # encriptar contraseñas antes de añadir a la BD
    hashed_pass = generate_password_hash(data_body["password"])

    new_user = User(email=data_body["email"], password=hashed_pass)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"success": "Creado con exito"}), 201


@api.route('/login', methods=['POST'])
def login():
    data_body = request.get_json()

    if not data_body["email"] or not data_body["password"]:
        return jsonify({"error": "email y password son obligatorio"}), 400

    user = User.query.filter_by(email=data_body["email"]).first()

    is_valid_pass = check_password_hash(user.password, data_body["password"])

    if not user or not is_valid_pass:
        return jsonify({"error": "email o password son incorrecto"}), 400

    token = create_access_token(identity=user.email)
    return jsonify({"token": token}), 200

# ruta privada, debes iniciar sesion antes, y recibe un token


@api.route('/updateProfile', methods=['PUT'])
@jwt_required()
def modify_profile():
    user_email = get_jwt_identity()
    user_body = request.get_json()
    # hacer el proceso para editar el usuario

    return jsonify({"user": "Usuario modificado con exito"}), 200


'''
    autenticacion --> 
        iniciar sesion -- POST (USER, PASSword), validar  que el user y password coinciden con la BD, TOKEN JWT
        registrarse -- POST, añadir un nuevo registro (add), validar  si ya existe(filter_By,) 
    autorizacion --> 
        cuando tenemos endpoints privados, 
        validar  que has iniciado sesion para acceder a ciertos recursos , acciones
'''
