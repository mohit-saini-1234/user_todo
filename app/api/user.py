  
from flask import (
    Blueprint, g, request, abort, jsonify , Flask
)
import base64
from flask import Flask, render_template , session
from random import randint 
import random
from threading import Thread
from flask_mail import Mail, Message
from passlib.hash import pbkdf2_sha256
import jwt
from flask_jwt_extended import ( JWTManager,jwt_optional ,
    jwt_required, create_access_token, get_current_user
)
from app.util import serialize_doc
import re
from bson.objectid import ObjectId
import requests
import datetime
from app import mongo
from app import token
from app.token import manager_required
import dateutil.parser
import json
from bson import json_util
from passlib.apps import custom_app_context as pwd_context
from app.config import app , mail ,sender_mail ,MAIL_SERVER ,MAIL_USERNAME , MAIL_PASSWORD , api_url ,MAIL_SERVER , MAIL_PORT




app.config['MAIL_SERVER']= MAIL_SERVER
app.config['MAIL_PORT'] = MAIL_PORT
app.config['MAIL_USERNAME'] = MAIL_USERNAME
app.config['MAIL_PASSWORD'] = MAIL_PASSWORD
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

bp = Blueprint('user', __name__, url_prefix='/')


@bp.route('/register', methods=['POST'])
@jwt_optional
def register():
   role = request.json.get("role", "user")
   name = request.json.get("name", None)
   username = request.json.get("username", None)
   password = request.json.get("password", None)
   email = request.json.get("email", None)
   if not name or not username or not password:
       return jsonify({"msg": "Invalid Request"}), 400
 
   check_username = mongo.db.users.count({
       "username" : username 
   })
   if check_username > 0 :
       return jsonify({"msg": "already taken"}), 500

    
   id = mongo.db.users.insert_one({
       "role" : role ,
       "name": name,
       "password": pbkdf2_sha256.hash(password),
       "username": username,
       "email" : email
   }).inserted_id
   if id is not None:
        msg = Message('Welcome', sender = sender_mail , recipients = [email] )
        msg.body = "welcome - ThankYou for Using Our Service - registerd successfully " 
        mail.send(msg)
   return jsonify(str(id))




@bp.route('/login', methods=['POST'])
def login():
    is_email = request.json.get("email", None)
    password = request.json.get("password", None)
    if not is_email:
        return jsonify(msg="Missing email parameter"), 400
    if not password:
        return jsonify(msg="Missing password parameter"), 400

    is_email = mongo.db.users.find_one({"email": is_email})
    if is_email is None:
        return jsonify(msg="email doesn't exists"), 400

    if not pbkdf2_sha256.verify(password, is_email["password"]):
        return jsonify(msg="old_password is wrong"), 400
    user1=is_email
    expires = datetime.timedelta(days=1)
    access_token = create_access_token(identity=user1, expires_delta=expires)
    if access_token is not None:
        msg = Message('Security - Login alert', sender = sender_mail , recipients = [email] )
        msg.body = "Warning - New device signed in   " 
        mail.send(msg)
    return jsonify(access_token=access_token), 200



@bp.route('/protected', methods=['GET'])
@jwt_required
def protected():
    current_user = get_current_user()
    current_user["_id"] = str(current_user["_id"])
    user = json.dumps(current_user,default=json_util.default)
    return user, 200


@bp.route('/profile', methods=['PUT', 'GET'])
@jwt_required
def profile():
    current_user = get_current_user()
    current_user["_id"] = str(current_user["_id"])
    user = current_user["_id"]
    return(str({"login as ": user})), 200

@bp.route('/reset_pass/<string:id>', methods=['PUT'])
def pass_Reset(id):
    email =request.json.get("email", None)
    old_password = request.json.get("password", None)
    new_password = request.json.get("new_password1", None)
    confirm_new_password = request.json.get("retype_new_password", None)


    hash = pbkdf2_sha256.hash("password")
    if not old_password:
        return jsonify(msg="Missing password parameter"), 400
    if old_password == new_password :
        return jsonify(msg="should be diffrent from old password")
    if new_password != confirm_new_password :
        return jsonify(msg="password done not match"), 400

    E_mail = mongo.db.users.find_one({"email": email})
    if E_mail is None:
        return jsonify(msg = "email sone not exist")

    if not pbkdf2_sha256.verify(password, E_mail["password"]):
        return jsonify(msg="password is wrong"), 400


    update_json = {}
    if new_password is not None:
         update_json["password"] = hash
    ret = mongo.db.users.update({
       "_id": ObjectId(id)
         }, {
       "$set": update_json
         }, upsert=False)

    if ret is not None:
        msg = Message('Password Change Alert', sender = sender_mail , recipients = [email] )
        msg.body = "Warning - Password Chnage Request Found  " 
        mail.send(msg)  

    return(ret)


@bp.route('/forgot_pass', methods=['GET']) 
def pass_Forgot(): 
    
    email = request.json.get("email", None)
    if not email:
        return jsonify(msg="Missing username parameter"), 400
    
    #encoding_mail
    sample_string_bytes = email.encode("ascii")
    base64_bytes = base64.b64encode(sample_string_bytes)
    base64_string = base64_bytes.decode("ascii")
    

    is_mail= mongo.db.users.find_one({"email":email})
    if is_mail is not None:
        msg = Message('Password Forgot Request', sender = sender_mail , recipients =[email] )
        msg.body = "Request for New Password Is Accepted - Open The Link And Get A New Random Password "
        msg.html = api_url
        mail.send(msg)

    return "check mail for set a new password"

@bp.route('/set_pass', methods=['GET']) 
def set_tempPass():
    email = request.args.get("Email")
    
    #decoding_mail
    base64_bytes = email.encode("ascii")
    sample_string_bytes = base64.b64decode(base64_bytes)
    sample_string = sample_string_bytes.decode("ascii")
    email = sample_string
    if not email:
        return jsonify(msg="Missing email parameter"), 400
    
    E_mail = mongo.db.users.find_one({"email": email})
    password = random.randint(10000, 99999)
    hash = pbkdf2_sha256.hash("password")
    update_json = {}
    if password is not None:
         update_json["password"] = hash
    ret = mongo.db.users.update({
       "email": email
         }, {
       "$set": update_json
         }, upsert=False)
    
    if ret is not None:
        msg = Message('New Password Set', sender = sender_mail , recipients =[email] )
        msg.body = "your new password is -"+str(password)+"-you can change it as you want"
        mail.send(msg)

    return (str(ret))



@bp.route("/update/<string:id>", methods=['PUT'])
@manager_required
def update_todo(id):

    if not request.json:
        abort(500)

    role = request.json.get("role", "user")
    username = request.json.get("username", "")

    if username is None:
        return jsonify(message="Invalid Request"), 500

    update_json = {}
    if role is not None:
        update_json["role"] = role

    if username is not None:
        update_json["username"] = username


    # match with Object ID
    ret = mongo.db.users.update({
        "_id": ObjectId(id)
    }, {
        "$set": update_json
    }, upsert=False)
    return jsonify(str(ret))

@bp.route("/del_todo/<string:id>", methods=["DELETE"])
@manager_required
def delete_todo(id):

    ret = mongo.db.tasks.remove({
        "_id" : ObjectId(id)
    })

    return jsonify(str(ret))  

   
