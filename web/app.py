from flask import *
from flask_restful import Api, Resource
import os
import bcrypt
import numpy as np
import requests
from pymongo import MongoClient

from keras.applications import InceptionV3
from keras.applications.inception_v3 import preprocess_input
from keras.applications import imagenet_utils
from tensorflow.keras.preprocessing.image import img_to_array
from PIL import Image
from io import BytesIO

# Load the pretrained model
pretrained_model = InceptionV3(weights="imagenet")

app = Flask(__name__)
api = Api(app)
Client = MongoClient('mongodb://db:27017')
db = Client.aNewDB
users = db["users"]


def UserExists(username):
    if users.count_documents({"username": username}) == 0:
        return False
    else:
        return True


def ret301():
    retjson = {
        "Status": 301,
        "message": "User Already exists"
    }
    return jsonify(retjson)


def ret302():
    retjson = {
        "Status": 302,
        "message": "Incorrect password, please check it and re-enter the password"
    }
    return jsonify(retjson)


def ret303():
    retjson = {
        "Status": 303,
        "message": "Not enough tokens"
    }
    return jsonify(retjson)


def verify_pw(username, password):
    pass_wd = users.find({"username": username})[0]["password"]
    return bcrypt.checkpw(password.encode('utf8'), pass_wd)


class Registration(Resource):
    def post(self):
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        hashpw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())
        if UserExists(username):
            retjson = ret301()
            return (retjson)
        users.insert_one({
            "username": username,
            "password": hashpw,
            "tokens": 6
        })
        retjson = {
            "Status": 200,
            "Message": "You have Signed up Successfully"
        }
        return jsonify(retjson)


class Classify(Resource):
    def post(self):
        # get postedData and url
        postedData = request.get_json()
        username = postedData["username"]
        password = postedData["password"]
        url = postedData["url"]

        # verify the credentials and the user
        if not UserExists(username):
            return (ret301())
        correct_pw = verify_pw(username, password)
        if not correct_pw:
            retjson = ret302()
            return (retjson)

        # verify the user does have enough tokens
        tokens = users.find({"username": username})[0]["tokens"]
        if tokens <= 0:
            retjson = ret303()
            return (retjson)

        # check for the urls
        if not url:
            retjson={
            "Status":400,
            "Message":"No url provided"
            }
            return jsonify(retjson)

        # load the image from the url
        response = requests.get(url)
        img = Image.open(BytesIO(response.content))

        # preprocess the image
        img = img.resize((299, 299))
        img_array = img_to_array(img)
        img_array = np.expand_dims(img_array, axis=0)
        img_array = preprocess_input(img_array)

        # make prediction
        prediction = pretrained_model.predict(img_array)
        actual_prediction = imagenet_utils.decode_predictions(prediction, top=5)

        # return classification response
        ret_json = {}
        for pred in actual_prediction[0]:
            ret_json[pred[1]] = float(pred[2] * 100)

        users.update_one({"username": username}, {"$set": {"tokens": tokens - 1}})
        return jsonify(ret_json)
class Refill(Resource):
    def post(self):
        postedData=request.get_json()
        username=postedData["username"]
        admin_pw=postedData["password"]
        tokens=postedData["addtokens"]
        admin="1234"
        if not UserExists(username):
            retjson=ret301()
            return retjson
        if admin!=admin_pw:
            retjson=ret302()
            return (retjson)

        users.update_one({"username":username},{"$set":{"tokens":tokens}})
        retjson={
        "status":200,
        "Message":"Tokens Have Been updated Successfully"
        }
        return jsonify(retjson)

api.add_resource(Registration, '/register')
api.add_resource(Classify, '/classify')
api.add_resource(Refill,'/refill')

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=False)
