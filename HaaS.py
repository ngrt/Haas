from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
from hash import Hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sealdarethebest'

#configurations for ORM SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///config/haas.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

#object db that instantiates SQLAlchemy
db = SQLAlchemy(app)


#2 models User and Hash
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)


#decorator to check if the user is logged-in
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message': 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is invalid'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

#resonds information about a given user
@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['id'] = user.id
    user_data['name'] = user.name
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

#route to create a User
@app.route('/register', methods=['POST'])
def create_user():

    data = request.get_json()

    hashed_password = generate_password_hash(data["password"], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], email=data['email'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created'})

#route to check the credentials given and return a token available 30 min
@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(email=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):

        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

#endpoint to test the API
@app.route('/generateDummyHash')
@token_required
def generateDummyHash(current_user):
    dummy_hash = {'hash': "00000000000000000000000000000000"}

    return jsonify(dummy_hash)

#endpoint receiving a json and returning the hash
@app.route('/calculateHash', methods=['POST'])
@token_required
def calculateHash(current_user):
    data = request.get_json()
    print(data)
    new_hash = Hash(data=data['data'], algo=data['algo'], iteration=data["iteration"])

    return jsonify({'hash': new_hash.hash()})

if __name__ == '__main__':
    app.run(debug=True)