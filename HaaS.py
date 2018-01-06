from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sealdarethebest'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///config/haas.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)
    hashes = db.relationship('Hash', backref='user', lazy=True)

class Hash(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hash = db.Column(db.String(255), unique=True)
    created_at = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


@app.route('/')
def hello_world():
    return 'Hello World!'

@app.route('/user', methods=['POST'])
def create_user():

    data = request.get_json()

    hashed_password = generate_password_hash(data["password"], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), name=data['name'], email=data['email'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'New user created'})


if __name__ == '__main__':
    app.run(debug=True)
