from flask import Flask, request, jsonify, session, abort, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_bcrypt import Bcrypt
# from flask_jwt_extended import create_access_token,get_jwt,get_jwt_identity, \
# unset_jwt_cookies, jwt_required, JWTManager
# from dotenv import load_dotenv

import os

# load_dotenv()

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = True
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(basedir, "app.sqlite")
db = SQLAlchemy(app)
ma = Marshmallow(app)
bcrypt = Bcrypt(app)
CORS(app)

# app.config["JWT_SECRET_KEY"] = os.getenv("API_KEY")
# jwt = JWTManager(app)


#----------Start ToDo db ----------
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(144), nullable=False)
    # user_fk = db.Column(db.Integer, db.ForeignKey('user.id'))


    def __init__(self, content):
        self.content = content
        # self.user_fk = user_fk

class TodoSchema(ma.Schema):
    class Meta:
        fields = ('id', 'content')

todo_schema = TodoSchema()
multiple_todo_schema = TodoSchema(many=True)


#----------Start Users db----------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    password = db.Column(db.String(30), nullable=False)
    # todo = db.relationship('Todo', backref ="user", cascade= 'all, delete, delete-orphan' )


    def __init__(self, username, password):
        self.username = username
        self.password = password

class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'username', 'password','todo')
    # todo = ma.Nested(multiple_todo_schema)
    


user_schema = UserSchema()
multiple_user_schema = UserSchema(many=True)


#----------start Todo Endpoints ----------
@app.route('/todo/add', methods=['POST'])
def add_todo():
    post_data = request.get_json()
    content = post_data.get('content')
    # user_fk = post_data.get('user_fk')

    new_todo = Todo(content)

    db.session.add(new_todo)
    db.session.commit()

    return jsonify('Todo added successfully')

@app.route('/todo/get', methods=["GET"])
def get_todos():
    todo = db.session.query(Todo).all()
    return jsonify(multiple_todo_schema.dump(todo))

# @app.route('/todo/get/<user_fk>', methods=['GET'])
# def get_todo(user_fk):
#     todo = db.session.query(Todo).filter(Todo.user_fk == User.id).all()
#     return jsonify(multiple_todo_schema.dump(todo))

@app.route('/todo/delete/<id>', methods = ["DELETE"])
def delete_todo(id):
    todo = db.session.query(Todo).filter(Todo.id == id).first()
    db.session.delete(todo)
    db.session.commit()

    return jsonify('Goodbye Todo')


#----------Start login end points----------

@app.route('/user/login', methods=['POST'])
def verify_user():
    if request.content_type != 'application/json':
        return jsonify('Error: Data must be JSON.')

    post_data = request.get_json()
    username = post_data.get('username')
    password = post_data.get('password')

    user = db.session.query(User).filter(User.username == username).first()

    if user is None:
        return jsonify("No user created")

    if bcrypt.check_password_hash(user.password, password) == False:
        return jsonify("Password is incorrect")

    # access_token = create_access_token(identity=username)
    # response = {"access_token":access_token}
    # return response
    return jsonify("Login Successful")

@app.route("/user/logout", methods=["POST"])
def logout():
    response = jsonify({"msg": "logout successful"})

    return response


#----------start User end points----------
@app.route('/user/signup', methods=['POST'])
def add_user():
    post_data = request.get_json()
    username = post_data.get('username')
    password = post_data.get('password')
    
    user = db.session.query(User).filter(User.username == username).first()

    if user is not None:
        return jsonify('Error: You must use another name. That one is taken!')


    encrypted_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username, encrypted_password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify('User Added Successfully')


@app.route('/user/get', methods=['GET'])
def get_all_users():
    users = db.session.query(User).all()
    return jsonify(multiple_user_schema.dump(users))

@app.route("/user/get/<username>", methods=["GET"])
def get_one_user(username):
    user = db.session.query(User).filter(User.username == username).first()
    return jsonify(user_schema.dump(user))

@app.route('/user/update/<id>', methods=["PUT"])
def update_user(id):
    post_data = request.get_json()
    username = post_data.get("username")
    password = post_data.get("password")

    user = db.session.query(User).filter(User.id == id).first()

    user.username = username
    user.password = password

    db.session.commit()
    return jsonify("Your user has ben updated!")

@app.route('/user/delete/<id>', methods = ["DELETE"])
def delete_user(id):
    user = db.session.query(User).filter(User.id == id).first()
    db.session.delete(user)
    db.session.commit()

    return jsonify('We will miss you')


if __name__ == "__main__":
    app.run(debug=True)