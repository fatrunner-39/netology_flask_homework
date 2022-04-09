import uuid
from sqlalchemy.dialects.postgresql import UUID
import pydantic
from flask import Flask, jsonify, request
from flask_bcrypt import Bcrypt
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from flask.views import MethodView
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from typing import Union


app = Flask('app')
bcrypt = Bcrypt(app)


engine = create_engine('postgresql+psycopg2://postgres:postgres@127.0.0.1:5432/flask_netology')
Base = declarative_base()
Session = sessionmaker(bind=engine)


class HTTPError(Exception):

    def __init__(self, status_code: int, message: Union[str, dict, list]):
        self.status_code = status_code
        self.message = message


@app.errorhandler(HTTPError)
def handle_error(error):
    response = jsonify({
        'message': error.message
    })
    response.status_code = error.status_code
    return response

def validate(input_model, output_model):
    try:
        return output_model(**input_model).dict()
    except pydantic.error_wrappers.ValidationError as er:
        raise HTTPError(400, er.errors())



class RegisterUserModel(pydantic.BaseModel):
    username: str
    password: str

    @pydantic.validator('password')
    def strong_password(cls, value: str):
        if len(value) < 8:
            raise ValueError('password is too short')
        return value


class CreateAdvertModel(pydantic.BaseModel):
    header: str
    description: str


class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True)
    password = Column(String, nullable=False)
    registration_time = Column(DateTime, server_default=func.now())

    @classmethod
    def register_user(cls, session: Session, username: str, password: str):
        password = bcrypt.generate_password_hash(password.encode()).decode()
        new_user = User(username=username, password=password)
        session.add(new_user)
        return new_user

    def check_password(self, password: str):
        return bcrypt.check_password_hash(self.password.encode(), password.encode())

    def to_dict(self):
        return {
            'username': self.username,
            'registration_time': int(self.registration_time.timestamp()),
            'id': self.id,
            # 'password': self.password
        }


class Token(Base):
    __tablename__ = "tokens"

    id = Column(UUID(as_uuid=True), default=uuid.uuid4, primary_key=True)
    creation_time = Column(DateTime, server_default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"))
    user = relationship(User, lazy="joined")


class Advert(Base):
    __tablename__ = 'adverts'

    id = Column(Integer, primary_key=True)
    header = Column(String(100), nullable=False)
    description = Column(String(1000), nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    user_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship(User, lazy="joined")

    @classmethod
    def create_advert(cls, session: Session, header: str, description: str):
        token = check_token(session)
        user_id = token.user.id
        new_advert = Advert(header=header, description=description, user_id=user_id)
        session.add(new_advert)
        return new_advert

    def to_dict(self):
        return {
            'header': self.header,
            'description': self.description,
            'user_id': self.user_id,
            'id': self.id,
        }


Base.metadata.create_all(engine)


class UserView(MethodView):

    def get(self, user_id: int):
        with Session() as session:
            token = check_token(session)
            if token.user.id != user_id:
                raise HTTPError(403, "auth error")
            return jsonify(token.user.to_dict())

    def post(self):
        with Session() as session:
            new_user = User.register_user(session, **validate(request.json, RegisterUserModel))
            session.add(new_user)
            try:
                session.commit()
            except IntegrityError:
                raise HTTPError(400, 'already exists')

            return jsonify(new_user.to_dict())


class AdvertView(MethodView):

    def get(self, adv_id: str):
        with Session() as session:
            my_advert = session.query(Advert).get(adv_id)
            return jsonify(my_advert.to_dict())

    def post(self):
        with Session() as session:
            new_advert = Advert.create_advert(session, **validate(request.json, CreateAdvertModel))
            session.add(new_advert)
            try:
                session.commit()
            except IntegrityError:
                raise HTTPError(400, 'already exists')

            return jsonify(new_advert.to_dict())

    def delete(self, adv_id: int):
        with Session() as session:
            token = check_token(session)
            my_advert = session.query(Advert).get(adv_id)
            if token.user.id != my_advert.user_id:
                raise HTTPError(403, 'auth error')
            session.delete(my_advert)
            session.commit()
            return {'204': 'no content'}


@app.route("/login/", methods=["POST"])
def login():
    login_data = request.json
    with Session() as session:
        user = (
            session.query(User)
            .filter(User.username == login_data["username"])
            .first()
        )
        if user is None or not user.check_password(login_data["password"]):
            raise HTTPError(401, "incorrect user or password")
        token = Token(user_id=user.id)
        session.add(token)
        session.commit()
        return jsonify({"token": token.id})


def check_token(session):
    token = (
        session.query(Token)
        .join(User)
        .filter(
            Token.id == request.headers.get("token"),
        )
        .first()
    )
    if token is None:
        raise HTTPError(401, "invalid token")
    return token


app.add_url_rule("/user/<int:user_id>/", view_func=UserView.as_view("get_user"), methods=["GET"])
app.add_url_rule('/user/', methods=['POST'], view_func=UserView.as_view('user_create'))
app.add_url_rule('/advert/', methods=['POST'], view_func=AdvertView.as_view('advert_create'))
app.add_url_rule('/advert/<int:adv_id>', view_func=AdvertView.as_view('get_advert'), methods=[
    'GET', 'DELETE'])
app.add_url_rule('/login/', methods=['POST'], view_func=login)

app.run()
