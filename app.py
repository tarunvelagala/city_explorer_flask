from datetime import date
import os
from flask import Flask, render_template, redirect, url_for, request
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from sqlalchemy import ForeignKey
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import StringField, PasswordField
from wtforms.validators import InputRequired, Email, Length

from index import get_tech_words, get_cities_from_techwords, get_points_from_city, vlogins

app = Flask(__name__)
Bootstrap(app)
app.secret_key = 'my-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    points = db.relationship('Points', backref="user", uselist=False)
    cities = db.relationship('Cities', backref="user")
    lastday = db.relationship('LoginHistory', backref="user")


class Points(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    points = db.Column(db.Integer, nullable=False, default=1)
    user_id = db.Column(db.Integer, ForeignKey('user.id'), nullable=False, unique=True)


class Cities(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    words = db.Column(db.String, nullable=False)
    cities = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('user.id'))


class LoginHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    yesterday_point = db.Column(db.Integer, nullable=False)
    today_point = db.Column(db.Integer, nullable=False)
    lastday = db.Column(db.Date, nullable=False)
    user_id = db.Column(db.Integer, ForeignKey('user.id'))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(max=15, min=4)])
    password = PasswordField('Password', validators=[InputRequired(), Length(max=80, min=8)])
    # remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Invalid Email')])
    username = StringField('username', validators=[InputRequired(), Length(max=15, min=4)])
    password = PasswordField('Password', validators=[InputRequired(), Length(max=80, min=8)])


class TechKeyForm(FlaskForm):
    techword = StringField('What did you learn today ?', validators=[InputRequired()])


@app.before_first_request
def create_tables():
    db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
@app.route('/home')
def index():
    return render_template('index.html', current_user=current_user)


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                # update login point
                #
                last = LoginHistory.query.filter(LoginHistory.user_id == user.id,
                                                 LoginHistory.lastday < date.today()).first()
                print(last)
                if last:
                    s0, s1 = last.yesterday_point, last.today_point
                    point = Points.query.filter_by(user_id=user.id).first()
                    print(point)
                    point.points += last.today_point
                    last.today_point += s0
                    last.yesterday_point = s1
                    last.lastday = date.today()
                    db.session.commit()
                # end
                return redirect(url_for('app_home'))
        error = 'Invalid User. Username doesn\'t exists.'
    return render_template('login.html', form=form, error=error)


@app.route('/signup', methods=['POST', 'GET'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        d_point = Points(user=new_user)
        new_history = LoginHistory(yesterday_point=0, today_point=1, lastday=date.today(), user=new_user)
        db.session.add(new_user)
        db.session.add(d_point)
        db.session.add(new_history)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)


@app.route('/app', methods=['POST', 'GET'])
@login_required
def app_home():
    form = TechKeyForm()
    error = None
    r_cities = None
    r_words = None
    q_user = User.query.filter_by(username=current_user.username).first()
    # print(q_user.id)
    q_points = Points.query.filter_by(user=q_user).first()
    # cities_explored = Cities.query.filter_by(user=q_user).all()
    if form.validate_on_submit():
        content = form.techword.data
        words = get_tech_words(content.split())
        cities = get_cities_from_techwords(words)
        q_city = Cities.query.filter_by(user=q_user).first()
        if 'no tech keys' in words or len(cities) == 0:
            error = 'No Tech Keys Found'
        d = dict(zip(words, cities))
        if q_city is None:
            for k, v in d.items():
                tmp = Cities(cities=v, words=k, user=q_user)
                db.session.add(tmp)
            d_points = get_points_from_city(cities)
            q_points.points += d_points
            r_cities = cities
            r_words = words
            db.session.commit()
        if q_city is not None:
            _cities = Cities.query.filter_by(user_id=q_user.id).all()
            g_cities = [city.cities for city in _cities]
            g_words = [city.words for city in _cities]
            r_cities = cities - set(g_cities)
            r_words = words - set(g_words)
            d = dict(zip(r_words, r_cities))
            for k, v in d.items():
                tmp = Cities(cities=v, words=k, user=q_user)
                db.session.add(tmp)
            d_points = get_points_from_city(r_cities)
            q_points.points += d_points
            db.session.commit()
    _cities = Cities.query.filter_by(user_id=q_user.id).all()
    g_cities = [city.cities for city in _cities]
    return render_template('app.html', form=form, points=q_points.points, error=error, username=q_user.username,
                           cities_explored=g_cities, words=r_words, r_cities=r_cities)


@app.route('/vlogin', methods=['POST', 'GET'])
def validator_login():
    form = LoginForm()
    error = None
    if form.validate_on_submit():
        if form.username.data in vlogins.keys():
            if form.password.data in vlogins.values():
                return redirect(url_for('validator_page'))
        error = 'Invalid User. Username doesn\'t exists.'
    return render_template('validatorlogin.html', form=form, error=error)


@app.route('/vpage', methods=['POST', 'GET'])
def validator_page():
    users = User.query.join(Points).filter(User.id == Points.user_id).order_by(Points.points.desc()).all()
    if request.method == 'POST':
        if request.form['val'] == 'plus':
            print(1)
        if request.form['val'] == 'sub':
            print(2)
    return render_template('validatorpage.html', users=users)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)
