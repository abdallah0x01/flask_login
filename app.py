from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, login_required, logout_user, LoginManager
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, ValidationError, Length
from flask_bcrypt import Bcrypt
app = Flask(__name__)
db = SQLAlchemy()  # creates database instance and connect it to app
bycrypt = Bcrypt(app)
# this connects app file to database.db
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db.init_app(app)
app.config['SECRET_KEY'] = 'secret'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


class Users(db.Model, UserMixin):
    '''this is the database table'''
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    # email = db.Column(db.String(40), nullable=False)
    password = db.Column(db.String(200), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(
        min=3, max=20)], render_kw={'placeholder': 'username'})
    # email = StringField(validators=[InputRequired(), Length(
    #     min=5, max=50)], render_kw={'placeholder': 'email'})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={'placeholder': 'password'})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_username = Users.query.filter_by(
            username=username.data).first()
        if existing_username:
            raise ValidationError(
                'username already exists, chhose another one')


class LoginFrom(FlaskForm):

    username = StringField(validators=[InputRequired(), Length(
        min=3, max=50)], render_kw={'placeholder': 'username'})

    password = PasswordField(validators=[InputRequired(), Length(
        min=4, max=50)], render_kw={'placeholder': 'password'})

    submit = SubmitField('Login')

    # def validate_on_submit(self):
    #     return super().validate_on_submit()


with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard.html', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')


@app.route('/logout.html', methods=['GET', 'POST'])
@login_required
def logout():
    return render_template('logout.html')


@app.route('/login.html', methods=['GET', 'POST'])
def login():
    login_form = LoginFrom()
    if login_form.validate_on_submit():
        user = Users.query.filter_by(username=login_form.username.data).first()
        if user:
            if bycrypt.check_password_hash(user.password, login_form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html', form=login_form)


@app.route('/register.html', methods=['GET', 'POST'])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        hashed_password = bycrypt.generate_password_hash(
            register_form.password.data)
        new_user = Users(username=register_form.username.data,
                         password=hashed_password)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html', form=register_form)


if __name__ == '__main__':
    app.run(debug=True)
