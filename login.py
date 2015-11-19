from flask import Flask, render_template, redirect, url_for, session, flash, request
from flask.ext.bootstrap import Bootstrap
from flask_wtf import Form
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, login_required, UserMixin, login_user, logout_user, fresh_login_required, \
    confirm_login, current_user
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.sqlite3'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.refresh_view = "reauthenticate"


# login_manager.needs_refresh_message = (
#     u"To protect your account, please reauthenticate to access this page."
# )
# login_manager.needs_refresh_message_category = "info"
# login_manager.login_view = "main"  # Redirects to this page for login


# login_manager.login_message = "Welcome"

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True)
    password_hash = db.Column(db.String)

    def gen_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def register(username, password):
        user = User(username=username)
        user.gen_password(password)
        db.session.add(user)
        db.session.commit()

    @staticmethod
    def update_password(new_password):
        user = current_user
        user.gen_password(new_password)
        db.session.add(user)
        db.session.commit()

    def __repr__(self):
        return "<name {0} password {1} ".format(self.username, self.password_hash)


class Reauthenticate(Form):
    re_password = PasswordField('Enter Password')
    new_password = PasswordField('Enter new password')
    auth_new_password = PasswordField('Re-enter new password')
    submit = SubmitField('Change Password')


class Login(Form):
    id = StringField('college_id', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('Login')


class NewUser(Form):
    name = StringField('Name', validators=[DataRequired()])
    id = StringField('college_id', validators=[DataRequired()])
    password = PasswordField('password', validators=[DataRequired()])
    repassword = PasswordField('re-password', validators=[DataRequired()])
    submit = SubmitField('Register')


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.route('/')
def page1():
    return render_template('page1.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.id.data).first()  #
        if user is None:
            return redirect(url_for('new_reg'))
        else:
            if user.check_password(form.password.data):
                login_user(user)
                form.id.data = ''

                return redirect(request.args.get('next') or url_for('main'))
            else:
                return redirect(url_for('main', **request.args))

    return render_template('page2.html', form=form)


@app.route('/newuser', methods=['GET', 'POST'])
def new_reg():
    reg_form = NewUser()

    if reg_form.validate_on_submit():
        if reg_form.password.data == reg_form.repassword.data:
            User.register(reg_form.name.data, reg_form.password.data)
            reg_form.id.data = ''
            reg_form.name.data = ''
            return redirect(url_for('login'))
        else:
            reg_form.id.data = ''
            reg_form.name.data = ''
            return redirect(url_for('new_reg'))

    return render_template('new_user.html', form=reg_form)


@app.route('/main')
@login_required
def main():
    return render_template('main.html')


@app.route('/profile')
@fresh_login_required
def prof():
    return render_template('page1.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('page1'))


@app.route('/changepass', methods=['GET', 'POST'])
@login_required
def change_password():
    form = Reauthenticate()
    user = current_user
    if form.validate_on_submit():
        a = user.check_password(form.re_password.data)

        if a:
            user.password_hash = generate_password_hash(form.new_password.data)
            db.session.commit()
            logout_user()
            return redirect(url_for('login'))

    return render_template('reauthenticate.html', form=form)


if __name__ == '__main__':
    db.create_all()
    app.run(port=8080, debug=True)
    app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'
