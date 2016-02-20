from flask import Flask, render_template, redirect, url_for, session, flash, request, g, send_from_directory
from flask.ext.bootstrap import Bootstrap
from flask_wtf import Form
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, EqualTo
from flask_wtf.file import FileField, FileAllowed, FileRequired
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.login import LoginManager, login_required, UserMixin, login_user, logout_user, fresh_login_required, \
    confirm_login, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import os
import imghdr
from flask.ext.uploads import UploadSet
from flask_wtf.csrf import CsrfProtect
app = Flask(__name__)
bootstrap = Bootstrap(app)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd()+'/uploads/')
app.config['ALLOWED_EXTENSIONS'] = ['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif']
app.config['WTF_CSRF_ENABLED'] = True

csrf = CsrfProtect()
csrf.init_app(app)


db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

login_manager.refresh_view = "/reauthenticate"

login_manager.login_view = '/login'
login_manager.login_message = 'PLease log in to access the page.'

login_manager.refresh_view = '/changepass'
login_manager.needs_refresh_message = "Confirm your account"


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True)
    address = db.Column(db.String)
    password_hash = db.Column(db.String)

    def gen_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def register(username, password, address):
        user = User(username=username)
        user.gen_password(password)
        user.address = address
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
    re_password = PasswordField('Enter Password', validators=[DataRequired()])
    new_password = PasswordField('Enter new password', validators=[DataRequired()])
    auth_new_password = PasswordField('Re-enter new password', validators=[DataRequired(), EqualTo('new_password',
                                                                                           message=' New Passwords do not match')])
    submit = SubmitField('Change Password')


class Login(Form):
    id = StringField('college_id', validators=[DataRequired()])
    address = StringField('address')
    password = PasswordField('password', validators=[DataRequired()])
    submit = SubmitField('Login')


class NewUser(Form):
    name = StringField('Name', validators=[DataRequired()])
    id = StringField('college_id', validators=[DataRequired()])
    address = StringField('address')
    password = PasswordField('password', validators=[DataRequired()])
    repassword = PasswordField('re-password', validators=[DataRequired()])
    submit = SubmitField('Register')


class UploadForm(Form):
    image_file = FileField('Upload image',validators=[FileAllowed(app.config['ALLOWED_EXTENSIONS'],message="Invalid")])
    submit = SubmitField('Submit')


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
            form.id.data = ''
            return redirect(url_for('new_reg'))
        else:
            if user.check_password(form.password.data):
                form.id.data = ''
                login_user(user)
                # return redirect(request.args.get('next') or url_for('main'))
                return redirect(url_for('main'))
            else:

                return redirect(url_for('main'))

    return render_template('page2.html', form=form)


@app.route('/newuser', methods=['GET', 'POST'])
def new_reg():
    reg_form = NewUser()

    if reg_form.validate_on_submit():
        if reg_form.password.data == reg_form.repassword.data:
            User.register(reg_form.name.data, reg_form.password.data, reg_form.address.data)
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


@app.route('/uploads', methods=['GET', 'POST'])
def upload_image():
    image = None
    form = UploadForm()

    if form.validate_on_submit():
        image = secure_filename(form.image_file.data.filename)
        form.image_file.data.save(os.path.join(app.config['UPLOAD_FOLDER'] + image))
        flash('Uploaded successfully')
        return render_template('main.html')

    return render_template('uploads.html', form=form, image=image)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('page1'))


@app.route('/changepass', methods=['GET', 'POST'])
@fresh_login_required
def change_password():
    form = Reauthenticate()
    user = current_user
    if form.validate_on_submit():
        a = user.check_password(form.re_password.data)

        if a:
            user.password_hash = generate_password_hash(form.new_password.data)
            db.session.commit()
            logout_user()
            flash('Password Changed')
            return redirect(url_for('login'))

        else:
            flash('Incorrect password entered!')

    return render_template('reauthenticate.html', form=form)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

@app.route('/edit', methods=['GET','PUT'])
def edit_profile():
	user = current_user
	form = Login()
	if request.method == 'GET':
		form.id.data = user.username
		form.address.data = user.address
	if request.method == 'PUT':
		user.id = form.id.data
		user.address = form.address.data
		try:
			db.session.add(user)
			db.session.commit()
		except Exception as e:
			db.session.rollback()
			print e
			abort(500)
		return redirect(url_for(main))

	return render_template('new_user.html',form=form)


if __name__ == '__main__':
    db.create_all()
    app.run(port=8080, debug=True)
    app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'
