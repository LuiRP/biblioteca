from flask import Flask, render_template, url_for, redirect, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os
from sqlalchemy.sql import func
import random
from datetime import datetime, date

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['UPLOAD_FOLDER'] = 'static/'  # Folder to store uploaded files
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}  # Allowed file extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['TEMPLATES_AUTO_RELOAD'] = True

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=30)], render_kw={"placeholder": "Nombre de Usuario"})
    email = StringField(validators=[InputRequired(), Length(min=4,max=150)], render_kw={"placeholder": "Correo"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=30)], render_kw={"placeholder": "Contraseña"})

    submit = SubmitField("Registrarse")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("Ese nombre de usuario ya existe. Porfavor utilize uno diferente.")
    
    def validate_email(self, email):
        existing_user_email = User.query.filter_by(email=email.data).first()
        if existing_user_email:
            raise ValidationError("Ese correo electronico ya ha sido registrado. Porfavor utilize uno diferente.")

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4,max=30)], render_kw={"placeholder": "Nombre de Usuario"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=30)], render_kw={"placeholder": "Contraseña"})

    submit = SubmitField("Iniciar Sesión")


class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), nullable=False, unique=True)
    cover = db.Column(db.String(100), nullable=False)
    pdf = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<Book {self.name}>'









#Routes

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user)
                return redirect(url_for('aprender'))

    return render_template('login.html', form=form)

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/logout', methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/aprender', methods=['GET','POST'])
@login_required
def aprender():
    return render_template('aprender.html')

@app.route('/biblioteca', methods=['GET','POST'])
@login_required
def biblioteca():
    books = Book.query.all()
    return render_template('biblioteca.html', books=books)

@app.route('/librodiario', methods=['GET','POST'])
@login_required
def librodiario():
    random_book = get_daily_random_element()
    return render_template('librodiario.html', book=random_book )

@app.route('/comunidad', methods=['GET','POST'])
@login_required
def comunidad():
    return render_template('comunidad.html')

@app.route('/perfil', methods=['GET','POST'])
@login_required
def perfil():
    return render_template('perfil.html', user=current_user)

@app.route('/perfil_cambio', methods=['GET','POST'])
@login_required
def perfil_cambio():
    return render_template('perfil_cambio.html', user=current_user)

@app.route('/course_1', methods=['GET','POST'])
@login_required
def course_1():
    return render_template('course_1.html')

@app.route('/course_2', methods=['GET','POST'])
@login_required
def course_2():
    return render_template('course_2.html')

@app.route('/course_3', methods=['GET','POST'])
@login_required
def course_3():
    return render_template('course_3.html')

@app.route('/course_4', methods=['GET','POST'])
@login_required
def course_4():
    return render_template('course_4.html')

@app.route('/course_5', methods=['GET','POST'])
@login_required
def course_5():
    return render_template('course_5.html')

@app.route('/course_6', methods=['GET','POST'])
@login_required
def course_6():
    return render_template('course_6.html')

@app.route('/add_book', methods=['GET', 'POST'])
def add_book():
    if request.method == 'POST':
        name = request.form['name']
        cover = request.files['cover']
        pdf = request.files['pdf']

        # Validate and save the cover image
        if cover and allowed_file(cover.filename):
            cover_filename = secure_filename(cover.filename)
            cover_path = os.path.join(app.config['UPLOAD_FOLDER'], cover_filename)
            cover.save(cover_path)
        else:
            flash('Invalid cover image file.')
            return redirect(request.url)

        # Validate and save the PDF
        if pdf and allowed_file(pdf.filename):
            pdf_filename = secure_filename(pdf.filename)
            pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], pdf_filename)
            pdf.save(pdf_path)
        else:
            flash('Invalid PDF file.')
            return redirect(request.url)

        # Save the book to the database
        new_book = Book(name=name, cover=cover_filename, pdf=pdf_filename)
        db.session.add(new_book)
        db.session.commit()

        flash('Book added successfully!')
        return redirect(url_for('add_book'))

    return '''
    <form method="post" enctype="multipart/form-data">
        Name: <input type="text" name="name"><br>
        Cover: <input type="file" name="cover"><br>
        PDF: <input type="file" name="pdf"><br>
        <input type="submit" value="Submit">
    </form>
    '''
#

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_daily_random_element():
    # Use today's date as a seed for randomness
    today = date.today()
    random.seed(today.toordinal())  # Seed the random number generator with today's date

    # Count the total number of rows in the table
    total_rows = Book.query.count()

    if total_rows == 0:
        return None

    # Generate a random offset based on the seed
    random_offset = random.randint(0, total_rows - 1)

    # Query the random element using the offset
    random_element = Book.query.offset(random_offset).first()
    return random_element

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    with app.app_context():
        db.create_all()
    app.run(debug=True)
