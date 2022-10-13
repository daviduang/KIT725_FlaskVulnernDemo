#from crypt import methods
import hashlib
from distutils.log import error
from sre_constants import SUCCESS
from unicodedata import name
from flask import Flask, render_template, request, flash, redirect, url_for, session, logging
from functools import wraps

# import data from data.py
from data import Articles
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt 

app = Flask(__name__)

# MYSQL config
app.secret_key = '12affedasafafqwe'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root1'
app.config['MYSQL_PASSWORD'] = 'root1'
app.config['MYSQL_DB'] = 'flaskdemo'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
# MYSQL init
mysql = MySQL(app)

# Page Routers  

# Home Page
@app.route('/')
def index():
    return render_template('index.html')

# About Page
@app.route('/about')
def about():
    return render_template('about.html')

#Reset Password Method 1
@app.route('/reset1', methods=['GET', 'POST'])
def reset1():
    

    username=request.values.get('username')
    repassword=request.values.get('password')
    resetpass(username,repassword)
    return render_template('reset1.html')


    
  
    



def resetpass(username, repassword):
    if repassword != "":
        # Create cursor
        cursor = mysql.connection.cursor()
        cursor.execute('UPDATE users SET password= "{}" where username="{}"'.format(repassword, username))

            # Commit to database
        mysql.connection.commit()

            # Close cursor
        cursor.close()
    return redirect(url_for('dashboard'))

    
        



# Articles Page
Articles = Articles()
@app.route('/articles')
def articles():
    return render_template('articles.html', articles = Articles)

@app.route('/articles/<string:id>')
def article(id):
    return render_template('article.html', id=id)

# User Registration Page (For Vulnern demo (A07), delete validators)
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=1, max=50)])
    email = StringField('Email', [validators.Length(min=1, max=50)])
    password = StringField('Password', [
        validators.Length(min=1, max=50),
        validators.EqualTo('confirm', message='Passwords do not match!')
    ])
    confirm = PasswordField('Confirm Password')
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data 
        username = form.username.data
        password=form.password.data
        #password=hashlib.sha256(form.password.data.encode('utf-8')).hexdigest()
       
        #password = sha256_crypt.encrypt(str(form.password.data)) # A02: Cryptographic failure (no salt used)

        # Create cursor
        cursor = mysql.connection.cursor()
        cursor.execute("INSERT INTO users(name, email, username, password) VALUES(%s, %s, %s, %s)", (name, email, username, password))

        # Commit to database
        mysql.connection.commit()

        # Close cursor
        cursor.close()

        flash('Registration Sucess!', 'success')
        redirect(url_for('index'))

    return render_template('register.html', form=form)

# User login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        # login form
        username = request.form['username']
        password_typed = request.form['password']
        
        # create cursor
        cursor = mysql.connection.cursor()
        crypted_password=hashlib.sha256(password_typed.encode('utf-8')).hexdigest()
       

        # get user
        #result = cursor.execute('SELECT * FROM users WHERE username = %s', [username] )
        result = cursor.execute('SELECT * FROM users WHERE username = "{}" and password = "{}" '.format(username, password_typed)) 
        print('SELECT * FROM users WHERE username = "{}" and password = "{}" '.format(username, password_typed))

        # if user has found
        # if there is a match
        if result > 0:
            session['logged_in'] = True
            session['username'] = username 
            

            # check if two passwords matched
           
            flash('Authentication Sucess!', 'success')
            return redirect(url_for('dashboard'))
            
           
        else:
            #session['username'] = result 
            
            return render_template('login.html', error='username not found')

    return render_template('login.html') 

# User login state confirmation(middleware), if not logged in, redirect user to login page 
# (This is prevention for A01(url attack), delete this for A01 demo)
def is_user_login(e):
    @wraps(e)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return e(*args, **kwargs)

        else:
            flash('Unauthorised Access!', 'danger')
            return redirect(url_for('login'))

    return wrap

# User dashboard Page
@app.route('/dashboard')

# add middleware to User dashboard page
@is_user_login

def dashboard():
    return render_template('dashboard.html')


# User logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Log out success!', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':  

    app.secret_key='secret' # secret key

    app.run(debug=True)
