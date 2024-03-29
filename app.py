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
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
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

# User Registration Page (For Vulnern demo (A07), delete validators)
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=1, max=50)])
    email = StringField('Email', [validators.Length(min=1, max=50)])
    password = StringField('Password', [
    
        # A07: Identification & Authentication Failure
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
        
        # A02: Cryptographic failure (password unencrypted)
        password = form.password.data

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

# A03: Injection
def login():
    if request.method == 'POST':

        # login form
        username = request.form['username']
        password_typed = request.form['password']
        
        # create cursor
        cursor = mysql.connection.cursor()

        # get user
        result = cursor.execute('SELECT * FROM users WHERE username = "{}" and password = "{}" '.format(username, password_typed)) 

        # if user has found
        if result > 0:
            session['logged_in'] = True
            session['username'] = username 

            user = cursor.fetchall()
            session['name'] = user[0]['name']
            session['email'] = user[0]['email']

            # check if two passwords matched
            flash('Authentication Sucess!', 'success')
            return redirect(url_for('dashboard'))
           
        else:
            return render_template('login.html', error='Authentication Failed!')

    return render_template('login.html') 

# User dashboard Page (A01: Broken Access Control)
@app.route('/dashboard', methods=['GET', 'POST'])

def dashboard():
    return render_template('dashboard.html')

# User logout
@app.route('/logout')
def logout():
    session.clear()
    flash('Log out success!', 'success')
    return redirect(url_for('login'))

# Reset Password (A04: Insecured Design)
@app.route('/resetPassword', methods=['GET', 'POST'])
def resetPassword():

    # A04: Insecured Design
    newpassword=request.values.get('password')
    
    resetpass(newpassword)
    return render_template('resetPassword.html')

def resetpass(newpassword):

    # if password is not empty
    if newpassword != "":

        # Get username from session
        username = session['username']

        # Create cursor
        cursor = mysql.connection.cursor()
        cursor.execute('UPDATE users SET password= "{}" where username="{}"'.format(newpassword, username))

        # Commit to database
        mysql.connection.commit()

        # Close cursor
        cursor.close()
    flash('Password Reset Sucess!', 'success')
    return redirect(url_for('dashboard'))

# View all articles for a user
@app.route('/articles', methods=['GET', 'POST'])
def articles():
    cur = mysql.connection.cursor()
    
    sql = "select * from article"
    cur.execute(sql)
    articles = cur.fetchall()
    cur.close()

    return render_template('articles.html', articles=articles)

# Search function in articles page
@app.route('/search', methods=['GET', 'POST'])

def search():
    if request.method == 'POST':
       
        content = request.form['content'] #content for searching
       
        if content is None:

            content = 'D'
        else:
            content=content

        cur = mysql.connection.cursor()
        cur.execute('SELECT * FROM article WHERE name LIKE "%{}%"'.format(content))
        filteredArticles = cur.fetchall()
       
        cur.close()
        return render_template('articles.html',articles = filteredArticles) 

# View a single article for a user
@app.route('/articles/<string:id>')
def article(id):
    cur =mysql.connection.cursor()
    cur.execute("select * from article WHERE id= %s",[id])
    article=cur.fetchone()
    
    return render_template('article.html', article=article)
    
if __name__ == '__main__':  

    app.secret_key='secret' # secret key

    app.run(debug=True)
