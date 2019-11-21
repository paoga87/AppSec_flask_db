import os
import subprocess
import json
import re
from subprocess import Popen, PIPE, check_output
from flask import Flask, render_template, redirect, url_for, session, request
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from passlib.hash import sha256_crypt
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

cpath = os.getcwd()
app_db_file = "sqlite:///{}".format(os.path.join(cpath, "app_db.db"))

app = Flask(__name__)
app.secret_key = 'WxND4o83j4K4iO3762'

#App DB Setup
app.config["SQLALCHEMY_DATABASE_URI"] = app_db_file
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

#Initialize csrf token
csrf = CSRFProtect(app)

#Initialize Talisman
Talisman(app, force_https=False, strict_transport_security=False, session_cookie_secure=False)

#User Models for the DB
class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(20), unique = True, nullable = False, primary_key = True)
    password = db.Column(db.String(86), nullable = False)
    twofa = db.Column(db.String(11), nullable = False)
    role = db.Column(db.String(6), nullable = False)

    def __repr__(self):
        return "<User %r %r %r %r>" % (self.username, self.password, self.twofa, self.role)

class LoginHistory(db.Model):
    __tablename__ = 'history'
    lid = db.Column(db.Integer, nullable = False, autoincrement = True, primary_key = True) 
    lintime = db.Column(db.DateTime, nullable = False)
    louttime = db.Column(db.DateTime, nullable = False)
    username = db.Column(db.String(20), nullable = False)

    def __repr__(self):
        return "<LoginHistory %r %r %r %r>" % (self.lid, self.lintime, self.louttime, self.username)

class QueryHistory(db.Model):
    __tablename__ = 'queries'
    qid = db.Column(db.Integer, nullable = False, autoincrement = True, primary_key = True) 
    qtext = db.Column(db.String(3000), nullable = False)
    qresult = db.Column(db.String(3000), nullable = False)
    username = db.Column(db.String(20), nullable = False)

    def __repr__(self):
        return "<QueryHistory %r %r %r %r>" % (self.qid, self.qtext, self.qresult, self.username)

#Create DB
db.create_all()

#Admin: expected account details - filter
if (User.query.filter_by(username = "admin").count() == 0):
    admin_account = User (username = "admin", password = sha256_crypt.using(rounds = 324333).hash("Administrator@1"), twofa = "12345678901", role ="admin")
    db.session.add(admin_account)
    db.session.commit()

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['uname'].lower()
        if (username in Users.keys()):
            success = "failure"
        else:
            password = sha256_crypt.hash(request.form['pword'])
            twofa = request.form['2fa']
            Users[username] = {'password': password, '2fa': twofa}
            success = "success"
            user_file = open("./static/users.txt", "w")
            user_file.write(json.dumps(Users))
            user_file.close()

        return render_template ("register.html", success = success)
    
    if request.method == 'GET':
        success = "Please register to access the site"
        return render_template("register.html", success = success)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['uname'].lower()
        if (username in Users.keys()):
            password = request.form['pword']
            twofa = request.form['2fa']
            if sha256_crypt.verify(password, Users[username]['password']):
                if (Users[username]['2fa'] == twofa):
                    session['logged_in'] = True
                    result = "success"
                else:
                    result = "Two-factor failure"
            else:
                result = "Incorrect password"
        else:
            result = "Incorrect username"
        
        return render_template('login.html', result = result)

    if request.method == 'GET':
        result = "Please login to use the site"
        return render_template("login.html", result = result)

@app.route('/spell_check', methods=['GET', 'POST'])
def spell():
    if(session.get('logged_in') == True): 
        if request.method == 'POST':
            outputtext = request.form ['inputtext']
            textfile = open("./static/text.txt", "w")
            textfile.writelines(outputtext)
            textfile.close()

            tmp = subprocess.check_output([cpath + '/static/a.out', cpath + '/static/text.txt', cpath + '/static/wordlist.txt']).decode('utf-8')
            misspelled = tmp.replace("\n",", ")[:-2]
            return render_template("spell_check.html", misspelled = misspelled, outputtext = outputtext)

        if request.method == 'GET':
            return render_template("spell_check.html")

    else:
        return redirect(url_for('login'))
    


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)