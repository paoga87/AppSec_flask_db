#!/usr/bin/env python
import os
import subprocess
import json
from subprocess import Popen, PIPE, check_output
from flask import Flask, render_template, redirect, url_for, session, request
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from passlib.hash import sha256_crypt


app = Flask(__name__)
app.config['SECRET_KEY'] = 'WxND4o83j4K4iO3762'

#Initialize csrf token
csrf = CSRFProtect(app)

#Initialize Talisman
Talisman(app, force_https=False, strict_transport_security=False, session_cookie_secure=False)

#Users file
Users = {}


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
        cpath = os.getcwd()
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