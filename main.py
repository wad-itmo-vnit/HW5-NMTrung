from flask import Flask, render_template, redirect, request, make_response, flash
from functools import wraps
import app_config
from model.user import User
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = app_config.SECRET_KEY

# users = {} 
# users['admin'] = User('admin', 'admin')

users = {name[:-5]:User.from_file(name) for name in os.listdir(app_config.USER_DB_DIR)}

def login_required(func):
    @wraps(func)
    def login_func(*arg, **kwargs):
        try:
            if (users[request.cookies.get('username')].authorize(request.cookies.get('token'))):
                return func(*arg, **kwargs)
        except:
            pass
        flash ("Login required!!!")
        return redirect('/login')

    return login_func

def no_login(func):
    @wraps(func)
    def no_login_func(*arg, **kwargs):
        if request.cookies.get('username') in users.keys():
            if users[request.cookies.get('username')].authorize(request.cookies.get('token')):
                flash("You're already in!!!")
                return redirect('/index')
        
        return func(*arg, **kwargs)

    return no_login_func

@app.route('/')
def home():
    return redirect('/login')

@app.route('/index')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@no_login
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
    if username in users.keys():
        if username == "drum":
            if users[username].authenticate(password):
                token = users[username].init_session()
                resp = make_response(redirect('/drum'))
                resp.set_cookie('username', username)
                resp.set_cookie('token', token)
                return resp
        else:
            if users[username].authenticate(password):
                token = users[username].init_session()
                resp = make_response(redirect('/index'))
                resp.set_cookie('username', username)
                resp.set_cookie('token', token)
                return resp
            else:
                flash("Username or password is incorrect!!!")
    else:
        flash("User does not exists")

    return render_template('login.html')

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    username = request.cookies.get('username')
    users[username].terminate_session()
    resp = make_response(redirect('/login'))
    resp.delete_cookie('username')
    resp.delete_cookie('token')
    flash("You've logged out!!!")
    return resp

@app.route('/register', methods=['POST', 'GET'])
@no_login
def register():
    if request.method == "GET":
        return render_template('register.html')
    
    username = request.form.get('username')
    password = request.form.get('password')
    password_confirm = request.form.get('password_confirm')

    if username not in users.keys():
        if password == password_confirm:
            users[username] = User.new(username, password)
            token = users[username].init_session()
            resp = make_response(redirect('/index'))
            resp.set_cookie('username', username)
            resp.set_cookie('token', token)
            return resp
        else:
            flash("Passwords do not match!!!")
    else:
        flash("User already exists!!!")

    return render_template('register.html')

@app.route('/changepwd', methods=['GET', 'POST'])
@login_required
def change_pwd():
    if request.method == 'GET':
        return render_template('changepwd.html')
    else:
        username = request.cookies.get('username')
        password = request.form.get('cur_password')
        new_password = request.form.get('new_password')
        password_confirm = request.form.get('password_confirm')

        if users[username].authenticate(password):
            if new_password == password_confirm:
                users[username] = User.new(username,new_password)
                users[username].dump()
                resp = make_response(redirect('/login'))
                flash("You have to login again!!!")
                return resp
            else:
                flash("Password do not match!!!")
        else:
            flash("Password is incorrect!!!")

    return render_template('changepwd.html')

@app.route('/drum', methods=['GET', 'POST'])
@login_required
def drum():
    return render_template('drum.html')
        

if __name__ == '__main__':
    app.run(host='localhost', port = 5000, debug=True)