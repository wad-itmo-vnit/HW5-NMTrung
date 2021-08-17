from flask import Flask, render_template, redirect, request, make_response
from functools import wraps

app = Flask(__name__)

auth_token = ["asdqwezxc","123456789"]

def generate_token(user,pwd):
    if (user == 'admin' and pwd == 'admin'):
        return auth_token[0]
    elif (user == 'drum' and pwd == '123456'):
        return auth_token[1]

@app.route('/')
def home():
    return redirect('/login')

def auth(request):
    global auth_token
    key = []
    token1 = request.cookies.get('login-info1')
    token2 = request.cookies.get('login-info2')
    if token1==auth_token[0]:
        key.append(1)
    if token2==auth_token[1]:
        key.append(2)
    return key

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'GET':
        return render_template('login.html')
    else:
        user = request.form.get('user')
        pwd = request.form.get('password')
        if (user == 'admin' and pwd == 'admin'):
            token1 = generate_token(user, pwd)
            resp1 = make_response(redirect('/index'))
            resp1.set_cookie('login-info1', token1)
            return resp1
        elif (user == 'drum' and pwd == '123456'):
            token2 = generate_token(user, pwd)
            resp2 = make_response(redirect('/drum'))
            resp2.set_cookie('login-info2', token2)
            return resp2
        else:
            return redirect('/login'), 403

@app.route('/index')
def index():
    if 1 in auth(request):
        return render_template('index.html')
    else:
        return redirect('/')

@app.route('/drum')
# @auth_required
def drum():
    if 2 in auth(request):
        return render_template('drum.html')
    else:
        return redirect('/')


if __name__ == '__main__':
    app.run(host='localhost', port = 5000, debug=True)