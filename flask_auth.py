from functools import wraps

from flask import Flask, request, abort


app = Flask(__name__)

def check_auth(name,passw):
    return (name=='admin' and passw=='pass')

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        print auth
        if not auth or not check_auth(auth.username, auth.password):
            abort(401)
        return f(*args, **kwargs)
    return decorated


@app.route('/')
@requires_auth
def hello():
    return "Hello World"


if __name__ == "__main__":
    app.run(debug=True)
    
