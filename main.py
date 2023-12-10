# Course: CS493 - Portfolio Project
# Author: Long To Lotto Tang
# Source: Based on Assignment 4
# Date: 11/30/2023

from urllib.parse import quote_plus, urlencode
from urllib.request import urlopen
from flask import Flask, jsonify, make_response, redirect, request, session, render_template, url_for
from google.cloud import datastore
from jose import jwt
from authlib.integrations.flask_client import OAuth

import json
import http.client
import requests
import boat
import load

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

app.register_blueprint(boat.bp)
app.register_blueprint(load.bp)

CLIENT_ID = 'pOvuy85jlBUSxwtsdwoNN7yCv7rn5h1K'
CLIENT_SECRET = 'Bg8Zv9r35p4EqWtFQ8RIk2m8Vagf5ogLFID_NXhQsZIU0JC63fq8TPtXbHMSQruL'
DOMAIN = 'dev-siscs6spoa85mbw0.us.auth0.com'

ALGORITHMS = ["RS256"]

oauth = OAuth(app)

auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    client_kwargs={
        'scope': 'openid profile email',
    },
    server_metadata_url=f'https://{DOMAIN}/.well-known/openid-configuration',
)

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def verify_jwt_simplified(token):
    
    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://" + DOMAIN + "/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


@app.route("/")
def home():
    if session.get('user') is None:
        return render_template("index.html")
    else:
        return render_template("index.html", session=session.get('user'), jwt=json.dumps(session.get('user')["id_token"]), user_id=json.dumps(session.get('user')['userinfo']['sub']), indent=4)


@app.route('/login', methods=['POST'])
def login_user():
    content = request.get_json()
    username = content['username']
    password = content['password']
    body = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    r = requests.post(url, json=body, headers=headers)

    if r.status_code == 200:
        id_token = r.json()['id_token']
        user_info = verify_jwt_simplified(id_token)

        new_user = datastore.entity.Entity(key=client.key('users'))

        query = client.query(kind='users')
        results = query.fetch()
        found = False

        for e in results:
            if e['user_id'] == user_info['sub']:
                found = True

        if not found:

            new_user.update({'user_id': user_info['sub'], 'username': user_info['name']})

            client.put(new_user)

        return r.text, 200, {'Content-Type': 'application/json'}
    
    else:
        return r.text, 403, {'Content-Type': 'application/json'}


@app.route("/login-btn")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )


@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    
    query = client.query(kind='users')
    results = query.fetch()
    found = False

    for e in results:
        if e['user_id'] == token['userinfo']['sub']:
            found = True

    if not found:

        new_user = datastore.entity.Entity(key=client.key('users'))
        new_user.update({'user_id': token['userinfo']['sub'], 'username': token['userinfo']['name']})

        client.put(new_user)

    session["user"] = token
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://"
        + DOMAIN
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("home", _external=True),
                "client_id": CLIENT_ID,
            },
            quote_via=quote_plus,
        )
    )


@app.route("/users", methods=['POST', 'PATCH', 'PUT', 'DELETE', 'OPTIONS', 'HEAD'])
def method_not_recognized1():
    return ({"Error": "Method not recognized."}, 405)


@app.route("/users", methods=["GET"])
def users_get():
    query = client.query(kind='users')
    results = list(query.fetch())
    for e in results:
        e['id'] = e.key.id
    res = make_response(json.dumps(results))
    res.mimetype = 'application/json'
    res.status_code = 201
    return res


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)