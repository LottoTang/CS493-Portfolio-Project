# Course: CS493 - Portfolio Project
# Author: Long To Lotto Tang
# Source: Based on Assignment 4
# Date: 11/30/2023

from urllib.request import urlopen
from flask import Blueprint, Flask, jsonify, make_response, request
from google.cloud import datastore
from jose import jwt

import json
import constants

client = datastore.Client()

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

bp = Blueprint('boat', __name__, url_prefix='/boats')

CLIENT_ID = 'pOvuy85jlBUSxwtsdwoNN7yCv7rn5h1K'
CLIENT_SECRET = 'Bg8Zv9r35p4EqWtFQ8RIk2m8Vagf5ogLFID_NXhQsZIU0JC63fq8TPtXbHMSQruL'
DOMAIN = 'dev-siscs6spoa85mbw0.us.auth0.com'

ALGORITHMS = ["RS256"]


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


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
                issuer="https://" + DOMAIN + "/"
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
    

@bp.route('', methods=['PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
def method_not_recognized1():
    return ({"Error": "Method not recognized."}, 405)


@bp.route('', methods=['POST', 'GET'])
def boats_get_post():
    # Create a Boat
    if request.method == 'POST':

        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Request MIME type is not acceptable."}, 406)
        
        mimetype = request.mimetype
        if mimetype != 'application/json':
            return ({"Error": "Server only accepts application/json data."}, 415)
        try:
            payload = verify_jwt(request)
            content = request.get_json()

            # Check missing attributes
            if 'name' not in content or 'type' not in content or 'length' not in content:
                return ({"Error": "The request object is missing one of the required attributes."}, 400)
        
            new_boat = datastore.entity.Entity(key=client.key(constants.boats))
            new_boat.update({'name': content['name'], 'type': content['type'], 'length': content['length'], 'loads': [], 'owner': payload['sub']})

            client.put(new_boat)

            # Add back the id & self back to new_boat
            new_boat['id'] = new_boat.key.id
            new_boat['self'] = request.base_url + "/" + str(new_boat.key.id)
            
            res = make_response(json.dumps(new_boat))
            res.mimetype = 'application/json'
            res.status_code = 201
            
            return res
        
        except AuthError:
            return ({"Error": "Missing or invalid JWTs."}, 401)
    
    # Get all Boats
    elif request.method == 'GET':

        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Request MIME type is not acceptable."}, 406)
        
        try:
            payload = verify_jwt(request)
            query = client.query(kind=constants.boats)
            query = query.add_filter('owner', '=', payload['sub'])

            # Pagination
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = query.fetch(limit=q_limit, offset=q_offset)
            
            pages = l_iterator.pages
            # results = list(filter(lambda entity: entity["owner"] == payload["sub"], list(next(pages))))
            results = list(next(pages))

            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            
            # Add back the id and self attribute back to the entities
            for e in results:
                e["id"] = e.key.id
                e["self"] = request.base_url + "/" + str(e.key.id)

            output = {"boats": results}

            # Add back the next attribute for each item (except those without next_url)
            if next_url:
                output["next"] = next_url

            res = make_response(json.dumps(output))
            res.mimetype = 'application/json'
            res.status_code = 200
            
            return res
        
        except AuthError:
            query = client.query(kind=constants.boats)

            # Pagination
            q_limit = int(request.args.get('limit', '5'))
            q_offset = int(request.args.get('offset', '0'))
            l_iterator = query.fetch(limit=q_limit, offset=q_offset)
            pages = l_iterator.pages
            results = list(next(pages))

            if l_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None
            
            # Add back the id and self attribute back to the entities
            for e in results:
                e["id"] = e.key.id
                e["self"] = request.base_url + "/" + str(e.key.id)

            output = {"boats": results}

            # Add back the next attribute for each item (except those without next_url)
            if next_url:
                output["next"] = next_url
            
            res = make_response(json.dumps(output))
            res.mimetype = 'application/json'
            res.status_code = 200
            
            return res


@bp.route('/<id>', methods=['HEAD', 'OPTIONS', 'POST'])
def method_not_recognized2(id):
    return ({"Error": "Method not recognized."}, 405)


@bp.route('/<id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def boats_get_delete(id):
    
    if request.method == 'GET':

        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Request MIME type is not acceptable."}, 406)
        
        try:
            payload = verify_jwt(request)
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)

            if boat is None:
                return ({"Error": "No boat with this boat_id exists."}, 404)

            if boat and boat['owner'] == payload['sub']:
                # Add back the id & self back to Boat
                boat['id'] = boat.key.id
                boat['self'] = request.base_url
            
                res = make_response(json.dumps(boat))
                res.mimetype = 'application/json'
                res.status_code = 200
            
                return res
            else:
                # Valid JWT but boat_id is owned by someone else
                    return ({"Error": "Valid JWT but the boat is owned by others."}, 403)
        except AuthError:
            return ({"Error": "Missing or invalid JWTs."}, 401)

    # Allow changing 1 or more attributes by PATCH (except "loads")
    elif request.method == 'PATCH':

        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Request MIME type is not acceptable."}, 406)
        
        mimetype = request.mimetype
        if mimetype != 'application/json':
            return ({"Error": "Server only accepts application/json data."}, 415)
        try:
            payload = verify_jwt(request)
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)

            if boat is None:
                return ({"Error": "No boat with this boat_id exists."}, 404)

            if boat and boat['owner'] == payload['sub']:
                content = request.get_json()
                content_keys = content.keys()
                attribute_keys = ["name", "type", "length"]

                for key in content_keys:
                    if key == 'loads':
                        return ({"Error": "Cannot modify 'loads' in this route."}, 400)

                    elif key not in attribute_keys:
                        return ({"Error": "The request body contains unallowed attributes."}, 400)
                    
                name = boat['name']
                boat_type = boat['type']
                length = boat['length']

                if 'name' in content_keys:
                    name = content['name']
                if 'type' in content_keys:
                    boat_type = content['type']
                if 'length' in content_keys:
                    length = content['length']

                boat.update({'name': name, 'type': boat_type, 'length': length, 'loads': boat['loads']})

                client.put(boat)

                boat['id'] = boat.key.id
                boat['self'] = request.base_url

                # Side effect: change of 'name'
                if 'name' in content_keys:
                    query = client.query(kind=constants.loads)
                    results = query.fetch()

                    for e in results:
                        if e['carrier'] is not None:
                            # Case: change of boat['name']
                            if e['carrier']['id'] == boat.key.id:
                                e['carrier']['name'] = name
                                client.put(e)  

                res = make_response(json.dumps(boat))
                res.mimetype = 'application/json'
                res.status_code = 200
                
                return res
            else:
                return ({"Error": "Valid JWT but the boat is owned by others."}, 403)
        except AuthError:
            return ({"Error": "Missing or invalid JWTs."}, 401)

    elif request.method == 'PUT':

        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Request MIME type is not acceptable."}, 406)

        mimetype = request.mimetype
        if mimetype != 'application/json':
            return ({"Error": "Server only accepts application/json data."}, 415)
        try:
            payload = verify_jwt(request)
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)

            if boat is None:
                return ({"Error": "No boat with this boat_id exists."}, 404)

            if boat['owner'] == payload['sub']:
                content = request.get_json()
                content_keys = content.keys()
                attribute_keys = ["name", "type", "length"]

                for key in content_keys:
                    if key == 'loads':
                        return ({"Error": "Cannot modify 'loads' in this route."}, 400)

                    elif key not in attribute_keys:
                        return ({"Error": "The request body contains unallowed attributes."}, 400)

                if 'name' not in content or 'type' not in content or 'length' not in content:

                    return ({"Error": "The request object is missing one of the required attributes."}, 400)
                
                if content['name'] != boat['name']:
                    # Side effect: change of 'name'
                    query = client.query(kind=constants.loads)
                    results = query.fetch()

                    for e in results:
                        if e['carrier'] is not None:

                            # Case: change of boat['name']
                            if e['carrier']['id'] == boat.key.id:
                                e['carrier']['name'] = content['name']
                                client.put(e)
                
                boat.update({'name': content['name'], 'type': content['type'], 'length': content['length'], 'loads': boat['loads']})

                client.put(boat)

                boat['id'] = boat.key.id
                boat['self'] = request.base_url

                res = make_response(json.dumps(boat))
                res.mimetype = 'application/json'
                res.status_code = 200
                
                return res
            else:
                return ({"Error": "Valid JWT but the boat is owned by others."}, 403)
        except AuthError:
            return ({"Error": "Missing or invalid JWTs."}, 401)

    # Delete a Boat
    elif request.method == 'DELETE':
        try:
            payload = verify_jwt(request)
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)

            if boat is None:
                return ({"Error": "No boat with this boat_id exists."}, 404)

            if boat['owner'] == payload['sub']:
                client.delete(boat_key)
                # Delete the Carrier from Load
                query = client.query(kind=constants.loads)
                results = query.fetch()

                for e in results:
                    if e['carrier'] is not None:
                        if e['carrier']['id'] == int(id):
                            e['carrier'] = None
                            client.put(e)
                    
                return ('', 204)
            else:
                return ({"Error": "Valid JWT but the boat is owned by others."}, 403)
        except AuthError:
            return ({"Error": "Missing or invalid JWTs."}, 401)


@bp.route('/<bid>/loads/<lid>', methods=['GET', 'POST', 'PATCH', 'HEAD', 'OPTIONS'])
def method_not_recognized3(bid, lid):
    return ({"Error": "Method not recognized."}, 405)


@bp.route('/<bid>/loads/<lid>', methods=['PUT', 'DELETE'])
def add_delete_load(bid, lid):
    # Assign Load to Boat
    if request.method == 'PUT':
        try:
            payload = verify_jwt(request)
            boat_key = client.key(constants.boats, int(bid))
            boat = client.get(key=boat_key)

            load_key = client.key(constants.loads, int(lid))
            load = client.get(key=load_key)

            # Check with invalid boat_id & load_id
            if boat is None:
                return ({"Error": "No boat with this boat_id exists."}, 404)
            
            if load is None:
                return ({"Error": "No load with this load_id exists."}, 404)

            # Check if the Load is assigned
            if load['carrier'] is not None:
                return ({"Error": "The load is already loaded on another boat."}, 403)
            
            if boat['owner'] == payload['sub']:
                boat_url_index = request.base_url.find('/boats/' + bid)
                boat_url_length = len('/boats/' + str(bid))

                load_url = request.base_url[0 : boat_url_index] + request.base_url[boat_url_index + boat_url_length:]

                boat_url = request.base_url[0:boat_url_index + boat_url_length]       

                load['carrier'] = {'id': boat.key.id, 'name': boat['name'], 'self': boat_url}
                boat['loads'].append({'id': load.key.id, 'self': load_url})

                client.put(load)
                client.put(boat)

                return ('', 204)
            else:
                return ({"Error": "Valid JWT but the boat is owned by others."}, 403)
        except AuthError:
            return ({"Error": "Missing or invalid JWTs."}, 401)
    
    # Remove Load from Boat
    elif request.method == 'DELETE':
        try:
            payload = verify_jwt(request)
            boat_key = client.key(constants.boats, int(bid))
            boat = client.get(key=boat_key)

            load_key = client.key(constants.loads, int(lid))
            load = client.get(key=load_key)

            # Check with invalid boat_id & load_id
            if boat is None:
                return ({"Error": "No boat with this boat_id exists."}, 404)
            
            if load is None:
                return ({"Error": "No load with this load_id exists."}, 404)
            
            if boat['owner'] != payload['sub']:
                return ({"Error": "Valid JWT but the boat is owned by others."}, 403)

            if len(boat['loads']) > 0:
                for index in range(0, len(boat['loads'])):
                    if boat['loads'][index]['id'] == int(lid):
                        # Remove the entire Load data from Boat(id & self)
                        boat['loads'].pop(index)
                        client.put(boat)
                        load['carrier'] = None
                        client.put(load)
                        return ('', 204)
            
            return ({"Error": "No load with this load_id is assigned on the boat on this boat_id."}, 404)
            
        except AuthError:
            return ({"Error": "Missing or invalid JWTs."}, 401)