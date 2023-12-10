# Course: CS493 - Portfolio Project
# Author: Long To Lotto Tang
# Source: Based on Assignment 4
# Date: 11/30/2023

from flask import Blueprint, make_response, request
from google.cloud import datastore

import json
import constants

client = datastore.Client()

bp = Blueprint('load', __name__, url_prefix='/loads')

@bp.route('', methods=['PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])
def method_not_recognized1():
    return ({"Error": "Method not recognized."}, 405)


@bp.route('', methods=['POST', 'GET'])
def loadss_get_post():
    # Create a Load
    if request.method == 'POST':

        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Request MIME type is not acceptable."}, 406)

        mimetype = request.mimetype
        if mimetype != 'application/json':
            return ({"Error": "Server only accepts application/json data."}, 415)
        
        content = request.get_json()

        # Check missing attributes
        if 'volume' not in content or 'item' not in content or 'creation_date' not in content:
            return ({"Error": "The request object is missing one of the required attributes."}, 400)

        new_load = datastore.entity.Entity(key=client.key(constants.loads))
        new_load.update({"volume": content["volume"], "item": content["item"], "creation_date": content["creation_date"], "carrier": None})
        
        client.put(new_load)

        # Add back the id & self back to new_load
        new_load['id'] = new_load.key.id
        new_load['self'] = request.base_url + "/" + str(new_load.key.id)

        res = make_response(json.dumps(new_load))
        res.mimetype = 'application/json'
        res.status_code = 201
        
        return res
    
    # Get all Loads
    elif request.method == 'GET':
        query = client.query(kind=constants.loads)

        # Pagination
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        g_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = g_iterator.pages
        results = list(next(pages))

        if g_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        # Add back the id and self attribute back to the entities
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.base_url + "/" + str(e.key.id)

        output = {"loads": results}

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
def loads_get_delete(id):
    if request.method == 'GET':

        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Request MIME type is not acceptable."}, 406)

        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)

        # Check with invalid load_id
        if load is None:
            return ({"Error": "No load with this load_id exists."}, 404)
        
        # Add back the id & self back to Load
        load["id"] = load.key.id
        load["self"] = request.base_url

        res = make_response(json.dumps(load))
        res.mimetype = 'application/json'
        res.status_code = 200
    
        return res
    
    # Allow changing 1 or more attributes by PATCH (except "carrier")
    elif request.method == 'PATCH':

        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Request MIME type is not acceptable."}, 406)
        
        mimetype = request.mimetype
        if mimetype != 'application/json':
            return ({"Error": "Server only accepts application/json data."}, 415)
        
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)

        if load is None:
            return ({"Error": "No load with this load_id exists."}, 404)
        
        content = request.get_json()
        content_keys = content.keys()
        attribute_keys = ["volume", "item", "creation_date"]

        for key in content_keys:
            if key == 'carrier':
                return ({"Error": "Cannot modify 'carrier' in this route."}, 400)

            elif key not in attribute_keys:
                return ({"Error": "The request body contains unallowed attributes."}, 400)
            
        volume = load['volume']
        item = load['item']
        creation_date = load['creation_date']

        if 'volume' in content_keys:
            volume = content['volume']
        if 'item' in content_keys:
            item = content['item']
        if 'creation_date' in content_keys:
            creation_date = content['creation_date']

        load.update({'volume': volume, 'item': item, 'creation_date': creation_date, 'carrier': load['carrier']})

        client.put(load)

        load['id'] = load.key.id
        load['self'] = request.base_url

        res = make_response(json.dumps(load))
        res.mimetype = 'application/json'
        res.status_code = 200

        return res

    elif request.method == 'PUT':

        if 'application/json' not in request.accept_mimetypes:
            return ({"Error": "Request MIME type is not acceptable."}, 406)
        
        mimetype = request.mimetype
        if mimetype != 'application/json':
            return ({"Error": "Server only accepts application/json data."}, 415)
        
        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)

        if load is None:
            return ({"Error": "No load with this load_id exists."}, 404)
        
        content = request.get_json()
        content_keys = content.keys()
        attribute_keys = ["volume", "item", "creation_date"]

        for key in content_keys:
            if key == 'carrier':
                return ({"Error": "Cannot modify 'carrier' in this route."}, 400)

            elif key not in attribute_keys:
                return ({"Error": "The request body contains unallowed attributes."}, 400)

        if 'volume' not in content or 'item' not in content or 'creation_date' not in content:

            return ({"Error": "The request object is missing one of the required attributes."}, 400)
        
        load.update({'volume': content['volume'], 'item': content['item'], 'creation_date': content['creation_date'], 'carrier': load['carrier']})

        client.put(load)

        load['id'] = load.key.id
        load['self'] = request.base_url

        res = make_response(json.dumps(load))
        res.mimetype = 'application/json'
        res.status_code = 200

        return res

    # Delete a Load
    elif request.method == 'DELETE':

        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)

        # Check with invalid load_id
        if load is None:
            return ({"Error": "No load with this load_id exists."}, 404)
        
        client.delete(load_key)

        # Delete the related Loads in Boat
        query = client.query(kind=constants.boats)
        results = query.fetch()

        for e in results:
            # Have Load(s) assigned to Boat
            if len(e['loads']) > 0:
                for index in range(0, len(e['loads'])):
                    if e['loads'][index]['id'] == load.key.id:
                        # Remove the entire Load data from Boat(id & self)
                        e['loads'].pop(index)
                        client.put(e)
                        break

        return ('', 204)