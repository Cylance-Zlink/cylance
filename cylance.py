#!/usr/bin/env python

__authors__ = ["Zack Link", "David Rojas"]
__maintainer__ = "Zack Link"
__email__ = "zlink@cylance.com"
__version__ = "0.5"
__credits__ = []
__license__ = "GPL"

import jwt
import json
import uuid
import requests  # requests version 2.18.4 as of the time of authoring
from datetime import datetime, timedelta
import os.path
import csv
import pandas as pd
import logging

""" USE CASES """


""" TODO LIST """
""" Not checking a lot of input params, need to add that """
""" Make get_data_by_id function return multiplae pages of data just like get_data function, actually, probabyly just merge the 2 functions by adding id as an optional parameter in get_data()"""
""" Search for TODO in the code """

""" GLOBAL PARAMS """
# LOG PARAMS
LOG_FILE = "cylance_api.log"
# Logging level, can be CRITICAL, ERROR, WARNING, INFO, DEBUG
LOG_LEVEL = logging.DEBUG
logging.basicConfig(filename=LOG_FILE,level=LOG_LEVEL)

creds = {
    "tenant": "",
    "app_id": "",
    "app_secret": "",
    "region": ""
}
auth_token = ""
device_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + str(auth_token)}
timeout_datetime = datetime.utcnow()
timeout_epoch = ""
regions = {
    'North America': '', 
    'Asia Pacific-North': '-apne1', 
    'Asia Pacific-South': '-au', 
    'Europe': '-euc1', 
    'US-Government': '-us', 
    'South America': '-sae1'
}
# region = "" 
URLS = {
    "BASE_URL": "https://protectapi", 
    "AUTH_URL": ".cylance.com/auth/v2/token", 
    "USERS": ".cylance.com/users/v2", 
    "DEVICES": ".cylance.com/devices/v2", 
    "DEVICETHREATS": ".cylance.com/devices/v2", 
    "POLICIES": ".cylance.com/policies/v2", 
    "ZONES": ".cylance.com/zones/v2", 
    "ZONEDEVICES": ".cylance.com/zones/v2",
    "THREATS": ".cylance.com/threats/v2",
    "THREATDEVICES": ".cylance.com/threats/v2", 
    "QUARANTINE": ".cylance.com/globallists/v2", 
    "SAFE": ".cylance.com/globallists/v2" 
}
PAGE_SIZE = 200

# Fields required for UPDATE of particular device type
FIELD_UPDATE_MAP = {
    "USERS": {"email":"", "user_role":"", "first_name":"", "last_name":"", "zones":[]},
    "DEVICES": {"name":"", "policy_id":"", "add_zones_id":[], "remove_zone_ids":[]}
}

def load_creds(file):
    # get saved creds if they exist
    global creds
    logging.info("loading creds")
    with open(file) as infile:
        creds = json.load(infile)
    # TODO: return success or failure

def save_creds(file=""):
    # save creds
    # TODO: retuen success or fail
    global creds
    logging.info("saving creds to: " + file)
    if file == "":
        file = "config.json"
    with open(file, "w") as out:
        json.dump(creds, out)
    out.close()
    os.chmod(file, 0o600)

def set_creds(tenant, app_id, app_secret, region=""):
    global creds
    creds['tenant'] = tenant
    creds['app_id'] = app_id
    creds['app_secret'] = app_secret
    creds['region'] = region
    if tenant == "":
        load_creds("config.json")

def get_regions():
    return regions.keys()

def get_region():
    global region
    return region

def set_region(reg):
    global region
    creds['region'] = regions[reg]

def get_data(data_type, args=""):
    """Pull data from console (all bulk gets)"""
    """args come in the form of:"""
    """  <filter1=value,filterN=value> <fields=field1,fieldN> <out=outputfile.json|.csv> """
    """  e.g. filter1=aaa,filter2=bbb fields=email,first_name,last_name out=users.csv"""

    """ First check if auth token is about to expire and refresh if necessary """
    global auth_token, device_headers
    if creds['tenant'] == "":
        return "Authorization credentials not set"
    if timeout_datetime < datetime.utcnow():  # need to auth/re-auth
        logging.info("timeout exceeded, need to renew auth token")
        auth_token = get_token()
    # Build URL from function and region
    url = URLS['BASE_URL'] + creds['region'] + URLS[data_type]
    logging.debug("using URL: " + url)

    # function variables
    file = ""
    filters = ""
    fields = ""
    args_sections = args.split(" ")
    # TODO - bug if file and/or fields are passed with no filter...
    # this could be a lot cleaner, also rethink the syntax for passing variables to see if there is a better way
    if len(args_sections) > 0:
        filters = args_sections[0]
    if len(args_sections) > 1:
        # Find fields and/or file
        a = args_sections[1].split("=")
        if a[0] == "fields":
            fields = a[1]
        elif a[0] == "out":
            file = a[1]
    if len(args_sections) > 2:
        # Find fields and/or file
        a = args_sections[2].split("=")
        if a[0] == "fields":
            fields = a[1]
        elif a[0] == "out":
            file = a[1]
    # TODO: need to wrap requests.get() in a try in case auth wasn't done first or otherwise don't have an auth token
    # Get 1st page of data
    r = requests.get(url + "?page_size=" + str(PAGE_SIZE), headers=device_headers)
    json_data = json.loads(r.text)
    rows = {'page_items':[]}
    rows['page_items'] = json_data['page_items']
    # If there are multiple pages, go ahead and pull them in too
    pages = json_data['total_pages']
    if pages > 1:
        logging.debug("getting more pages of results from: " + url)
        for x in range (2, pages + 1):
            r = requests.get(url + "?page_size=" + str(PAGE_SIZE) + "&page=" + str(x), headers=device_headers)
            json_data = json.loads(r.text)
            rows['page_items'] = rows['page_items'] + json_data['page_items']

    # Use pandas dataframe to manipulate data
    df = pd.DataFrame.from_dict(rows['page_items'])
    # print "#### DESCRIBE DATAFRAME ####"
    # print df.dtypes.index

    # If there are filters defined, run them
    if filters != "":
        logging.debug("have filter: " + filters + " calling filter_data()")
        df = filter_data(df, filters)

    # If desired fields are defined, run them
    # print " fields = " + fields
    if fields != "":
        logging.debug("Fields defined, need to remove unwanted fields, calling field_data()")
        #filter and order fields
        df = field_data(df, fields)

    # If an output file is defined, go ahead and write to file
    # print " filename = " + file
    if file != "":
        logging.info("write to file requested: " + file + ". Calling write_to_file()")
        # Write data to file based on extension
        write_to_file(df, file)
    return df

def get_data_by_id(data_type, id, args=""):
    """ Gets data for a specific ID.  Data_types supported: USERS, DEVICES, DEVICETHREATS, ZONEDEVICES, POLICIES, ZONES, THREATS, THREATDEVICES, and THREATDOWNLOADS."""
    """ standard args for filtering, fields and file output"""
    """ First check if auth token is about to expire and refresh if necessary """
    global auth_token, device_headers
    if timeout_datetime < datetime.utcnow():  # need to auth/re-auth
        logging.info("timeout exceeded, need to renew auth token")
        auth_token = get_token()
    # Build URL from function and region
    if data_type in { 'USERS', 'DEVICES', 'POLICIES', 'ZONES', 'THREATS' }:
        url = URLS['BASE_URL'] + creds['region'] + URLS[data_type] + "/" + id
    elif data_type in { 'ZONEDEVICES', 'THREATDEVICES' }:
        url = URLS['BASE_URL'] + creds['region'] + URLS[data_type] + "/" + id + "/devices?page=1&page_size=" + str(PAGE_SIZE)
    elif data_type == "DEVICETHREATS":
        url = URLS['BASE_URL'] + creds['region'] + URLS[data_type] + "/" + id + "/threats?page=1&page_size=" + str(PAGE_SIZE)
    # elif data_type == "THREATDOWNLOADS":
    #    url = URLS['BASE_URL'] + creds['region'] + URLS[data_type] + "/" + id + "/threats?page=1&page_size=" + str(PAGE_SIZE)
        
    r = requests.get(url, headers=device_headers)
    # TODO need to support multi page responses like in get_data() ?  Not sure there are multi-page results, validate need first
    json_data = json.loads(r.text)
    df = pd.DataFrame.from_dict(json_data, orient='index')
    return df

def update_data(data_type, id, data):
    """Update an entity. Supports USER, DEVICE, POLICY."""
    """Standard args for filtering, fields and file output"""
    """ First check if auth token is about to expire and refresh if necessary """
    global auth_token, device_headers
    if timeout_datetime < datetime.utcnow():  # need to auth/re-auth
        logging.info("timeout exceeded, need to renew auth token")
        auth_token = get_token()
    # Build URL from function and region
    if data_type in { 'USERS', 'DEVICES', 'POLICIES', 'ZONES' }:
        url = URLS['BASE_URL'] + region + URLS[data_type] + "/" + id
    else:
        return "bad data_type: " + data_type + " for update_data"
    # if data is an input file, slurp that in
    # print data
    if data.startswith("in="):
        file = data.split("=")[1]
        with open(file) as infile:
            data = json.load(infile, 'utf-8')
    else:
        data = json.loads(data)
    data = convert_unicode_to_utf8(data)
    data_tobe_updated = {} 
    for f in FIELD_UPDATE_MAP[data_type]:
        if f in data:
            data_tobe_updated[f] = data[f]
        else:
            data_tobe_updated[f] = ""
    # print "Update user with this data"
    # print data_tobe_updated
    r = requests.put(url, data=data_tobe_updated, headers=device_headers)
    if r.status_code == "200":
        return "success"
    else:
        return "failed" + r.text

def delete_data(data_type, id):
    """delete an entity by id.  Supported data_types are USER, DEVICE, POLICY, ZONE"""
    """ First check if auth token is about to expire and refresh if necessary """
    global auth_token, device_headers
    if timeout_datetime < datetime.utcnow():  # need to auth/re-auth
        logging.info("timeout exceeded, need to renew auth token")
        auth_token = get_token()
    # Build URL from function and region
    if data_type in { 'USERS', 'DEVICES', 'POLICY', 'ZONE' }:
        url = URLS['BASE_URL'] + region + URLS[data_type] + "/" + id
    else: 
        return "bad data_type: " + data_type + " for delete_data"
    r = requests.delete(url, header=device_headers)
    if r.code == "200":
        return "success"
    else:
        return "failed"


def filter_data(data, filters):
    """Take a results set and match on all filters (i.e. AND not OR)"""
    """This is currently case sensitive, need to move to regex or something to make it case insensitive"""
    filter = dict()
    f = filters.split(',')
    for token in f:
        pieces = token.split('=')
        filter[pieces[0]] = pieces[1]
    for key,val in filter.items():
        # print " key = " + key + " val = " + val
        data = data[data[key].str.contains(val, case=False)]
    return data

def field_data(data, fields):
    """Strip data down to just fields requested and in the order requested"""
    # TODO: fields seem to be in arbitrary order, make sure they come out are in the order requested
    all_fields = data.columns.values.tolist()
    target_fields = fields.split(",")
    target_field_count = len(fields)
    for col in all_fields:
        bar = 0
        # go through all target fields and delete the column if no matches
        for field in target_fields:
            if col == field:
              bar += 1
        if bar < 1:
            data.pop(col)
    return data

def write_to_file(data, filename):
    """"Write the results to file based on extension"""
    # print "writing to " + filename
    ext = os.path.splitext(filename)[1][1:].strip().lower() 
    if ext == "json":
        with open(filename, 'w') as outfile:
            outfile.write(data.to_json(orient='records', lines=True))
    if ext == "csv":
        # Need to flatten this data out, nested attributes mess up dumping to csv.  Need to format or strip fields that contain hashes not strings
        out = open(filename, 'w')
        data.to_csv(out, header=True, index=False, encoding='utf-8')
        out.close()
        """ Should return success or failure"""

def convert_unicode_to_utf8(input):
    if isinstance(input, dict):
        return {convert_unicode_to_utf8(key): convert_unicode_to_utf8(value)
                for key, value in input.iteritems()}
    elif isinstance(input, list):
        return [convert_unicode_to_utf8(element) for element in input]
    elif isinstance(input, unicode):
        return input.encode('utf-8')
    else:
        return input

def get_token():
    # get jwt token
    global creds, auth_token, device_headers
    global timeout_datetime
    timeout = 1800  # 30 minutes from now
    now = datetime.utcnow()
    timeout_datetime = now + timedelta(seconds=timeout)
    epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
    epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
    jti_val = str(uuid.uuid4())
    tid_val = creds['tenant']
    app_id = creds['app_id']
    app_secret = creds['app_secret']
    claims = {
        "exp": epoch_timeout,
        "iat": epoch_time,
        "iss": "http://cylance.com",
        "sub": app_id,
        "tid": tid_val,
        "jti": jti_val
        # The following is optional and is being noted here as an example on how one can restrict
        # the list of scopes being requested
        # "scp": "policy:create, policy:list, policy:read, policy:update"
    }
    encoded = jwt.encode(claims, app_secret, algorithm='HS256')
    payload = {"auth_token": encoded}
    headers = {"Content-Type": "application/json; charset=utf-8"}
    resp = requests.post(URLS['BASE_URL'] + creds['region'] + URLS['AUTH_URL'], headers=headers, data=json.dumps(payload))
    auth_token = json.loads(resp.text)['access_token']  # access_token to be passed to GET request
    device_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + str(auth_token)}
    return auth_token

if __name__ == '__main__':
    # need something here
    print "Use import cylance in your script"
    print "Uasge:"
    print "set_creds(tenant, app_id, app_secret, [region])"
    print "set_region(region)  (optional, default=US)"
    print "get_token()"
    print "Now you can use all the functions like get_data(USERS) etc"
    print "lib takes care of passing auth token to server, renewing token when it expires"


