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

""" USE CASES """


""" TODO LIST """
""" Not checking a lot of input params, need to add that """
""" Make get_data_by_id function return multiplae pages of data just like get_data function, actually, probabyly just merge the 2 functions by adding id as an optional parameter in get_data()"""
""" Search for TODO in the code """

""" GLOBAL PARAMS """
creds = {
    "tenant": "",
    "app_id": "",
    "app_secret": "",
    "region": ""
}
#tenant = ""
#app_id = ""
#app_secret =""
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
region = "" 
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

def load_creds(file):
    # get saved creds if they exist
    global creds
    print "loading creds"
    with open(file) as infile:
        creds = json.load(infile)

def save_creds(file=""):
    # save creds
    # TODO: retuen success or fail
    global creds
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
    """  <filter1=value,filterN=value> <fields=field1,fieldN> <file=outputfile.json|.csv> """
    """  e.g. filter1=aaa,filter2=bbb fields=email,first_name,last_name file=users.csv"""

    """ First check if auth token is about to expire and refresh if necessary """
    global auth_token, device_headers
    if timeout_datetime < datetime.utcnow():  # need to auth/re-auth
        auth_token = get_token()
    # Build URL from function and region
    url = URLS['BASE_URL'] + creds['region'] + URLS[data_type]

    # function variables
    file = ""
    filters = ""
    fields = ""
    args_sections = args.split(" ")
    # TODO - bug if file and/or fields are passed with no filter...
    if len(args_sections) > 0:
        filters = args_sections[0]
    if len(args_sections) > 1:
        # Find fields and/or file
        a = args_sections[1].split("=")
        if a[0] == "fields":
            fields = a[1]
        elif a[0] == "file":
            file = a[1]
    if len(args_sections) > 2:
        # Find fields and/or file
        a = args_sections[2].split("=")
        if a[0] == "fields":
            fields = a[1]
        elif a[0] == "file":
            file = a[1]
    # Get 1st page of data
    r = requests.get(url + "?page_size=" + str(PAGE_SIZE), headers=device_headers)
    json_data = json.loads(r.text)
    rows = {'page_items':[]}
    rows['page_items'] = json_data['page_items']
    # If there are multiple pages, go ahead and pull them in too
    pages = json_data['total_pages']
    if pages > 1:
        for x in range (2, pages + 1):
            r = requests.get(url + "?page_size=" + str(PAGE_SIZE) + "&page=" + str(x), headers=device_headers)
            json_data = json.loads(r.text)
            rows['page_items'] = rows['page_items'] + json_data['page_items']

    # Use pandas dataframe to manipulate data
    df = pd.DataFrame.from_dict(rows['page_items'])
    print "#### DESCRIBE DATAFRAME ####"
    print df.dtypes.index

    # If there are filters defined, run them
    if filters != "":
        df = filter_data(df, filters)

    # If desired fields are defined, run them
    print " fields = " + fields
    if fields != "":
        print "Fields defined, need to remove unwanted fields"
        #filter and order fields
        df = field_data(df, fields)

    # If an output file is defined, go ahead and write to file
    if file != "":
        # Write data to file based on extension
        write_to_file(df, file)

    # return rows
    return df

def get_data_by_id(data_type, id, args=""):
    """ Gets data for a specific ID.  Data_types supported: USERS, DEVICES, DEVICETHREATS, ZONEDEVICES, POLICIES, ZONES, THREATS, THREATDEVICES, and THREATDOWNLOADS."""
    """ standard args for filtering, fields and file output"""
    """ First check if auth token is about to expire and refresh if necessary """
    global auth_token, device_headers
    if timeout_datetime < datetime.utcnow():  # need to auth/re-auth
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
        auth_token = get_token()
    # Build URL from function and region
    if data_type in { 'USER', 'DEVICE', 'POLICY', 'ZONE' }:
        url = URLS['BASE_URL'] + region + URLS[data_type] + "/" + id
    else:
        return "bad data_type: " + data_type + " for update_data"
    r = requests.put(url, header=device_headers)
    if r.code == "200":
        return "success"
    else:
        return "failed"

def delete_data(data_type, id):
    """delete an entity by id.  Supported data_types are USER, DEVICE, POLICY, ZONE"""
    """ First check if auth token is about to expire and refresh if necessary """
    global auth_token, device_headers
    if timeout_datetime < datetime.utcnow():  # need to auth/re-auth
        auth_token = get_token()
    # Build URL from function and region
    if data_type in { 'USER', 'DEVICE', 'POLICY', 'ZONE' }:
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
        print " key = " + key + " val = " + val
        data = data[data[key].str.contains(val, case=False)]
    return data

def field_data(data, fields):
    """Strip data down to just fields requested and in the order requested"""
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
    resp = requests.post(URLS['BASE_URL'] + region + URLS['AUTH_URL'], headers=headers, data=json.dumps(payload))
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


