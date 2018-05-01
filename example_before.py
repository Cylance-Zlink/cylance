import jwt  # PyJWT version 1.6.1 as of the time of authoring
import uuid
import requests  # requests version 2.18.4 as of the time of authoring
import json
import sys
import time
from time import gmtime, strftime, sleep
from datetime import datetime, timedelta

# Script to get device list avery 60 seconds

# CONFIGURATION
tenant = ""         # Tenant ID
app = ""            # Application ID
secret = ""         # Application Secret

# ***** PART 1 - GENERATE JWT TOKEN ***** #

def main_loop():
    # ***** START - AUTH API CONFIGURATION ***** #
    timeout = 1800  # 30 minutes from now
    now = datetime.utcnow()
    timeout_datetime = now + timedelta(seconds=timeout)
    epoch_time = int((now - datetime(1970, 1, 1)).total_seconds())
    epoch_timeout = int((timeout_datetime - datetime(1970, 1, 1)).total_seconds())
    jti_val = str(uuid.uuid4())
    tid_val = tenant
    app_id = app
    app_secret = secret
    AUTH_URL = "https://protectapi.cylance.com/auth/v2/token"
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
    resp = requests.post(AUTH_URL, headers=headers, data=json.dumps(payload))
    # ***** END - AUTH API CONFIGURATION ***** #

    jwt_token = json.loads(resp.text)['access_token']  # access_token to be passed to GET request

# ***** PART 2 - GET DEVICES  ***** #
    device_id = "INSERT DEVICE ID"  # Device ID obtained from Cylance console
    GETDEVICES_URL = "https://protectapi.cylance.com/devices/v2/?page_size=200"
    device_headers = {"Content-Type": "application/json; charset=utf-8", "Authorization": "Bearer " + str(jwt_token)}

    # Get 1st page of data
    r = requests.get(GETDEVICES_URL, headers=device_headers)
    json_data = json.loads(r.text)
    results = {'page_items':[]}
    results['page_items'] = json_data['page_items']

    # If there are multiple pages, go ahead and pull them in too
    pages = json_data['total_pages']
    if pages > 1:
        for x in range (2, pages + 1):
            r = requests.get(GETDEVICES_URL + "&page=" + str(x), headers=device_headers)
            json_data = json.loads(r.text)
            results['page_items'] = results['page_items'] + json_data['page_items']
    print results

while True:
    main_loop()
    time.sleep(60)
