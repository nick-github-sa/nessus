#!/usr/bin/python
import requests, json, time, urllib3
import csv
import pandas as pd

# Variables
nessusBaseURL="https://x.x.x.x"
nessusUsername="xxxxxxxxxxx"
nessusPassword="xxxxxxxxxxx"
upToThisManyDaysAgo=15
folderID = 3
sleepPeriod = 5

# Turn off TLS warnings
urllib3.disable_warnings()

# Grab the token
URL=nessusBaseURL+"/session"
TOKENPARAMS = {'username':nessusUsername, 'password':nessusPassword}
r = requests.post(url = URL, data = TOKENPARAMS, verify = False)
jsonData = r.json()
token = str("token="+jsonData['token'])

# Look for scans from upToThisManyDaysAgo from GET /scans request
epochTime = time.time()
lastDay = str(epochTime - ( 60 * 60 * 24 * upToThisManyDaysAgo))
splitDay = lastDay.split('.',-1)
URL = nessusBaseURL+"/scans?folder_id="+str(folderID)+"&last_modification_date="+splitDay[0]
headers = {'X-Cookie': token, 'Content-type': 'application/json', 'Accept': 'text/plain'}
t = requests.get(url = URL, headers=headers, verify = False)
data = t.json()

# Cycle through the scans from upToThisManyDaysAgo looking for ones that have been completed and add them to a list
scanIDs = []
for line in data['scans']:
    if line['status'] == 'completed':
        scanIDs.append([line['id'],line['name']])

# Write to CSV file
f = open('newfilecritical.csv', "w")
writer = csv.writer(f, delimiter = ' ')

# Main loop for the program
for listID in scanIDs:
    ID = listID[0]
    NAME = str(listID[1])

    # Call the POST /export function to collect details for each scan
    URL = nessusBaseURL+"/scans/"+str(ID)+"/export"

    # In this case, we're asking for a:
    #   - CSV export
    #   - Only requesting certain fields
    #   - Severity = 3 (aka High) only
    payload = {
        "format": "csv",
        "reportContents": {
            "csvColumns": {
                "id": False,
                "cve": False,
                "cvss": True,
                "risk": True,
                "hostname": True,
                "protocol": False,
                "port": False,
                "plugin_name": False,
                "synopsis": False,
                "description": False,
                "solution": False,
                "see_also": False,
                "plugin_output": False,
                "stig_severity": False,
                "cvss3_base_score": False,
                "cvss_temporal_score": False,
                "cvss3_temporal_score": False,
                "risk_factor": False,
                "references": False,
                "plugin_information": False,
                "exploitable_with": False
            }
        },
        "extraFilters": {
            "host_ids": [],
            "plugin_ids": []
        },
        "filter.0.quality": "eq",
        "filter.0.filter": "severity",
        "filter.0.value": 4
    }

    # Pass the POST request in json format. Two items are returned, file and token
    jsonPayload = json.dumps(payload)
    r = requests.post(url = URL, headers=headers, data = jsonPayload, verify = False)
    jsonData = r.json()
    scanFile = str(jsonData['file'])
    scanToken = str(jsonData['token'])

    # Use the file just received and check to see if it's 'ready', otherwise sleep for sleepPeriod seconds and try again
    status = "loading"
    while status != 'ready':
        URL = nessusBaseURL+"/scans/"+str(ID)+"/export/"+scanFile+"/status"
        t = requests.get(url = URL, headers=headers, verify = False)
        data = t.json()
        if data['status'] == 'ready':
            status = 'ready'
        else:
            time.sleep(sleepPeriod)

    # Now that the report is ready, download
    URL = nessusBaseURL+"/scans/"+str(ID)+"/export/"+scanFile+"/download"
    d = requests.get(url = URL, headers=headers, verify = False)
    dataBack = d.text

    # Clean up the CSV data
    csvData = dataBack.split('\r\n')
    NAMECLEAN=NAME.replace('/','-',-1)
    print("-----------------------------------------------")
    print("Starting  "+NAMECLEAN)
    for line in csvData:
        writer.writerow(line.replace('"','').replace(' ', ''))
    print("Completed "+NAMECLEAN)

f.close()

