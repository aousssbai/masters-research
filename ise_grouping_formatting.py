from ipaddress import ip_address
from time import time
import requests
import itertools

from pandas import read_csv
import numpy
import json
import pandas as pd 
import ipaddress 
import re
import csv
import urllib2
import ssl

#we check if the csv file is empty
df = pd.read_csv('ise.csv') 
if (df.empty):
    exit()


#here we need to open the csv file and convert it into a dict 
ise_data = []
reader = csv.DictReader(open('ise.csv'))
for row in reader:
    ise_data.append(row)

#now we need to "clean" the data aka translating all categorical fields into numerical values

for connection in ise_data:

    #replace usernames with 0 and 1
    connection["UserName"] = 0

    #convert all Addresses to int
    connection["Address"] =  int(ipaddress.IPv4Address(unicode(connection["Address"])))

    #convert callingID from hex to int
    for letter in connection["Calling_Station_ID"]:
        if letter =='-' or letter == '.':
            connection["Calling_Station_ID"] = connection["Calling_Station_ID"].replace(letter,'')
    connection["Calling_Station_ID"] = int(connection["Calling_Station_ID"],16)

    #convert device types
    if connection["Device_Type"] == "Device Type#All Device Types#WLC":
        connection["Device_Type"] = 1

    elif connection["Device_Type"] == "Device Type#All Device Types#WS-C4510RE":
        connection["Device_Type"] = 2

    elif connection["Device_Type"] == "Device Type#All Device Types":
        connection["Device_Type"] = 3

    elif connection["Device_Type"] == "Device Type#All Device Types#C800":
        connection["Device_Type"] = 4

    elif connection["Device_Type"] == "Device Type#All Device Types#WS-C3850-48P":
        connection["Device_Type"] = 5

    else:
        connection["Device_Type"] = 6

    #convert locations
    if connection["Location"] == "Location#All Locations#US West#UNITED STATES#SAN JOSE#SJC12":
        connection["Location"] = 1

    elif connection["Location"] == "Location#All Locations#US West#UNITED STATES#SAN JOSE#SJCQ":
        connection["Location"] = 2

    elif connection["Location"] == "Location#All Locations#US West#UNITED STATES#SAN JOSE#SJC17":
        connection["Location"] = 3

    elif connection["Location"] == "Location#All Locations#US West#UNITED STATES#SAN JOSE#SJC05":
        connection["Location"] = 4

    elif connection["Location"] == "Location#All Locations#US West#UNITED STATES#SAN JOSE#SJC02":
        connection["Location"] = 5

    elif connection["Location"] == "Location#All Locations#CVO":
        connection["Location"] = 6

    elif connection["Location"] == "Location#All Locations#All Locations":
        connection["Location"] = 7

    elif connection["Location"] == "Location#All Locations#US West":
        connection["Location"] = 8

    elif connection["Location"] == "Location#All Locations#EMEA":
        connection["Location"] = 9

    else: 
        connection["Location"] = 10

#convert message class
    if connection["MESSAGE_CLASS"] == "Passed-Authentication":
        connection["MESSAGE_CLASS"] = 1
    elif connection["MESSAGE_CLASS"] == "RADIUS":
        connection["MESSAGE_CLASS"] = 2 
    elif connection["MESSAGE_CLASS"] == "Failed-Attempt":
        connection["MESSAGE_CLASS"] = 3 
    elif connection["MESSAGE_CLASS"] == "MDM":
        connection["MESSAGE_CLASS"] = 4 
    elif connection["MESSAGE_CLASS"] == "Radius-Token":
        connection["MESSAGE_CLASS"] = 5 
    elif connection["MESSAGE_CLASS"] == "Radius-Accounting":
        connection["MESSAGE_CLASS"] = 6 
    elif connection["MESSAGE_CLASS"] == "Guest":
        connection["MESSAGE_CLASS"] = 7 
    elif connection["MESSAGE_CLASS"] == "Posture":
        connection["MESSAGE_CLASS"] = 8 
    elif connection["MESSAGE_CLASS"] == "System-Management":
        connection["MESSAGE_CLASS"] = 9 
    elif connection["MESSAGE_CLASS"] == "EAP-TLS":
        connection["MESSAGE_CLASS"] = 10 
    else:
        connection["MESSAGE_CLASS"] = 11

#convert message text 
    if connection["MESSAGE_TEXT"] == "Authentication succeeded":
        connection["MESSAGE_TEXT"] = 1
    elif connection["MESSAGE_TEXT"] == "Endpoint abandoned EAP session and started new":
        connection["MESSAGE_TEXT"] = 2
    elif connection["MESSAGE_TEXT"] == "Supplicant stopped responding to ISE":
        connection["MESSAGE_TEXT"] = 3
    elif connection["MESSAGE_TEXT"] == "NAS conducted several failed authentications of the same scenario":
        connection["MESSAGE_TEXT"] = 4
    elif connection["MESSAGE_TEXT"] == "Mobile device management compliant":
        connection["MESSAGE_TEXT"] = 5
    elif connection["MESSAGE_TEXT"] == "Authentication against the RADIUS token server failed":
        connection["MESSAGE_TEXT"] = 6
    elif connection["MESSAGE_TEXT"] == "Endpoint conducted several failed authentications of the same scenario":
        connection["MESSAGE_TEXT"] = 7
    elif connection["MESSAGE_TEXT"] == "Authentication failed":
        connection["MESSAGE_TEXT"] = 8
    elif connection["MESSAGE_TEXT"] == "RADIUS Accounting watchdog update":
        connection["MESSAGE_TEXT"] = 9
    elif connection["MESSAGE_TEXT"] == "RADIUS Accounting start request":
        connection["MESSAGE_TEXT"] = 10
    else:
        connection["MESSAGE_TEXT"] = 11

#convert NAS_PORT_TYPE
    if connection["NAS_Port_Type"] == "Wireless - IEEE 802.11":
        connection["NAS_Port_Type"] = 1
    elif connection["NAS_Port_Type"] == "Ethernet":
        connection["NAS_Port_Type"] = 2
    elif connection["NAS_Port_Type"] == "Virtual":
        connection["NAS_Port_Type"] = 3
    else:
        connection["NAS_Port_Type"] = 4

#convert Timestamp
    connection["Real_Time_Stamp"] = re.sub("[^0-9]", " ", connection["Real_Time_Stamp"][:22])
    connection["Real_Time_Stamp"] = connection["Real_Time_Stamp"].replace(" ", "")  

    

#now the data is encoded, we send it to the AzureML model and get the prediction score

data =  {

        "Inputs": {},
            "GlobalParameters": {}
    }



for connection in ise_data:
   
    
    data["Inputs"]["input1"] = {
            "ColumnNames": ["Column 0", "Address", "Calling_Station_ID", "Device_Type", "Location", "MESSAGE_CLASS", "MESSAGE_CODE", "MESSAGE_TEXT", "NAS_Port_Type", "NAS_Port", "Real_Time_Stamp", "RequestLatency", "UserName"],
            "Values": [[ unicode(ise_data.index(connection)), unicode(connection["Address"]), unicode(connection["Calling_Station_ID"]), unicode(connection["Device_Type"]), unicode(connection["Location"]), unicode(connection["MESSAGE_CLASS"]), unicode(connection["MESSAGE_CODE"]), unicode(connection["MESSAGE_TEXT"]), unicode(connection["NAS_Port_Type"]), unicode(connection["NAS_Port"]), unicode(connection["Real_Time_Stamp"]), unicode(connection["RequestLatency"]), unicode(connection["UserName"]) ] ]
      
        }
    
    body = str.encode(json.dumps(data))

    url = 'URL_OF_THE_DEPLOYED_MODEL'
    api_key = 'YOUR_API_KEY'
    headers = {'Content-Type':'application/json', 'Authorization':('Bearer '+ api_key)}


            
    r = requests.post(url, data=json.dumps(data), headers=headers)
    response = json.loads(r.content)

    if response["Results"]["output1"]["value"]["Values"][0][15] == "1":
        with open('scores.csv','a') as fd:
            fd.write("ise,1,"+unicode(float(response["Results"]["output1"]["value"]["Values"][0][14])*0.929))
         

    else: 
        with open('scores.csv','a') as fd:
            fd.write("ise,0,"+unicode(float(response["Results"]["output1"]["value"]["Values"][0][13])*0.99))    



f = open("ise.csv", "w+")
f.close()

with open('ise.csv','a') as fd:
    fd.write("UserName,Calling_Station_ID,MESSAGE_TEXT,MESSAGE_CLASS,NAS_Port_Type,RequestLatency,MESSAGE_CODE,NAS_Port,Location,Device_Type,Address,Real_Time_Stamp")
    fd.write("\n")
