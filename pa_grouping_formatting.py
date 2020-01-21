from ipaddress import ip_address
import time
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
from datetime import datetime
datetimeFormat = '%Y-%m-%d %H:%M:%S'

#===========================================================PF==========================================================================
#we check if the csv file is empty
df = pd.read_csv('pa.csv') 
if (df.empty):
    exit()

for index, row in df.iterrows():
    df['_time'][index] = datetime.strptime(unicode(time.strftime(datetimeFormat, time.localtime(row['_time']))), datetimeFormat)

df = df.sort_values(by='_time', ascending=True)

allTimes = []
for index, row in df.iterrows():
    allTimes.append(df['_time'][index])



#now we gather the logs by connection
temp=[]
final=[]
count=1
for index, row in df.iterrows():
    temp.append(row)
    if index<len(df)-1 and count<len(allTimes):
        diff = allTimes[count] - row['_time']
        if diff.seconds>120:
            final.append(temp)
            temp=[]
    count+=1

if temp:
    final.append(temp)
    temp=[]




#now we need to "clean" the data aka translating all categorical fields into numerical values

finalEncodedLogs = []
finalStats = []


#============================== in this part we focus on computing the general stats of the connection for the global analysis =================
for connection in final:
    applications   = []
    resources      = []
    clients        = []
    logs           = []
    roundTrips     = []
    totalRT        = 0
    totalRC        = 0
    stats          = {}
    allApps        = {}
    allResources   = {}
    allAuthMechs   = {}
    topApp         = ""
    topResource    = ""
    topAuthMech    = ""
    user = "aosbai"
    stats['clients'] = []
    
    
    for log in connection:
        totalRT+= int(log["roundTripMS"])
        totalRC+= int(log["responseCode"])
        if log['applicationName'] not in allApps:
            allApps[log['applicationName']] = 0
        else: 
            allApps[log['applicationName']]+=1
        if log['resource'] not in allResources:
            allResources[log['resource']] = 0
        else: 
            allResources[log['resource']]+=1
        if log['authMech'] not in allAuthMechs:
            allAuthMechs[log['authMech']] = 0
        else: 
            allAuthMechs[log['authMech']]+=1
        stats['hour']    = log["_time"].hour
        
        if log['client'] not in stats['clients']:
            stats['clients'].append(log['client'])

    stats['averageRoundTrip'] = totalRT/len(connection)
    stats['responseCodeAverage'] = totalRC/len(connection)

    count=0      
    for key in allApps: 
        if allApps[key]>count:
            count= allApps[key]
            topApp = key

    count=0      
    for key in allResources: 
        if allResources[key]>count:
            count= allResources[key]
            topResource = key

    count=0      
    for key in allAuthMechs: 
        if allAuthMechs[key]>count:
            count= allAuthMechs[key]
            topAuthMech = key


    stats['topApp']      = topApp 
    stats['topResource'] = topResource
    stats['topAuthMech'] = topAuthMech

    stats['#ofLogs']     = len(connection)
    
    

    finalStats.append(stats)

    #============================== here we enter the reference value for the global analysis ===============================

    refValues = {}
    refValues['top10Apps']      = ["CAEAIprod-directory","CAEAXprod-learn","CAEAIprod-wampmt","CAEAXprod-taclearning","CDCprod-www","CAEAXprod-mymobile","CAEAXprod-mymobilesetup","CAEAIprod-myid","CAEAXprod-askeva","CAEAIprod-API-myid-api"]
    refValues['top10Resrouces'] = ["learn.cisco.com [] / /*:443","directory.cisco.com [] / /dir/dwr/*:443","wampmt.cisco.com [] / /*:443","taclearning.cisco.com [] / /*:443","directory.cisco.com [] / /*:443","mymobile.cisco.com [] / /*:443","wwwin.cisco.com [] / /c/dam/cec/*:443","mymobilesetup.cisco.com [] / /*:443","myid.cisco.com [] / /*:443","wwwin.cisco.com [] / /etc/*:443"]
    refValues['topAuthMech']    = ["Cookie","OAuth"]
    refValues['topClients']     = ["72.163.10.116","173.37.20.60","72.163.25.187","173.37.26.104","173.37.149.116","173.37.111.62","173.37.111.53","173.37.111.55","173.37.111.38","173.37.111.41"]
    refValues['responseCode']   = 277
    refValues['avgRoundTrip']   = 32.77619342839429
    refValues['top10Hours']     = [17,16,18,15,21,11,13,8,20,12]
    refValues['average#logs']   = 7.933333333333334


    #==============================in this part we remove all the non necessary fields and we encode the connection ======================



    uhknownApps      = []
    unknownResources = []
    unknownClients   = []

    #encode with unique ID
    for log in connection:
        
        log.pop('subject')
        log.pop('trackingId')
        log.pop('responseCode')
        log.pop('roundTripMS')
        log.pop('authMech')
        

        if log['applicationName'] in refValues['top10Apps']:
            log['applicationName'] = refValues['top10Apps'].index(log['applicationName'])+1
        else: 
            uhknownApps.append(log['applicationName'])
            log['applicationName'] = uhknownApps.index(log['applicationName'])+11
            
        
        if log['resource'] in refValues['top10Resrouces']:
            log['resource'] = refValues['top10Resrouces'].index(log['resource'])+1
        else: 
            unknownResources.append(log['resource'])
            log['resource'] = unknownResources.index(log['resource'])+11
            
        
        if log['client'] in refValues['topClients']:
            log['client'] = refValues['topClients'].index(log['client'])+1
        else: 
            unknownClients.append(log['client'])
            log['client'] = unknownClients.index(log['client'])+11
            

    #remove duplicate logs
    seen = set()
    new_connection = []
    for log in connection:
        t = tuple(log.items())
        if t not in seen:
            seen.add(t)
            new_connection.append(log)

    #compress all logs into one encoded log
    uniqueLog = {}
    uniqueLog['resource']           = ""
    uniqueLog['applicationName']    = ""
    uniqueLog['client']             = ""
    uniqueLog['user']               = user
    uniqueLog['time']               = stats['hour']
    uniqueLog['averageRoundTrip']   = stats['averageRoundTrip']


    for log in new_connection:
        uniqueLog['resource']        = uniqueLog['resource'] + str(log['resource'])
        uniqueLog['applicationName'] = uniqueLog['applicationName'] + str(log['applicationName'])
        uniqueLog['client']          = uniqueLog['client'] + str(log['client'])

    finalEncodedLogs.append(uniqueLog)

#now the data is encoded, we send it to the AzureML model and get the prediction score

data =  {

        "Inputs": {},
            "GlobalParameters": {}
    }



for connection in finalEncodedLogs:
   
    
    data["Inputs"]["input1"] = {
            "ColumnNames": ["Column 0", "applicationName", "averageRoundTrip", "client", "resource", "time", "user"],
            "Values": [[ unicode(finalEncodedLogs.index(connection)), unicode(connection["applicationName"]), unicode(connection["averageRoundTrip"]), unicode(connection["client"]), unicode(connection["resource"]), unicode(connection["time"]), unicode(connection["user"])]]
      
        }
    
    body = str.encode(json.dumps(data))

    url = 'https://ussouthcentral.services.azureml.net/workspaces/314d80c302f942f08187131ffd595f24/services/ddc93cef54f0496aa43b13da421b364b/execute?api-version=2.0&details=true'
    api_key = '6TAOM8V0oFTioBg6CmC6MoMOr1H3drCHiuoPVUCfrjo/E2iIx6dpPYfZTcLEY0t2fpn+F3l75yzPutIRDAAWSg=='
    headers = {'Content-Type':'application/json', 'Authorization':('Bearer '+ api_key)}


            
    r = requests.post(url, data=json.dumps(data), headers=headers)
    response = json.loads(r.content)
    

    if response["Results"]["output1"]["value"]["Values"][0][9] == "1":
        
        with open('scores.csv', 'r+b') as f:
            header = next(csv.reader(f))
            dict_writer = csv.DictWriter(f, header, -999)
            dict_writer.writerow({'source':'pa','output':'1','confidence':unicode(float(response["Results"]["output1"]["value"]["Values"][0][8])*0.856)})

        
    else: 
        with open('scores.csv', 'r+b') as f:
            header = next(csv.reader(f))
            dict_writer = csv.DictWriter(f, header, -999)
            dict_writer.writerow({'source':'pa','output':'0','confidence':unicode(float(response["Results"]["output1"]["value"]["Values"][0][7])*0.733)})




f = open("pa.csv", "w+")
f.close()

with open('pa.csv','a') as fd:
    fd.write("applicationName,responseCode,resource,authMech,_time,roundTripMS,client,trackingId,subject")
    fd.write("\n")
