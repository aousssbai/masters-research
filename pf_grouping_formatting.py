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

#===========================================================PF==========================================================================
#we check if the csv file is empty
df = pd.read_csv('pf.csv') 
if (df.empty):
    exit()


#here we need to open the csv file and convert it into a dict 
pf_data = []
reader = csv.DictReader(open('pf.csv'))
for row in reader:
    pf_data.append(row)



#now we gather the logs by connection
list1=[]
temp1=[]

for i in pf_data:
    if i['event'] == "AUTHN_ATTEMPT":
        temp1.append(i)
    else:
        if temp1:
            list1.append(temp1)
            temp1=[]
if temp1:
    list1.append(temp1)
    temp1=[]

        
list2=[]
temp2=[]

for i in pf_data:
    if i['event'] != "AUTHN_ATTEMPT":
        temp2.append(i)
    else:
        if temp2:
            list2.append(temp2)
            temp2=[]
if temp2:
    list2.append(temp2)
    temp2=[]

finalList=[]

if list1 and not list2:
    finalList = list1
elif list2 and not list1:
    finalList = list2
elif len(list1) == len(list2):
    for i in range (0,len(list1)):
        finalList.append(list1[i]+list2[i])
elif len(list1)>len(list2):
    for i in range (0,len(list2)):
        finalList.append(list1[i]+list2[i])
    for i in range(len(list2), len(list1)):
        finalList.append(list1[i])
else: 
    for i in range (0,len(list1)):
        finalList.append(list1[i]+list2[i])
    for i in range(len(list1), len(list2)):
        finalList.append(list2[i])


    
PF = finalList 



for PFconnection in PF:
    PFconnection[0]['transaction_time'] = PFconnection[0]['transaction_time'][:23]
    old = list(PFconnection[0]['transaction_time'])
    old[19] = '.'
    old[10] = ' '
    PFconnection[0]['transaction_time'] = "".join(old)


#now we need to "clean" the data aka translating all categorical fields into numerical values
datetimeFormat   = '%Y-%m-%d %H:%M:%S.%f'
finalEncodedLogs = []
finalStats       = []
user             = "aosbai"



#============== in this part we focus on computing the general stats of the connection for the global analysis =================
for connection in PF:
    totalRT           = 0
    topClient         = ""
    time              = 0
    stats             = {}
    protocols         = {}
    clients           = {}
    events            = {}
    successCount      = 0
    countAuthnAttempt = 0
    countOAuth        = 0
    countSSO          = 0
    countSAML20       = 0
    countWSFED        = 0
    countOIDC         = 0
    countOAuth20      = 0
    allClients        = []
    allProtocols      = []
    allEvents         = []
    allStatus         = []
    
    

    for log in connection:
        totalRT += int(log["responsetime"])
        
        if log["event"] == "AUTHN_ATTEMPT":
            countAuthnAttempt += 1
        elif log["event"] == "OAuth":
            countOAuth += 1
        elif log["event"] == "SSO":
            countSSO += 1
            
        
        if log["protocol"] == "SAML20":
            countSAML20 += 1
        elif log["protocol"] == "WSFED":
            countWSFED += 1
        elif log["protocol"] == "OIDC":
            countOIDC += 1
        else:
            countOAuth20 += 1
            
            
            
        stats["time"] = log["date_hour"]
        if log['clientip'] not in clients:
            clients[log['clientip']] = 1
        else: 
            clients[log['clientip']]+=1
        
        if log['status'] == "success":
            successCount += 1
       
            
            
            
        
        #from now we encode all the logs of the connection into a single line 
        
        log.pop("TID")
        log.pop("subject")
        log.pop("responsetime")
        log.pop("transaction_time")
        
        unknownClients = []
        
        refValues = {}
        refValues['topClients'] = []
        refValues['events']  = ["OAuth","AUTHN_ATTEMPT","SSO", "STS","SLO"]
        refValues['protocols']     = ['OIDC','SAML20','OAuth20','WSFED', "WSTrust", "SAML11"]
        
        # series = pd.Series(log) 
        
        # nullCount = series.isnull()

        if log['clientip'] in refValues['topClients']:
            log['clientip'] = refValues['topClients'].index(log['clientip'])+1
        else: 
            unknownClients.append(log['clientip'])
            log['clientip'] = unknownClients.index(log['clientip'])+11
            
        
        if str(log['protocol'])!="":
            log['protocol'] = refValues['protocols'].index(log['protocol'])+1
        
        
       
        log['event'] = refValues['events'].index(log['event'])+1
        
        
        if log['status'] == "success":
            log['status'] = 0
        else: 
            log['status'] = 1
        
    #compute the stats of the connection
    stats['averageResponseTime'] = totalRT/len(connection)  
    
    count=0      
    for key in clients: 
        if clients[key] > count:
            count     = clients[key]
            topClient = key

    stats["topClient"]      = topClient
    stats['#ofLogs']        = len(connection)
    events["OAuth"]         = (countOAuth/len(connection))*100
    events["SSO"]           = (countSSO/len(connection))*100
    events["AUTHN_ATTEMPT"] = (countAuthnAttempt/len(connection))*100
    protocols["OIDC"]       = (countOIDC/len(connection))*100
    protocols["WSFED"]      = (countWSFED/len(connection))*100
    protocols["SAML20"]     = (countSAML20/len(connection))*100
    protocols["OAuth20"]    = (countOAuth20/len(connection))*100
    stats["events"]         = events
    stats["protocols"]      = protocols
    stats["status"]         = (successCount/len(connection))*100
    
    finalStats.append(stats)
        
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
    uniqueLog['clientip']            = ""
    uniqueLog['protocol']            = ""
    uniqueLog['event']               = ""
    uniqueLog['status']              = ""
    uniqueLog['user']                = user
    uniqueLog['time']                = stats['time']
    uniqueLog['averageResponseTime'] = stats['averageResponseTime']


    for log in new_connection:
        uniqueLog['clientip']        = uniqueLog['clientip'] + str(log['clientip'])
        if str(log['protocol'])!="nan":
            uniqueLog['protocol']        = uniqueLog['protocol'] + str(log['protocol'])
        uniqueLog['event']           = uniqueLog['event']    + str(log['event'])
        uniqueLog['status']          = uniqueLog['status']   + str(log['status'])

    finalEncodedLogs.append(uniqueLog) 
 

#now the data is encoded, we send it to the AzureML model and get the prediction score

data =  {

        "Inputs": {},
            "GlobalParameters": {}
    }


for connection in finalEncodedLogs:
   
    
    data["Inputs"]["input1"] = {
            "ColumnNames": ["Column 0", "averageResponseTime", "clientip", "event", "protocol", "status", "time", "user"],
            "Values": [[ unicode(finalEncodedLogs.index(connection)), unicode(connection["averageResponseTime"]), unicode(connection["clientip"]), unicode(connection["event"]), unicode(connection["protocol"]), unicode(connection["status"]), unicode(connection["time"]), unicode(connection["user"])]]
      
        }
    
    body = str.encode(json.dumps(data))

    url = 'https://ussouthcentral.services.azureml.net/workspaces/314d80c302f942f08187131ffd595f24/services/3be788dc66044932862dfb4e12c7a8fa/execute?api-version=2.0&details=true'
    api_key = 'H8wEUvp7txlmaMldsCbM+SA8QAczrBYej2K3Kmh1TNMy46FiWht+3hNqRHeuvePOgL3txWVhUcgRHidHTd1g4w=='
    headers = {'Content-Type':'application/json', 'Authorization':('Bearer '+ api_key)}


            
    r = requests.post(url, data=json.dumps(data), headers=headers)
    response = json.loads(r.content)


    if response["Results"]["output1"]["value"]["Values"][0][10] == "1":
        with open('scores.csv', 'r+b') as f:
            header = next(csv.reader(f))
            dict_writer = csv.DictWriter(f, header, -999)
            dict_writer.writerow({'source':'pf','output':'1','confidence':unicode(float(response["Results"]["output1"]["value"]["Values"][0][9])*0.769)})

    else: 
        with open('scores.csv', 'r+b') as f:
            header = next(csv.reader(f))
            dict_writer = csv.DictWriter(f, header, -999)
            dict_writer.writerow({'source':'pf','output':'0','confidence':unicode(float(response["Results"]["output1"]["value"]["Values"][0][8])*0.998)})    



f = open("pf.csv", "w+")
f.close()


with open('pf.csv','a') as fd:
    fd.write("status,date_hour,protocol,transaction_time,responsetime,TID,clientip,event,subject")
    fd.write("\n")


