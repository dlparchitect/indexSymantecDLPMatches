"""

indexSymantecDLPMatches.py

PROVIDED AS-IS
The code is a) an example and b) provided as-is, we do not know your computing environment so you need to assess the script’s function and performance before implementing it.



1/ Get a List of Incidents that have not been processed (using a specific Incidents Note as defined by dlpEnforceIncidentNote). 
You can use other artifacts, such as Incident Status. It is possible to control the number 
of Incidents by date or pull a certain number of incidents at a time (up to 10000 as per the API... defined by dlpEnforceIncidentPageSize).
2/ With the incident list, the code makes another call to obtain each's incidents details, 
including the Matches.
3/  The code can make bulk or individual API calls to ElasticSearch or Splunk for indexing.
4/ Once the matches are in ElastiSearch, the code makes another call 
to the DLP Rest API to update the processed incidents by adding a note.


Prerequisites
    indexDLPMatches.py is written in Python 3.8
    Symantec DLP 15.8 MP1
        A Symantec DLP user with API privileges 
    Python 3.8
    json and requests Python modules
    ElasticSearch/Kibana
    Splunk with HEC

References:
https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/15-8/DLP-Enforce-REST-APIs-overview/overview.html

"""

import json
import requests
from requests.auth import HTTPBasicAuth
from requests.structures import CaseInsensitiveDict
from requests.packages import urllib3
import logging
from datetime import datetime


#Symantec DLP parameters
dlpEnforceURLBase = 'https://localhost/ProtectManager/webservices/v2/incidents/'
dlpEnforceURLRestQueryIncidents = ''
dlpEnforceURLRestMatches = '/components/matches'
dlpEnforceUserName = 'Administrator'
dlprEnforcePassword = 'Password'
dlpEnforceIncidentURL = 'https://localhost/ProtectManager/IncidentDetail.do?value(variable_1)=incident.id&value(operator_1)=incident.id_in&value(operand_1)='
dlpEnforceIncidentNote = "Matches Processed"
# dlpEnforceIncidentPageSize controls the number of incidents to display
dlpEnforceIncidentPageSize = 5

#ElasticSearch Parameters
esURL = 'https://192.168.5.197:9200'
esIndex = 'indexdlpmatches'
esHeaders = {"Content-Type": "application/json"}
esTypeIndex = '_doc'
esTypeOp = '_bulk'
esIntBulkNumberofMatches = 1000

#Splunk Parameters
splunkURL = 'https://192.168.5.115:8088/services/collector'
splunkToken = '6d7b8966-c4c4-48c9-b776-ca0db99461c8'
splunkHeaders =  {'Authorization': 'Splunk '+splunkToken}
splunkIndex = 'indexdlpmatches'


headers = CaseInsensitiveDict()
#headers["Authorization"] = "Basic QWRtaW5pc3RyYXRvcjpTeW1jNG5vdyE="
headers["Content-Type"] = "application/json"

#Control variables
#strlistofIncidents stores the list of incidents to proces. 
strlistofIncidents=''
#intViolationsCounter keeps the amount of matches to control when to do a bulk call to ElasticSearch 
intViolationsCounter = 0
#documenttoIndexBulk builds the json body for ElasticSearch indexing bulk call
documenttoIndexBulk=''
#documenttoIndex builds the json body for ElasticSearch indexing one-at-a-time call
documenttoIndex=''
#bolValidateSSL Validate HTTPS certificates
bolValidateSSL = False
#bolLoggingtoFile Log Results to a File
bolLoggingtoFile = True
loggingFile='incidentDLPMatches.log'
#intTotalViolations will hold the total number of violations for logging 
intTotalViolations=0
#bolSplunkIt if you want to send the maches to Splunk
bolSplunkIt = True
#bolElasticSearchIt if you want to send the maches to ElastiSearch line by line. Default false.
bolElasticSearchIt = False
#bolElasticSearchIt if you want to send the maches to ElastiSearch in Bulk. Default True.
bolElasticSearchItBulk = True

#Disable SSL warnings. DO NOT DO THIS IN PRODUCTION.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

if bolLoggingtoFile:
    logging.basicConfig(filename='incidentDLPMatches.log', level=logging.DEBUG)



#Read a list of incidents to report
# The query filters incidents with a Note indicating that they were already processed for Matches extraction
'''
querylistofincidents = """
{
    "select": [
        {"name": "incidentId"},
        {"name": "policyName"},
        {"name": "severityId"},
        {"name": "detectionDate"}     
    ],
    "filter": {
        "filterType": "booleanLogic",
        "booleanOperator": "AND",
        "filters": [
            {
                "filterType": "booleanLogic",
                "booleanOperator": "AND",
                "filters": [
                    {
                        "filterType": "localDateTime",
                        "operandOne": {
                            "name": "messageDate"
                        },
                        "operator": "GTE",
                        "operandTwoValues": [
                            "2020-11-03T00:00:00"
                        ]
                    },
                    {
                        "filterType": "localDateTime",
                        "operandOne": {
                            "name": "messageDate"
                        },
                        "operator": "LTE",
                        "operandTwoValues": [
                            "2021-11-03T23:59:59"
                        ]
                    },
                    {
                        "filterType": "string",
                        "operandOne": {
                            "name": "incidentNote",
                            "function": "UPPER"
                        },
                        "operator": "NOT_LIKE",
                        "operandTwoValues": [
                            "%"""+dlpEnforceIncidentNote+"""%"
                        ]
                    }
                ]
            }
        ]
    },
    "orderBy": [
        {
            "field": {
                "name": "messageDate"
            },
            "order": "ASC"
        }
    ],
    "page": {
        "type": "offset",
        "pageNumber": 1,
        "pageSize": 50
    }
}
"""
'''

querylistofincidents = """
{
    "select": [
        {"name": "incidentId"},
        {"name": "policyName"},
        {"name": "severityId"},
        {"name": "detectionDate"}     
    ],
    "filter": {
        "filterType": "booleanLogic",
        "booleanOperator": "AND",
        "filters": [
            {
                "filterType": "booleanLogic",
                "booleanOperator": "AND",
                "filters": [
                    {
                        "filterType": "string",
                        "operandOne": {
                            "name": "incidentNote",
                            "function": "UPPER"
                        },
                        "operator": "NOT_LIKE",
                        "operandTwoValues": [
                            "%"""+dlpEnforceIncidentNote+"""%"
                        ]
                    }
                ]
            }
        ]
    },
    "orderBy": [
        {
            "field": {
                "name": "messageDate"
            },
            "order": "ASC"
        }
    ],
    "page": {
        "type": "offset",
        "pageNumber": 1,
        "pageSize": """+str(dlpEnforceIncidentPageSize)+"""
    }
}
"""


def indexSplunkIt():
    if bolSplunkIt:
        #Splunk HEC JSON requires a couple of extra fields
        documenttoIndexSplunk = '''{"event":"event", "fields":'''+documenttoIndex+'''}'''
        splunkresp = requests.post(splunkURL, json=json.loads(documenttoIndexSplunk), headers=splunkHeaders, verify=bolValidateSSL)
        #print(splunkresp.text)
        #print(documenttoIndexSplunk)
    
def indexElasticSearchIt():
    if bolElasticSearchIt:
        esresp = requests.post(esURL+'/'+esIndex+'/'+esTypeIndex, json=json.loads(documenttoIndex), headers=esHeaders, verify=bolValidateSSL)
        #print(esresp.text)
        #print(documenttoIndex)
    
def indexElasticSearchItBulk():
    if bolElasticSearchItBulk:
        esresp = requests.post(esURL+'/'+esTypeOp, data=documenttoIndexBulk, headers=esHeaders, verify=bolValidateSSL)
        #print(esresp.text)
        #print(documenttoIndexBulk)
    
def updateDLPIncidentswithNote():
    #Update Incidents with Note "Matches Processed"
    queryupdateIncidents = '''
    {
       "incidentIds":[
       '''+strlistofIncidents+'''
       ],
       "incidentNotes":[
          {
             "note":"'''+dlpEnforceIncidentNote+'''"
          }
       ]
    }'''
    dlpresp = requests.patch(dlpEnforceURLBase, headers=headers, data=queryupdateIncidents, auth=HTTPBasicAuth(dlpEnforceUserName, dlprEnforcePassword), verify=bolValidateSSL)
    #print(dlpresp.status_code)
    #print(dlpresp.content)
    if bolLoggingtoFile:
        logging.debug('Incident processed on ' + str(datetime.now()))
        logging.debug('Total Number of Indexed Matches '+str(intTotalViolations))
        logging.debug(queryupdateIncidents)
        
#Call DLP Rest API to get the list of Incidents. 
dlpresponse = requests.post(dlpEnforceURLBase, headers=headers, data=querylistofincidents, auth=HTTPBasicAuth(dlpEnforceUserName, dlprEnforcePassword), verify=bolValidateSSL)
listofIncidents = json.loads(dlpresponse.content)


for eachIncident in listofIncidents['incidents']:
    #print (eachIncident['incidentId'])
    #This call returns the incident details, including matches
    dlpresponse = requests.get(dlpEnforceURLBase+str(eachIncident['incidentId'])+dlpEnforceURLRestMatches, auth=HTTPBasicAuth(dlpEnforceUserName, dlprEnforcePassword), verify=bolValidateSSL)

    #Build the list of Incidents for updating Notes
    strlistofIncidents = strlistofIncidents+','+str(eachIncident['incidentId'])

    #Load matches from JSON
    incidentmatches = json.loads(dlpresponse.content)

    #Loop through the number of message Components (messageComponentId)
    for incidentdatacomponent in incidentmatches:
        #Loop through the violations in each component (violations)
        for incidentviolations in incidentdatacomponent['violations']:
            #Loop through the violation segments in each violation (violationSegments)
            for incidentviolationsSegment in incidentviolations['violationSegments']:
                if incidentviolationsSegment['segmentType']=='VIOLATING_CONTENT':
                    #Builds the JSON objects according to ElasticSearch Bulk API format (not fun)
                    documenttoIndexBulk = documenttoIndexBulk+'''{"index": { "_index": "'''+esIndex+'''"} }\n{"incidentId": "'''+str(eachIncident['incidentId'])+'''", "policyName": "'''+str(eachIncident['policyName'])+'''", "ruleName": "'''+str(incidentviolationsSegment['ruleName'])+'''","enforceURL": "'''+dlpEnforceIncidentURL+str(eachIncident['incidentId'])+'''", "detectionDate": "'''+str(eachIncident['detectionDate'])+'''","incidentSeverity": "'''+str(eachIncident['severityId'])+'''", "incidentMatches": "'''+str(incidentviolationsSegment['text'])+'''"}\n'''
                    intTotalViolations = intTotalViolations + 1
                    intViolationsCounter = intViolationsCounter + 1
                    #When we have the esIntBulkNumberofMatches, this code calls the Bulk API
                    if intViolationsCounter == esIntBulkNumberofMatches:
                        #print ("Bulk in the for loop")
                        #r = requests.post(esURL+'/'+esTypeOp, data=documenttoIndexBulk, headers=esHeaders, verify=bolValidateSSL)
                        indexElasticSearchItBulk()
                        intViolationsCounter = 0
                        documenttoIndexBulk = ''
                    
                    
                    #SplunkIt
                    documenttoIndex = '''{"incidentId": "'''+str(eachIncident['incidentId'])+'''", "policyName": "'''+str(eachIncident['policyName'])+'''", "ruleName": "'''+str(incidentviolationsSegment['ruleName'])+'''","enforceURL": "'''+dlpEnforceIncidentURL+str(eachIncident['incidentId'])+'''", "detectionDate": "'''+str(eachIncident['detectionDate'])+'''","incidentSeverity": "'''+str(eachIncident['severityId'])+'''", "incidentMatches": "'''+str(incidentviolationsSegment['text'])+'''"}'''
                    indexSplunkIt()
                    """
                    #This code performs a single-doc Index. It works too.
                    #documenttoIndex = '''{"incidentId": "'''+str(eachIncident['incidentId'])+'''", "policyName": "'''+str(eachIncident['policyName'])+'''", "ruleName": "'''+str(incidentviolationsSegment['ruleName'])+'''","enforceURL": "'''+dlpEnforceIncidentURL+str(eachIncident['incidentId'])+'''", "detectionDate": "'''+str(eachIncident['detectionDate'])+'''","incidentSeverity": "'''+str(eachIncident['severityId'])+'''", "incidentMatches": "'''+str(incidentviolationsSegment['text'])+'''"}'''
                    #r = requests.post(esURL+'/'+esIndex+'/'+esTypeIndex, json=json.loads(documenttoIndex), headers=esHeaders, verify=bolValidateSSL)
                    #Or call the function
                    #indexElasticSearchIt()
                    """
#Outside the For Loop, this code checks if there are pending matches stored in documenttoIndexBulk
if (intViolationsCounter != 0 and bolElasticSearchItBulk):
    intViolationsCounter = 0
    #print ("Outside the Loop")
    #print (documenttoIndexBulk)     
    #r = requests.post(esURL+'/'+esTypeOp, data=documenttoIndexBulk, headers=esHeaders, verify=bolValidateSSL)
    #print(r.text)
    #Only Elastisearch as we are doing line by line for Splunk in the For Loop.
    indexElasticSearchItBulk()

#Update DLP incidents in Enforce with a specific note as defined per dlpEnforceIncidentNote
strlistofIncidents=strlistofIncidents[1:]
updateDLPIncidentswithNote()
