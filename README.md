# indexSymantecDLPMatches

PROVIDED AS-IS
The code is a) an example and b) provided as-is, we do not know your computing environment so you need to assess the script’s function and performance before implementing it.


1/ Get a List of Incidents that have not been processed (using a specific Incidents Note as defined by dlpEnforceIncidentNote). You can use other artifacts, such as Incident Status. It is possible to control the number 
of Incidents by date or pull a certain number of incidents at a time (up to 10000 as per the API... defined by dlpEnforceIncidentPageSize).
2/ With the incident list, the code makes another call to obtain each's incidents details, including the Matches.
3/ The code can make bulk or individual API calls to ElasticSearch or Splunk for indexing.
4/ Once the matches are in ElastiSearch, the code makes another call to the DLP Rest API to update the processed incidents by adding a note.

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
