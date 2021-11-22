# indexSymantecDLPMatches

PROVIDED AS-IS
The code is a) an example and b) provided as-is, we do not know your computing environment so you need to assess the script’s <br /> 
function and performance before implementing it. <br />


1/ Get a List of Incidents that have not been processed (using a specific Incidents Note as defined by dlpEnforceIncidentNote). <br />
You can use other artifacts, such as Incident Status. It is possible to control the number <br />
of Incidents by date or pull a certain number of incidents at a time <br />
(up to 10000 as per the API... defined by dlpEnforceIncidentPageSize). <br />
2/ With the incident list, the code makes another call to obtain each's incidents details, including the Matches. <br />
3/ The code can make bulk or individual API calls to ElasticSearch or Splunk for indexing. <br />
4/ Once the matches are in ElastiSearch, the code makes another call to the DLP Rest API to update the processed incidents by adding a note. <br />
<br />
Prerequisites <br />
1/ indexDLPMatches.py is written in Python 3.8 <br />
2/ Symantec DLP 15.8 MP1 <br />
    2.1/ A Symantec DLP user with API privileges <br />
3/ Python 3.8 <br />
    3.1/ json and requests Python modules <br />
4/ ElasticSearch/Kibana or Splunk with HEC <br />
<br />
References: <br />
https://techdocs.broadcom.com/us/en/symantec-security-software/information-security/data-loss-prevention/15-8/DLP-Enforce-REST-APIs-overview/overview.html  <br />
