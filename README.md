# OpenDXL-ATD-MISP

This integration is focusing on the automated threat intelligence collection with McAfee ATD, OpenDXL and MISP.
McAfee Advanced Threat Defense (ATD) will produce local threat intelligence that will be pushed via DXL. 
An OpenDXL wrapper will subscribe and parse indicators ATD produced and will import indicators into a threat intelligence management platform (MISP). 

![1_atd_misp](https://cloud.githubusercontent.com/assets/25227268/25056477/5ac507f6-2169-11e7-87a9-87f251b9eab7.PNG)

## Component Description

**McAfee Advanced Threat Defense (ATD)** is a malware analytics solution combining signatures and behavioral analysis techniques to rapidly identify malicious content and provides the local threat intelligence for our solution. ATD exports IOC data in STIX format in several ways including the DXL.
https://www.mcafee.com/in/products/advanced-threat-defense.aspx

**MISP** threat sharing platform is free and open source software helping information sharing of threat and cyber security indicators.
https://github.com/MISP/MISP

## Prerequisites
MISP platform installation ([Link](https://github.com/MISP/MISP)) (tested with MISP 2.4.70)

PyMISP Library installation ([Link](https://github.com/CIRCL/PyMISP))

OpenDXL Python installation
1. Python SDK Installation ([Link](https://opendxl.github.io/opendxl-client-python/pydoc/installation.html))
2. Certificate Files Creation ([Link](https://opendxl.github.io/opendxl-client-python/pydoc/certcreation.html))
3. ePO Certificate Authority (CA) Import ([Link](https://opendxl.github.io/opendxl-client-python/pydoc/epocaimport.html))
4. ePO Broker Certificates Export ([Link](https://opendxl.github.io/opendxl-client-python/pydoc/epobrokercertsexport.html))

McAfee ATD solution (tested with ATD 3.8)

## Configuration
McAfee ATD receives files from multiple sensors like Endpoints, Web Gateways, Network IPS or via Rest API. ATD will perform malware analytics and produce local threat intelligence. After an analysis every indicator of comprise will be published via the Data Exchange Layer (topic: /mcafee/event/atd/file/report).

### atd_subscriber.py

The atd_subscriber is an OpenDXL script that receives DXL messages from ATD, prepares the JSON and loads misp.py

Change the CONFIG_FILE path in the atd_subscriber.py file

`CONFIG_FILE = "/path/to/config/file"`

### misp.py

The misp.py script receives the JSON messages and parses information and uses the Python API from MISP to create a new threat event as well as adding atributes parsed out of the ATD DXL message.

Change the misp_url and misp_key
`misp_url = 'https://misp-url.com/' 

misp_key = 'auth-key'`

The MISP auth key can be found under the automation section in MISP.



## Run the OpenDXL wrapper
`python atd_subscriber.py`
or
`nohup python atd_subscriber.py &`

