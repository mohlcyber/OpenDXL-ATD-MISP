# OpenDXL-ATD-MISP
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This integration is focusing on the automated threat intelligence collection with McAfee ATD, OpenDXL and MISP.
McAfee Advanced Threat Defense (ATD) will produce local threat intelligence that will be pushed via DXL. 
An OpenDXL wrapper will subscribe and parse indicators ATD produced and will import indicators into a threat intelligence management platform (MISP). The wrapper will also upload the ATD PDF report and original detonated sample to MISP.

PLACEHOLDER PICTURE

## Component Description

**McAfee Advanced Threat Defense (ATD)** is a malware analytics solution combining signatures and behavioral analysis techniques to rapidly identify malicious content and provides local threat intelligence. ATD exports IOC data in STIX format in several ways including the DXL.
https://www.mcafee.com/in/products/advanced-threat-defense.aspx

**MISP** threat sharing platform is free and open source software helping information sharing of threat and cyber security indicators.
https://github.com/MISP/MISP

## Prerequisites

Download the [Latest Release](https://github.com/mohlcyber/OpenDXL-ATD-MISP/releases)
   * Extract the release .zip file
   
MISP platform installation ([Link](https://github.com/MISP/MISP)) (tested with MISP 2.4.92)

Requests ([Link](http://docs.python-requests.org/en/master/user/install/#install))

PyMISP library installation ([Link](https://github.com/MISP/PyMISP))
```sh
git clone https://github.com/MISP/PyMISP.git
cd PyMISP/
python setup.py install
```

OpenDXL SDK ([Link](https://github.com/opendxl/opendxl-client-python))
```sh
git clone https://github.com/opendxl/opendxl-client-python.git
cd opendxl-client-python/
python setup.py install
```

Certificate Files Creation ([Link](https://opendxl.github.io/opendxl-client-python/pydoc/epoexternalcertissuance.html)).
DXL 4.x support a simplyfied way to create certificates
([Link](https://github.com/opendxl/opendxl-client-python/blob/master/docs/sdk/basiccliprovisioning.rst)).

McAfee ATD solution (tested with ATD 4.4)

## Configuration
McAfee ATD receives files from multiple sensors like Endpoints, Web Gateways, Network IPS or via Rest API. ATD will perform malware analytics and produce local threat intelligence. After an analysis every indicator of comprise will be published via the Data Exchange Layer (topic: /mcafee/event/atd/file/report).

### atd_subscriber.py
The atd_subscriber.py receives DXL messages from ATD, prepares the JSON and loads misp.py.

Change the CONFIG_FILE path in the atd_subscriber.py file.

`CONFIG_FILE = "/path/to/config/file"`

### misp.py
The misp.py script receives the JSON messages from ATD, parses IOCs and use the Python API from MISP (PyMISP) to create a new threat event, add atributes and asign a tag.

Change the following information

<img width="305" alt="screen shot 2018-06-22 at 17 54 39" src="https://user-images.githubusercontent.com/25227268/41786272-62ace20e-7645-11e8-9265-885be035124a.png">

The MISP auth key can be found under the automation section in MISP.

Change the tag assignment in line 185

`misp.add_tag(event, str("ATD:Report"))`

Make sure that you added the tag in MISP.

The misp.py script will also download the PDF and original detonated sample from ATD and upload it to MISP. 
Make sure that the ATD user specified in line 18 is authorized to download reports and samples.

## Run the OpenDXL wrapper
> python atd_subscriber.py

or

> nohup python atd_subscriber.py &

## Summary
With this use case, ATD produces local intelligence and contributes information to an intelligence management platform like MISP.
MISP is able to aggregate global, community and locally produced intelligence.

![2_atd_misp](https://cloud.githubusercontent.com/assets/25227268/25057844/d5ded02a-2173-11e7-914d-422329a1bb51.PNG)

![3_atd_misp](https://cloud.githubusercontent.com/assets/25227268/25057877/260102da-2174-11e7-91a1-37e3a9feca09.PNG)
