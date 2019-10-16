# OpenDXL-ATD-MISP
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This integration is focusing on the automated threat intelligence collection with McAfee ATD, OpenDXL and MISP.
McAfee Advanced Threat Defense (ATD) will produce local threat intelligence that will be pushed via DXL. 
An OpenDXL wrapper will subscribe and parse indicators ATD produced and will import indicators into a threat intelligence management platform (MISP). The wrapper will also upload the ATD PDF report and original detonated sample to MISP.

<img width="980" alt="screen shot 2018-06-25 at 08 36 45" src="https://user-images.githubusercontent.com/25227268/41834017-ef1470ea-7852-11e8-9d3d-d210c653e66c.png">

## Component Description

**McAfee Advanced Threat Defense (ATD)** is a malware analytics solution combining signatures and behavioral analysis techniques to rapidly identify malicious content and provides local threat intelligence. ATD exports IOC data in STIX format in several ways including the DXL.
https://www.mcafee.com/in/products/advanced-threat-defense.aspx

**MISP** threat sharing platform is free and open source software helping information sharing of threat and cyber security indicators.
https://github.com/MISP/MISP

## Prerequisites

Download the [Latest Release](https://github.com/mohlcyber/OpenDXL-ATD-MISP/releases)
   * Extract the release .zip file
   
MISP platform installation ([Link](https://github.com/MISP/MISP)) (tested with MISP 2.4.116)

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

McAfee ATD solution (tested with ATD 4.6.2)

## Configuration
McAfee ATD receives files from multiple sensors like Endpoints, Web Gateways, Network IPS or via Rest API. ATD will perform malware analytics and produce local threat intelligence. After an analysis every indicator of comprise will be published via the Data Exchange Layer (topic: /mcafee/event/atd/file/report).

### atd_misp.py
The script will subscribe to the DXL messaging fabric to retrieve McAfee ATD analysis results. Additionally the script will parse IOCs and use the API from MISP (PyMISP) to create a new threat event, add atributes and assign a tag.

Change the following information

<img width="386" alt="Screenshot 2019-10-15 at 10 37 10" src="https://user-images.githubusercontent.com/25227268/66814979-c93d7a80-ef37-11e9-8cd6-dc19f4d5c237.png">

The misp.py script will also download the PDF and original detonated sample from ATD and upload it to MISP. 
Make sure that the ATD user specified in line 25 is authorized to download reports and samples.

## Run the OpenDXL wrapper
> python3 atd_misp.py

or

> nohup python3 atd_misp.py &

## Summary
With this use case, ATD produces local intelligence and contributes information to an intelligence management platform like MISP.
MISP is able to aggregate global, community and locally produced intelligence.

<img width="1440" alt="Screenshot 2019-10-15 at 10 43 25" src="https://user-images.githubusercontent.com/25227268/66815524-b37c8500-ef38-11e9-96f1-86df877e26c9.png">

<img width="1440" alt="Screenshot 2019-10-16 at 12 05 37" src="https://user-images.githubusercontent.com/25227268/66909607-56063800-f00d-11e9-96e2-4916b9e3a0e2.png">

<img width="1440" alt="Screenshot 2019-10-15 at 10 43 42" src="https://user-images.githubusercontent.com/25227268/66815561-c727eb80-ef38-11e9-9139-f4045726cf4b.png">
