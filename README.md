# OpenDXL-ATD-MISP

This integration is focusing on the automated threat intelligence collection with McAfee ATD, OpenDXL and MISP.
McAfee Advanced Threat Defense (ATD) will produce local threat intelligence that will be pushed via DXL. 
An OpenDXL wrapper will subscribe and parse indicators ATD produced and will import indicators into a threat intelligence management platform (MISP). 

![1_atd_misp](https://cloud.githubusercontent.com/assets/25227268/25056477/5ac507f6-2169-11e7-87a9-87f251b9eab7.PNG)

# Component Description

McAfee Advanced Threat Defense (ATD) is a malware analytics solution combining signatures and behavioral analysis techniques to rapidly identify malicious content and provides the local threat intelligence for our solution. ATD exports IOC data in STIX format in several ways including the DXL.
The MISP threat sharing platform is free and open source software helping information sharing of threat and cyber security indicators
