# OpenDXL-ATD-MISP

This playbook is focusing on the automated threat intelligence collection with McAfee ATD,
OpenDXL and an intelligence management platform.
In this playbook McAfee Advanced Threat Defense (ATD) will produce local threat intelligence
that will be pushed via DXL. An OpenDXL wrapper will subscribe and parse indicators ATD
produced and will import indicators into a threat intelligence management platform (MISP). 
