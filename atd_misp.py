# written by mohlcyber v.1.3

import sys
import os
import requests
import base64
import time
import json

from dxlclient.callbacks import EventCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig

from pymisp import ExpandedPyMISP, MISPEvent, MISPAttribute
from pathlib import Path

requests.packages.urllib3.disable_warnings()

#MISP Details
misp_url = 'https://1.1.1.1'
misp_key = '### API Key ###'
misp_tag = '### TAG Name ###'
misp_verify = False

#ATD Details
atd_ip = '2.2.2.2'
atd_user = '### ATD Username ###'
atd_pw = '### ATD Password ###'
atd_profile = '### ATD Profile ID ###'
atd_verify = False

#DXL Config
dxl_config = '### PATH to Config File ###s'

class ATD():
    def __init__(self):
        self.ip = atd_ip
        self.url = "https://" + self.ip + "/php/"
        self.user = atd_user
        self.pw = atd_pw
        creds = self.user + ':' + self.pw
        self.creds = base64.b64encode(creds.encode())
        self.profile = atd_profile
        self.verify = atd_verify

        self.sessionsetup()

    def sessionsetup(self):
        try:
            sessionheaders = {
                'VE-SDK-API' : self.creds,
                'Content-Type' : 'application/json',
                'Accept' : 'application/vnd.ve.v1.0+json'
            }

            r = requests.get(self.url + "session.php", headers=sessionheaders, verify=self.verify)
            data = r.json()
            results = data.get('results')
            tmp_header = results['session'] + ':' + results['userId']
            self.headers = {
                'VE-SDK-API': base64.b64encode(tmp_header.encode()),
                'Accept': 'application/vnd.ve.v1.0+json',
                'accept-encoding': 'gzip;q=0,deflate,sdch'
            }
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))

    def get_report(self, taskid, itype):
        try:
            payload = {'iTaskId': taskid, 'iType': itype}
            r = requests.get(self.url + "showreport.php", params=payload, headers=self.headers, verify=self.verify)

            if itype == 'sample':
                open('{0}.zip'.format(taskid), 'wb').write(r.content)
            elif itype == 'pdf':
                open('{0}.pdf'.format(taskid), 'wb').write(r.content)

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))

    def logout(self):
        requests.delete(self.url + "session.php", headers=self.headers, verify=self.verify)


class MISP():
    def __init__(self, query):
        self.misp = ExpandedPyMISP(misp_url, misp_key, ssl=misp_verify, debug=False)
        self.misp_tag = misp_tag
        self.tags = self.misp.tags()
        self.query = query
        self.mainfile = query['Summary']['Subject']['Name']
        self.attributes = []

    def form_attr_obj(self, type, value, file=None):
        try:
            attr = MISPAttribute()
            attr.type = type
            attr.value = value

            if file is not None:
                path = Path(file)
                attr.data = path

            self.attributes.append(attr)

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))

    def create_attr_obj(self):
        try:
            self.form_attr_obj('filename', self.mainfile)

            atdip = self.query['Summary']['ATD IP']
            if not atdip: pass
            else: self.form_attr_obj('comment', 'ATD IP {0}'.format(atdip))

            dstip = self.query['Summary']['Dst IP']
            if not dstip: pass
            else: self.form_attr_obj('ip-dst', dstip)

            taskid = self.query['Summary']['TaskId']
            if not taskid: pass
            else: self.form_attr_obj('comment', 'ATD TaskID: {0}'.format(taskid))

            md5 = self.query['Summary']['Subject']['md5']
            if not md5: pass
            else: self.form_attr_obj('md5', md5)

            sha1 = self.query['Summary']['Subject']['sha-1']
            if not sha1: pass
            else: self.form_attr_obj('sha1', sha1)

            sha256 = self.query['Summary']['Subject']['sha-256']
            if not sha256: pass
            else: self.form_attr_obj('sha256', sha256)

            size = self.query['Summary']['Subject']['size']
            if not size: pass
            else: self.form_attr_obj('comment', 'File size is: {0}'.format(size))

            verdict = self.query['Summary']['Verdict']['Description']
            if not verdict: pass
            else: self.form_attr_obj('comment', verdict)

            # Add process information to MISP
            try:
                for processes in self.query['Summary']['Processes']:
                    name = processes['Name']
                    md5 = processes['Md5']
                    sha1 = processes['Sha1']
                    sha256 = processes['Sha256']
                    if not name: pass
                    else: self.form_attr_obj('filename', name)
                    if not md5: pass
                    else: self.form_attr_obj('md5', md5)
                    if not sha1: pass
                    else: self.form_attr_obj('sha1', sha1)
                    if not sha256: pass
                    else: self.form_attr_obj('sha256', sha256)
            except:
                pass

            # Add files information to MISP
            try:
                for files in self.query['Summary']['Files']:
                    name = files['Name']
                    md5 = files['Md5']
                    sha1 = files['Sha1']
                    sha256 = files['Sha256']
                    if not name: pass
                    else: self.form_attr_obj('filename', name)
                    if not md5: pass
                    else: self.form_attr_obj('md5', md5)
                    if not sha1: pass
                    else: self.form_attr_obj('sha1', sha1)
                    if not sha256: pass
                    else: self.form_attr_obj('sha256', sha256)
            except:
                pass

            # Add URL information to MISP
            try:
                for url in self.query['Summary']['Urls']:
                    url = url['Url']
                    if not url: pass
                    else: self.form_attr_obj('url', url)
            except:
                pass

            # Add ips information to MISP
            try:
                for ips in self.query['Summary']['Ips']:
                    ipv4 = ips['Ipv4']
                    port = ips['Port']
                    if not ipv4: pass
                    else: self.form_attr_obj('ip_dst', ipv4)
                    if not port: pass
                    else:
                        self.form_attr_obj('port', port)
                        self.form_attr_obj('url','{0}:{1}'.format(ipv4, port))
            except:
                pass

            # Add stats Information to MISP
            try:
                for stats in self.query['Summary']['Stats']:
                    category = stats['Category']
                    if not category: pass
                    else: self.form_attr_obj('comment', category)
            except:
                pass

            # Add behaviour information to MISP
            try:
                for behave in self.query['Summary']['Behavior']:
                    behave = behave['Analysis']
                    if not behave: pass
                    else: self.form_attr_obj('comment', behave)
            except:
                pass

            # Download original sample from ATD analysis
            time.sleep(10)
            atd = ATD()
            atd.get_report(taskid, 'pdf')
            atd.get_report(taskid, 'sample')
            atd.logout()

            pdf = '{0}.pdf'.format(taskid)
            samplefile = '{0}.zip'.format(taskid)

            # add attributes for analysis report
            self.form_attr_obj('attachment', '{0}.pdf'.format(str(self.mainfile)), file=pdf)

            # add attributes for malware sample
            self.form_attr_obj('malware-sample', '{0}.zip'.format(str(self.mainfile)), file=samplefile)

            # Delete original sample local - potentially nice to have locally as well
            os.remove(pdf)
            os.remove(samplefile)

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))

    def add_event(self):
        try:
            event = MISPEvent()
            event.distribution = 0

            # ATD Threat mapping to MISP Threat Level
            atd_threat_level = self.query['Summary']['Verdict']['Severity']
            if not atd_threat_level:
                pass
            else:
                if atd_threat_level == '3':
                    event.threat_level_id = 1
                elif atd_threat_level == '4':
                    event.threat_level_id = 2
                elif atd_threat_level == '5':
                    event.threat_level_id = 3
                else:
                    event.threat_level_id = 0

            event.analysis = 0  # initial
            event.info = "ATD Analysis Report - {0}".format(self.mainfile)
            event.attributes = self.attributes
            event.Tag = 'ATD:Report'

            event = self.misp.add_event(event, pythonify=True)
            self.evenid = event.id
            print('SUCCESS: New MISP Event got created with ID: {}'.format(str(event.id)))

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))

    def assign_tag(self):
        try:
            uuid = None

            results = self.misp.search(eventid=self.evenid)
            for event in results:
                uuid = event['Event']['uuid']
                self.misp.tag(uuid, self.misp_tag)
                break

            if uuid is None:
                print('STATUS: Could not tag the MISP Event. Continuing...')

            #MITRE tags assign to McAfee ATD findings
            version = self.query['Summary']['SUMversion']
            version = str(version).replace('.', '')
            if int(version) >= 46021:
                mitre_list = self.query['Summary']['Mitre']
                for val in mitre_list:
                    mitre_tech = val['Techniques']
                    for tag in self.tags:
                        if 'mitre-attack-pattern="{0}'.format(mitre_tech) in tag['name']:
                            self.misp.tag(uuid, tag['id'])

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            print("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                  .format(location=__name__, funct_name=sys._getframe().f_code.co_name, line_no=exc_tb.tb_lineno,
                          error=str(e)))

    def main(self):
        self.create_attr_obj()
        self.add_event()
        self.assign_tag()

class DXL():
    def __init__(self):
        self.config = DxlClientConfig.create_dxl_config_from_file(dxl_config)

    def subscriber(self):
        with DxlClient(self.config) as client:
            client.connect()
            class MyEventCallback(EventCallback):
                def on_event(self, event):
                    try:
                        query = event.payload.decode()
                        print("STATUS: McAfee ATD Event received. Adding to MISP.")

                        query = query[:query.rfind('}') + 1]
                        query = json.loads(query)

                        # Push data into MISP
                        misp = MISP(query)
                        misp.main()

                    except Exception as e:
                        exc_type, exc_obj, exc_tb = sys.exc_info()
                        print("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(e)))

                @staticmethod
                def worker_thread(req):
                    client.sync_request(req)

            # Register the callback with the client
            client.add_event_callback('#', MyEventCallback(), subscribe_to_topic=False)
            client.subscribe("/mcafee/event/atd/file/report")

            # Wait forever
            while True:
                time.sleep(60)

if __name__ == '__main__':
    dxl = DXL()
    dxl.subscriber()