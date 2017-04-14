import argparse
import json

from pymisp import PyMISP

misp_url = 'https://misp-url.com/'
misp_key = 'auth-key'


def init(url, key):
      return PyMISP(url, key, False, 'json', debug=False)

def action(query):
      # Parse out all data from json
      
      mainfile = query['Summary']['Subject']['Name']

      # Create New Event in MISP
      misp = init(misp_url, misp_key)
      event = misp.new_event(0, 1, 1, "ATD Analysis Report - " + mainfile)
      misp.add_named_attribute(event, "filename", mainfile)

      # Add main Information to MISP
     
      atdip = query['Summary']['ATD IP']
      if not atdip: pass 
      else: misp.add_named_attribute(event, "comment", "ATD IP " + atdip)
      
      dstip = query['Summary']['Dst IP']
      if not dstip: pass
      else: misp.add_named_attribute(event, "ip-dst", dstip)

      taskid = query['Summary']['TaskId']
      if not taskid: pass
      else: misp.add_named_attribute(event, "comment", "ATD TaskID: " + taskid)
      
      md5 = query['Summary']['Subject']['md5']
      if not md5: pass
      else: misp.add_named_attribute(event, "md5", md5)
      
      sha1 = query['Summary']['Subject']['sha-1']
      if not sha1: pass
      else: misp.add_named_attribute(event, "sha1", sha1)
      
      sha256 = query['Summary']['Subject']['sha-256']
      if not sha256: pass
      else: misp.add_named_attribute(event, "sha256", sha256)
      
      size = query['Summary']['Subject']['size']
      if not size: pass
      else: misp.add_named_attribute(event, "comment", "File size is " + size)
      
      verdict = query['Summary']['Verdict']['Description']
      if not verdict: pass
      else: misp.add_named_attribute(event, "comment", verdict)

      # Add process information to MISP
      try:
           for processes in query['Summary']['Processes']:
                name = processes['Name']
                md5 = processes['Md5']
                sha1 = processes['Sha1']
                sha256 = processes['Sha256']
                if not name: pass
                else: misp.add_named_attribute(event, "filename", name)
                if not md5: pass
                else: misp.add_named_attribute(event, "md5", md5)
                if not sha1: pass
                else: misp.add_named_attribute(event, "sha1", sha1)
                if not sha256: pass
                else: misp.add_named_attribute(event, "sha256", sha256)
      except:
           pass

      # Add files information to MISP
      try:
           for files in query['Summary']['Files']:
                name = files['Name']
                md5 = files['Md5']
                sha1 = files['Sha1']
                sha256 = files['Sha256']
                if not name: pass
                else: misp.add_named_attribute(event, "filename", name)
                if not md5: pass
                else: misp.add_named_attribute(event, "md5", md5)
                if not sha1: pass
                else: misp.add_named_attribute(event, "sha1", sha1)
                if not sha256: pass
                else: misp.add_named_attribute(event, "sha256", sha256)
      except:
           pass

      # Add URL information to MISP
      try:
           for url in query['Summary']['Urls']:
                url = url['Url']
                if not url: pass
                else: misp.add_named_attribute(event, "url", url)
      except:
           pass

      # Add ips information to MISP
      try:     
           for ips in query['Summary']['Ips']:
                ipv4 = ips['Ipv4']
                port = ips['Port']
                if not ipv4: pass
                else: misp.add_named_attribute(event, "ip-dst", ipv4)
                if not port: pass
                else: misp.add_named_attribute(event, "url", ipv4 + ":" + port)
      except:
           pass

      # Add stats Information to MISP
      try:
           for stats in query['Summary']['Stats']:
                category = stats['Category']
                if not category: pass
                else: misp.add_named_attribute(event, "comment", category)
      except:
           pass

      # Add behaviour information to MISP
      try: 
           for behave in query['Summary']['Behavior']:
                behave = behave['Analysis']
                if not category: pass
                else: misp.add_named_attribute(event, "comment", behave)
      except:
           pass

      # Add tag to event
      misp.add_tag(event, str("ATD:Report"))

      print "done"
