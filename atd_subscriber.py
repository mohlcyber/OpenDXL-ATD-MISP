#!/usr/bin/env python

import logging
import time
import json
import importlib

from dxlclient.callbacks import EventCallback
from dxlclient.client import DxlClient
from dxlclient.client_config import DxlClientConfig

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

CONFIG_FILE = "path to config dxlclient config file"
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

# Variable MISP python
servicedxl = importlib.import_module("misp")

# Create the client
with DxlClient(config) as client:

    # Connect to the fabric
    client.connect()

    # Create and add event listener
    class MyEventCallback(EventCallback):
        def on_event(self, event):
            try:
                query = event.payload.decode()
                print("Event received: " + query)

                query = query[:-3]
                query = json.loads(query)

                # Push data into MISP
                servicedxl.action(query)

            except Exception as e:
                print(e)

        @staticmethod
        def worker_thread(req):
            client.sync_request(req)

    # Register the callback with the client
    client.add_event_callback('#', MyEventCallback(), subscribe_to_topic=False)
    client.subscribe("/mcafee/event/atd/file/report")

    # Wait forever
    while True:
        time.sleep(60)
