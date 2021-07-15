#!/usr/bin/python3
# elastic2nagios - provide an interface between Elastic alerts and Nagios-compatible tools

import falcon
import json
import os
import time
import datetime

alertfile = "alerts.json"
acklogfile = "ack.log"
baseurl = "http://localhost:8000/"
version = "20210708-siem"

class List:
    def on_get(self, req, resp):
        # Load existing alerts
        with open(alertfile) as fh:
            alerts = json.loads(fh.read())

        # Check alert data
        required = [ "plugin_output", "service", "status", "hostname", "id", "last_state_change"]
        for i in alerts:
            for j in required:
                if j not in i:
                    media = {
                        "error": "Alert database is corrupt",
                        "status": 500
                    }
                    resp.status = falcon.HTTP_500
                    resp.media = media
                    return
        
        # Enrich alerts with Nagios data
        for i in alerts:
            i["flags"] = 11
            i["host_alive"] = 1
            i["services_total"] = 1
            i["services_visible"] = 1
            delta = datetime.timedelta(seconds=int(time.time()) - i["last_state_change"])
            hours, remainder = divmod(delta.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            i["duration"] = "{}d {}h {}m {}s".format(delta.days, hours, minutes, seconds)
            i["ack_url"] = baseurl + "ack/" + str(i.pop("id", None))
        
        # Construct response
        response = {}
        response["version"] = version
        response["running"] = 1
        response["servertime"] = int(time.time())
        response["data"] = alerts
        resp.media = response
    
class Create:
    def on_post(self, req, resp):
        # Check required parameters
        required = [ "plugin_output", "service", "status", "hostname" ]
        for i in required:
            if i not in req.media.keys():
                media = {
                    "error": i + " is missing",
                    "status": 400
                }
                resp.status = falcon.HTTP_400
                resp.media = media
                return
        
        # Load existing alerts if any
        if os.path.exists(alertfile):
            with open(alertfile) as fh:
                alerts = json.loads(fh.read())
        else:
            alerts = []

        # Generate alert ID
        alertid = 0
        for i in alerts:
            if i["id"] > alertid:
                alertid = i["id"]
        alertid += 1

        # Add some other data to the new alert
        newalert = req.media
        newalert["id"] = alertid
        newalert["last_state_change"] = int(time.time())

        # Write alerts file
        alerts.append(newalert)
        with open(alertfile, "w+") as fh:
            fh.write(json.dumps(alerts))

class Ack:
    def on_post(self, req, resp, alert_id):
        # Check request
        required = ["user_ad", "user_ip"]
        for i in required:
            if i not in req.media.keys():
                media = {
                    "error": i + " is missing",
                    "status": 400
                }
                resp.status = falcon.HTTP_400
                resp.media = media
                return

        # Log ack
        with open(acklogfile, "a+") as fh:
            ack = req.media
            fh.write("Alert {} acknowledged by {} from {}\n".format(alert_id, ack["user_ad"], ack["user_ip"]))


        # Load existing alerts
        with open(alertfile) as fh:
            alerts = json.loads(fh.read())

        # Delete alert with matching ID
        for i in alerts:
            if i["id"] == alert_id:
                alerts.remove(i)

        # Write alerts file
        with open(alertfile, "w") as fh:
            fh.write(json.dumps(alerts))

app = falcon.App()
app.add_route('/list', List())
app.add_route('/create', Create())
app.add_route('/ack/{alert_id:int}', Ack())