#!/usr/bin/python3
# elastic2nagios - provide an interface between Elastic alerts and Nagios-compatible tools

import falcon
import json
import re
import os
import time
import datetime
import config

class List:
    def on_get(self, req, resp):
        # Load existing alerts
        with open(config.alertfile) as fh:
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
        
        # Enrich alerts with Nagios data and count
        for i in alerts:
            i["flags"] = 11
            i["host_alive"] = 1
            i["services_total"] = 1
            i["services_visible"] = 1
            delta = datetime.timedelta(seconds=int(time.time()) - i["last_state_change"])
            hours, remainder = divmod(delta.seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            i["duration"] = "{}d {}h {}m {}s".format(delta.days, hours, minutes, seconds)
            i["ack_url"] = config.baseurl + "ack/" + str(i.pop("id", None))
            if i["count"] > 1:
                i["plugin_output"] += " (repeated: {}x)".format(i.pop("count", None))
            else:
                i.pop("count")
        
        # Construct response
        response = {}
        response["version"] = config.version
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

        # Input check
        forbidden_chars = re.compile('[<>;]')
        if forbidden_chars.search(req.media["plugin_output"]) != None:
            media = {
                "error": "Invalid character in plugin_output",
                "status": 400
            }
            resp.status = falcon.HTTP_400
            resp.media = media
            return
        
        # Load existing alerts if any
        if os.path.exists(config.alertfile):
            with open(config.alertfile) as fh:
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
        newalert["count"] = 1

        # Check for duplicates
        duplicate = False
        for i in alerts:
            if i["plugin_output"] == newalert["plugin_output"] and \
                i["service"] == newalert["service"] and \
                i["status"] == newalert["status"] and \
                i["hostname"] == newalert["hostname"]:
                i["count"] += 1
                duplicate = True

        # Write alerts file
        if duplicate == False:
            alerts.append(newalert)
        with open(config.alertfile, "w+") as fh:
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
        with open(config.acklogfile, "a+") as fh:
            ack = req.media
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            fh.write("[{}] Alert {} acknowledged by {} from {}\n".format(timestamp, alert_id, ack["user_ad"], ack["user_ip"]))


        # Load existing alerts
        with open(config.alertfile) as fh:
            alerts = json.loads(fh.read())

        # Delete alert with matching ID
        for i in alerts:
            if i["id"] == alert_id:
                alerts.remove(i)

        # Write alerts file
        with open(config.alertfile, "w") as fh:
            fh.write(json.dumps(alerts))

app = falcon.App()
app.add_route('/list', List())
app.add_route('/create', Create())
app.add_route('/ack/{alert_id:int}', Ack())
