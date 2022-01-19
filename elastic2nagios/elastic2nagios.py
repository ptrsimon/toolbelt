#!/usr/bin/python3
# elastic2nagios - provide an interface between Elastic alerts and Nagios-compatible tools

import falcon
import json
import re
import os
import socket
import time
import datetime
import config

class List:
    def on_get(self, req, resp):
        with open(config.alertfile) as fh:
            alerts = json.loads(fh.read())

        for i in alerts:
            if "hostname" not in i:
                i["hostname"] = "none"

        required = [ "plugin_output", "service", "status", "id", "last_state_change"]
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
        
        response = {}
        response["version"] = config.version
        response["running"] = 1
        response["servertime"] = int(time.time())
        response["data"] = alerts
        resp.media = response
    
class Create:
    def add_alert(self, newalert):
        if os.path.exists(config.alertfile):
            with open(config.alertfile) as fh:
                alerts = json.loads(fh.read())
        else:
            alerts = []

        # Nagios dashboard flood protection - limit total visible alerts to 100
        if len(alerts) == 100:
            newalert = {}
            newalert["plugin_output"] = "Flood protection: not displaying alert because there are 100 alerts already"
            newalert["service"] = "elastic2nagios"
            newalert["hostname"] = socket.gethostname()
            newalert["status"] = "CRITICAL"

        alertid = 0
        for i in alerts:
            if i["id"] > alertid:
                alertid = i["id"]
        alertid += 1

        newalert["id"] = alertid
        newalert["last_state_change"] = int(time.time())
        newalert["count"] = 1

        # Truncate alert to 500 characters
        if len(newalert["plugin_output"]) > 500:
            newalert["plugin_output"] = newalert["plugin_output"][:500] + "..."

        duplicate = False
        for i in alerts:
            if i["plugin_output"] == newalert["plugin_output"] and \
                i["service"] == newalert["service"] and \
                i["status"] == newalert["status"] and \
                i["hostname"] == newalert["hostname"]:
                i["count"] += 1
                duplicate = True

        if duplicate == False:
            alerts.append(newalert)
        with open(config.alertfile, "w+") as fh:
            fh.write(json.dumps(alerts))

    def check_input(self, alert):
        required = [ "plugin_output", "service", "status", "hostname" ]
        for i in required:
            if i not in alert.keys():
                media = {
                    "error": i + " is missing",
                    "status": 400
                }
                return False

        forbidden_chars = re.compile('[<>;]')
        if forbidden_chars.search(alert["plugin_output"] + 
        alert["service"] +
        alert["hostname"] + 
        alert["status"] ) != None:
            return False

        return True

    def on_post(self, req, resp):
        # Support a single object and a list of objects as well
        if isinstance(req.media, list):
            for i in req.media:
                if self.check_input(i) == False:
                    media = {
                        "error": "Bad request",
                        "status": 400
                    }
                    resp.status = falcon.HTTP_400
                    resp.media = media
                self.add_alert(i)
        else:
            if self.check_input(req.media) == False:
                    media = {
                        "error": "Bad request",
                        "status": 400
                    }
                    resp.status = falcon.HTTP_400
                    resp.media = media
            self.add_alert(req.media)        

class Ack:
    def on_post(self, req, resp, alert_id):
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

        with open(config.alertfile) as fh:
            alerts = json.loads(fh.read())

        deleted_alert = {}
        for i in alerts:
            if i["id"] == alert_id:
                deleted_alert = i
                alerts.remove(i)

        with open(config.alertfile, "w") as fh:
            fh.write(json.dumps(alerts))

        with open(config.acklogfile, "a+") as fh:
            ack = req.media
            timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
            fh.write("[{}] Alert {} acknowledged by {} from {}. Data: hostname={} service={} plugin_output={}\n".format(timestamp, alert_id, ack["user_ad"], ack["user_ip"], deleted_alert["hostname"], deleted_alert["service"], deleted_alert["plugin_output"]))

        resp.media = {"success": "true"}
        resp.status = falcon.HTTP_200
        return

app = falcon.App()
app.add_route('/list', List())
app.add_route('/create', Create())
app.add_route('/ack/{alert_id:int}', Ack())
