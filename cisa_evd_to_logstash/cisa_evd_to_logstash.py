# cisa_evd_to_logstash.py - take a CISA Known Exploited Vulnerabilities Database dump
# and convert it to a Logstash-friendly format. It can be parsed by the translate
# plugin.
#
# CISA DB: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
#
# Usage: cisa_evd_to_logstash.py cisa_exampledb.json [outfile.json]

import json
import sys

def load_db(file):
    with open(file) as fh:
        data = json.load(fh)['vulnerabilities']
    return data

def process_data(data):
    logstashdata = {}
    for i in data:
        domain = {}
        logstashdata[i['cveID']] = {
            'action': i['requiredAction'],
            'description': i['shortDescription'],
            'added': i['dateAdded']
        }
    return logstashdata

def write_logstash_json(data, outfile):
    with open(outfile, 'w') as fh:
        json.dump(data, fh)

def main(argv):
    if len(sys.argv) >= 3:
        outfile = sys.argv[2]
    else:
        outfile = "cisa_evd_logstash.json"
    write_logstash_json(process_data(load_db(argv[1])), outfile)

if __name__ == '__main__':
    main(sys.argv)
