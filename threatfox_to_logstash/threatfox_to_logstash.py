# threatfox_to_logstash.py - take a ThreatFox domain JSON database dump and
# convert it to a Logstash-friendly format. It can be parsed by the translate
# plugin.
#
# Usage: threatfox_to_logstash.py domains.json [outfile.json]

import json
import sys

def load_db(file):
    with open(file) as fh:
        data = json.load(fh)
    return data

def process_data(data):
    logstashdata = {}
    for i in data.values():
        domain = {}
        logstashdata[i[0]['ioc_value']] = {
            'ioc_type': i[0]['ioc_type'],
            'threat_type': i[0]['threat_type'],
            'malware': i[0]['malware'],
            'malware_alias': i[0]['malware_alias'],
            'malware_printable': i[0]['malware_printable'],
            'first_seen_utc': i[0]['first_seen_utc'],
            'last_seen_utc': i[0]['last_seen_utc'],
            'confidence_level': i[0]['confidence_level'],
            'reference': i[0]['reference'],
            'tags': i[0]['tags'],
            'anonymous': i[0]['anonymous'],
            'reporter': i[0]['reporter']
        }
    return logstashdata

def write_logstash_json(data, outfile):
    with open(outfile, 'w') as fh:
        json.dump(data, fh)

def main(argv):
    if len(sys.argv) >= 3:
        outfile = sys.argv[2]
    else:
        outfile = "threatfox_logstash.json"
    write_logstash_json(process_data(load_db(argv[1])), outfile)

if __name__ == '__main__':
    main(sys.argv)
