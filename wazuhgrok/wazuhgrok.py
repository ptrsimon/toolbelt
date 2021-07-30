#!/usr/bin/python3
# wazuhgrok.py - render Grok patterns to regexes.
#
# USAGE: wazuhgrok.py PATTERNFILE DECODERFILE

import sys
import string

def get_patterns(path):
    patterns = {}
    patterns_rendered = {}
    with open(path, 'r') as fh:
        for line in fh:
            patterns[line.split(" ", 1)[0]] = line.split(" ", 1)[1]
    # Render embedded patterns
    for k,v in patterns.items():
        print("k: " + k)
        print("v: " + v)
        for k2,v2 in patterns.items():
            print("k2: " + k2)
            print("v2: " + v2)
            if '%{' + k2 + '}' in  v:
                if k in patterns_rendered.keys():
                    patterns_rendered[k] = patterns_rendered[k].replace('%{' + k2 + '}', v2.replace('\n', ''))
                else:
                    patterns_rendered[k] = v.replace('%{' + k2 + '}', v2.replace('\n', ''))
                print("patterns_rendered[" + k + "]: " + patterns_rendered[k])

    print(patterns_rendered)
    return patterns_rendered

def render_decoders(path, patterns):
    with open(path, 'r') as fh:
        decoderdata = fh.read()
    for k,v in patterns.items():
        grokname = "%{" + k + "}"
        regex = v.replace('\n', '')
        grokkeddata = decoderdata.replace(grokname, regex)
    with open(path + ".grokked", 'w') as fh:
        fh.write(grokkeddata)
    return

if __name__ == "__main__":
    render_decoders(sys.argv[2], get_patterns(sys.argv[1]))
