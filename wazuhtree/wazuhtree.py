#!/usr/bin/python3
# wazuhtree - visualize Wazuh rule matching
#
# Depends: graphviz (apt/brew install graphviz AND pip3 install graphviz)
# Usage: wazuhtree RULEDIR

import sys
import os
import re
import xml.etree.ElementTree as et
import graphviz

def read_rules(ruledir):
    ruledict = {}

    for rulefile in os.listdir(ruledir):
        with open(ruledir + '/' + rulefile) as fh:
            data = re.sub(r'<!--[\s\S]*?-->', '',
                re.sub(r'\&', '&amp;', "<rules>" + fh.read() + "</rules>")) # workarounds to parse Wazuh's pseudo-XML format
            rules = et.fromstring(data)
            
            for group in rules.iter():
                if group.tag == "group":
                    for rule in group:
                        ruledata = {}
                        depends = False
                        for param in rule:
                            if param.tag == "if_sid" or param.tag == "if_matched_sid":
                                for depid in param.text.split(','):
                                    ruledata['depid'] = depid
                                    depends = True
                            if param.tag == "description":
                                ruledata['description'] = param.text
                            if param.tag == "hostname":
                                ruledata['hostname'] = param.text
                        if depends == True: # only add rules that are part of a dependency tree
                            ruledict[rule.attrib['id']] = ruledata
    
    return ruledict

def buildgraph(ruledict):
    tree = graphviz.Digraph(comment="The tree", graph_attr={'splines': 'ortho', 'ratio': 'expand'})
    
    for id in ruledict.keys():
        if "hostname" in ruledict[id]:
            tree.node(id, id + "\nHostname filter: " + ruledict[id]['hostname'] + "\n" + ruledict[id]['description'])
        else:
            tree.node(id, id + "\n" + ruledict[id]['description'])
    for id, data in ruledict.items():
        print(id, data['depid'])
        tree.edge(data['depid'], id, constraint='true')

    return tree.unflatten(stagger=10)

def render(tree):
    tree.view()

def main(args):
    if len(args) != 2:
        print("Invalid arguments, exit")
        return 1
    ruledir = args[1]

    render(buildgraph(read_rules(ruledir)))

    return

if __name__ == "__main__":
    sys.exit(main(sys.argv))
