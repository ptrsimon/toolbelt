#!/usr/bin/python3
# misp2elastic.py - perform retrospective analysis and enrichment on Elasticsearch data
#                   based on threat intelligence from MISP. Uses redis for quick lookups
#                   to avoid excessive usage of MISP API.
