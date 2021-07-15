# misp2elastic

## Summary
Perform retrospective analysis and enrichment on Elasticsearch data based on threat intelligence from MISP.
Uses redis for quick lookups to avoid excessive usage of MISP API.

## Why not https://github.com/securitydistractions/elastimispstash?
elastimispstash only supports event enrichment on ingest time, via logstash and memcached.
We needed retrospective enrichment in order to investigate past intrusions based on newly available IOCs.

## Why redis?
While elastimispstash uses memcached as a quick lookup engine, we wanted something more robust and something which was meant to be a database in the first place.
Also, we are already using redis in our SIEM so that further simplifies operations.

## How does it work?
1. misp2elastic periodically runs to enrich past events with newer threat data. This period should be about the same as the update frequency of your threat intel feeds.
2. As a first step, misp2elastic requests the relevant IOCs from the MISP API and loads them in redis (only as a simple key-value structure to save memory).
3. misp2elastic uses the scroll API of Elasticsearch to iterate over all indexed events.
4. For each event, misp2elastic takes the value of the field of interest (eg. source.ip) and performs a redis lookup with the field value as a key.
5. If the field value was found in redis, it means that we found a potential IOC. In this case, misp2elastic queries the MISP API to get the full context of the IOC and updates the Elastic document with this enrichment information. Optional: it logs an alert in a separate index that past event data was enriched with new threat intel.