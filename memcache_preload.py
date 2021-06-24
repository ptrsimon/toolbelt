# memcache_preload - read a file and put its contents into memcached
#
# File needs to be in CSV format like this:
# key1,value1
# key2,value2
#
# Depends: pymemcache
# Usage: memcache_preload.py file.csv

import sys
from pymemcache.client.base import Client

def readfile(path):
    data = {}
    with open(path) as fh:
        for line in fh:
            key, value = line.partition(',')[::2]
            data[key] = value.strip()
    return data

def load(data):
    mcclient = Client('127.0.0.1')
    for key, val in data.items():
        mcclient.set(key, val)

def main(argv):
    load(readfile(argv[1]))

if __name__ == '__main__':
    main(sys.argv)