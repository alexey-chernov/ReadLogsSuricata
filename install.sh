#!/bin/bash

python3 -m venv virtualenv
source virtualenv/bin/activate
pip install pandas matplotlib flask maxminddb requests geoip2 python-whois
