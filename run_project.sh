#!/bin/bash

python3 -m venv virtualenv
source virtualenv/bin/activate
FLASK_APP=app.py flask run -h 0.0.0.0 -p 5000
