#!/bin/bash

curl -k -X POST -H 'Content-Type: application/json' -d @sarc.json https://127.0.0.1:8443/authorize
