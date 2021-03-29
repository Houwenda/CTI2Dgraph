#!/bin/bash

# load cwe data first
cd ./cwe
python3 process.py
python3 load.py

# load cve data
cd ../nvdcve
python3 process.py
python3 load.py

# load suricata rules data
cd ../suricata-rules
python3 process.py
python3 load.py