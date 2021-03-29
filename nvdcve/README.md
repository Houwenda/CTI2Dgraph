1. Download json data feed of NVD CVE using ./cve/download.sh
2. Parse CVE data feed and duamp into json file using ./process.py
3. Create schema and load CVE data into Dgraph database using ./load.py

Commands:
```shellscript
cd cve/
./download.sh
cd ../
pip3 install -r requirements.txt
python3 process.py
python3 load.py
```