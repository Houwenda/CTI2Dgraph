1. Download suricata rules using docker-compose.
2. Find sid-CVE pairs in suricata rules using ./process.py
3. Create schema and load data into Dgraph using ./load.py

Commands:
```shellscript
sudo docker-compose up
sudo docker-compose down
python3 process.py
python3 load.py
```