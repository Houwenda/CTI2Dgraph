Loading:
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

Updating:
1. Refind sid-CVE pairs in updated rules using ./process.py
2. Add new data to Dgraph using ./update.py

Commands:
```shellscript
python3 process.py
python3 update.py
```