1. Download CWE using ./cwe/download.sh
2. Parse CWE data into json file using process.py
3. Create schema and load CWE data into Dgraph database using ./load.py

Commands:
```shellscript
cd cwe/
./download.sh
cd ../
python3 process.py
python3 load.py
```