# CTI2Dgraph
Load Cyber Threat Intelligence from NVD-CVE, MITRE CWE, MITRE CAPEC, MITRE ATT&CK into Dgraph database, along with Suricata rules.

## Dgraph Setup
Deploy Dgraph using docker-compose.
```yaml
version: "3"
services:
    zero:
        image: dgraph/dgraph:v20.11.0
        ports:
            - "5080" # internal & external grpc
            - "6080:6080" # external http
        volumes:
            - "./data:/dgraph"
        command: "dgraph zero --my=zero:5080"
        restart: on-failure
    alpha:
        image: dgraph/dgraph:v20.11.0
        volumes:
            - "./data:/dgraph"
        ports:
            - "8080:8080" # external http
            - "9080:9080" # external grpc
            # 7080 for internal grpc
        restart: on-failure
        command: 'dgraph alpha --my=alpha:7080 --zero=zero:5080 --whitelist="172.24.0.1"' # whitelisted ip address is the host ip of docker-compose
    ratel:
        image: dgraph/dgraph:v20.11.0
        ports:
            - "8000:8000" # webui
        command: "dgraph-ratel"
```

## Downloading Raw Data
Download data feeds using download.sh in subdirectories.
```shellscript
cd att\&ck/att\&ck
./download.sh
cd ../../cwe/cwe
./download.sh
cd ../../nvdcve/cve
./download.sh
cd ../../
```
Download Suricata rules using docker-compose.
```shellscript
cd  suricata-rules
sudo docker-compose up
sudo docker-compose down
cd ../
```

## Loading Data Into Dgraph
Usage:
```shellscript
pip3 install -r requirements.txt
./deploy.sh
```