import pydgraph
import json

def removeDuplicate(client, rawData):
    querySuricataRule = '''query all($sid: string) {
        q(func: eq(sid, $sid)) {
            uid
            sid
        }
    }
'''
    result = []
    txn = client.txn()
    for suricataRule in rawData:
        res = txn.query(querySuricataRule, variables={'$sid':suricataRule["sid"]})
        if len(json.loads(res.json)["q"]) == 0: # not exist
            result.append(suricataRule)
    txn.commit()
    return result

def update(client, fileName):
    with open(fileName) as f:
        dataWithoutRelation = json.load(f) # json validation
    dataWithoutRelation = removeDuplicate(client, dataWithoutRelation)
    print("Adding new suricata rules:", len(dataWithoutRelation))

    # remove relation information
    for i in range(len(dataWithoutRelation)):
        dataWithoutRelation[i]["cve"] = []
        
    totalCount = len(dataWithoutRelation)
    index = 0
    span = 100 # 100 records per transaction
    while index + span < totalCount :
        txn = client.txn()
        try:
            mu = pydgraph.Mutation(set_json=json.dumps(dataWithoutRelation[index:index+span]).encode('utf8'))
            txn.mutate(mu)
            txn.commit()
            index += span
        except pydgraph.AbortedError:
            print("error")
            break
        finally:
            txn.discard()
        print(str(index+span)+".", end="")
    
    txn = client.txn()
    try:
        mu = pydgraph.Mutation(set_json=json.dumps(dataWithoutRelation[index:]).encode('utf8'))
        txn.mutate(mu)
        txn.commit()
        index += span
    except pydgraph.AbortedError:
        print("error")
    finally:
        txn.discard()
    print()
    print("json data without relation loaded into dgraph")
    
    # create relations
    querySuricataRule = '''query all($sid: string) {
        q(func: eq(sid, $sid)) {
            uid
            sid
        }
    }
'''
    queryCve = '''query all($name: string) {
        q(func: eq(name, $name)) {
            uid
            name
        }
    }
'''
    with open(fileName) as f:
        data = json.load(f) # json validation
    data = removeDuplicate(client, data)
    for suricataRule in data:
        txn = client.txn()
        res = txn.query(querySuricataRule, variables={'$sid':suricataRule["sid"]})
        print(json.loads(res.json))
        currentUid = json.loads(res.json)["q"][0]["uid"]
        if len(suricataRule["cve"]) > 0:
            for name in suricataRule["cve"]:
                res = txn.query(queryCve, variables={'$name':name})
                res = json.loads(res.json)["q"]
                if len(res) == 0:
                    print("cve not found:", name)
                    continue
                uid = res[0]["uid"]
                txn.mutate(set_nquads='<' + currentUid + '> <cve> <' + uid + '> .')
        txn.commit()
    print("suricata rule to cve relations created")

def updateCveLink(client, fileName):
    with open(fileName) as f:
        data = json.load(f) # json validation
    # create relations
    querySuricataRule = '''query all($sid: string) {
        q(func: eq(sid, $sid)) {
            uid
            sid
            cve {
                name
            }
        }
    }
'''
    queryCve = '''query all($name: string) {
        q(func: eq(name, $name)) {
            uid
            name
        }
    }
'''
    for suricataRule in data:
        txn = client.txn()
        res = txn.query(querySuricataRule, variables={'$sid':suricataRule["sid"]})
            
        if "cve" not in json.loads(res.json)["q"][0]:
            print(res.json)
            currentUid = json.loads(res.json)["q"][0]["uid"]
            if len(suricataRule["cve"]) > 0:
                for name in suricataRule["cve"]:
                    res = txn.query(queryCve, variables={'$name':name})
                    res = json.loads(res.json)["q"]
                    if len(res) == 0:
                        print("cve not found:", name)
                        continue
                    uid = res[0]["uid"]
                    txn.mutate(set_nquads='<' + currentUid + '> <cve> <' + uid + '> .')

        txn.commit()
        # break

if __name__ == '__main__':
    client_stub = pydgraph.DgraphClientStub('localhost:9080')
    client = pydgraph.DgraphClient(client_stub)

    update(client, "./result.json")
    updateCveLink(client, "./result.json")