import pydgraph
import json

def removeDuplidate(client, rawData):
    query = '''query all($name: string) {
        q(func: eq(name, $name)) {
            uid
            name
        }
    }
'''
    result = []
    txn = client.txn()
    for cve in rawData:
        res = txn.query(query, variables={'$name':cve["name"]})
        if len(json.loads(res.json)["q"]) == 0: # not exist
            result.append(cve)
    txn.commit()
    return result

def update(client, fileName):
    print("Reading cve data from file")
    with open(fileName) as f:
        dataWithoutRelation = json.load(f) # json validation
    dataWithoutRelation = removeDuplidate(client, dataWithoutRelation)
    print("Adding new nvd cve data:", len(dataWithoutRelation))

    # remove relation information
    for i in range(len(dataWithoutRelation)):
        dataWithoutRelation[i]["cwe"] = []

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
    print("cve data without relations loaded into dgraph")

    # create relations
    query = '''query all($name: string) {
        q(func: eq(name, $name)) {
            uid
            name
        }
    }
'''
    with open(fileName) as f:
        data = json.load(f) # json validation
    data = removeDuplidate(client ,data)

    for cve in data:
        txn = client.txn()
        res = txn.query(query, variables={'$name':cve["name"]})
        print(json.loads(res.json))
        currentUid = json.loads(res.json)["q"][0]["uid"]
        if len(cve["cwe"]) > 0:
            for cwe in cve["cwe"]:
                name = cwe["name"]
                res = txn.query(query, variables={'$name':name})
                res = json.loads(res.json)["q"]
                if len(res) == 0:
                    print("cwe not found:", name)
                    continue
                uid = res[0]["uid"]
                txn.mutate(set_nquads='<'+currentUid + '> <cwe> <' + uid + '> .')
        txn.commit()
    print("cve to cwe relations created")

if __name__ == '__main__':
    client_stub = pydgraph.DgraphClientStub('localhost:9080')
    client = pydgraph.DgraphClient(client_stub)
    
    update(client, "./result.json")
