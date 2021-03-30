import pydgraph
import json

def clearDatabase(client):
    op = pydgraph.Operation(drop_all=True)
    client.alter(op)
    print("database cleared up")

def initGraphTypes(client):
    schema = """
name: string @index(exact) .
name_full: string @index(exact) .
description: [string] .
child_of: [uid] @reverse .
peer_of: [uid] @reverse .
can_precede: [uid] @reverse .
can_also_be: [uid] @reverse .
capec: [uid] @reverse .
type Cwe {
    name
    name_full
    description
    child_of
    peer_of
    can_precede
    can_also_be
    capec
}
"""
    op = pydgraph.Operation(schema=schema,
        run_in_background=False)
    client.alter(op)
    print("schema initialized")

def loadFromJsonFile(client, fileName):
    with open(fileName) as f:
        data = json.load(f) # json validation

    with open(fileName) as f:
        dataWithoutRelation = json.load(f)
    # remove relation information
    for i in range(len(dataWithoutRelation)):
        dataWithoutRelation[i]["child_of"] = []
        dataWithoutRelation[i]["peer_of"] = []
        dataWithoutRelation[i]["can_precede"] = []
        dataWithoutRelation[i]["can_also_be"] = []
        dataWithoutRelation[i]["capec"] = []
    
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
    print("json data without relations loaded into dgraph")

    # create relations
    query = '''query all($name: string) {
        q(func: eq(name, $name)) {
            uid
            name
        }
    }
'''
    for cwe in data:
        txn = client.txn()
        res = txn.query(query, variables={'$name':cwe["name"]})
        print(json.loads(res.json))
        currentUid = json.loads(res.json)["q"][0]["uid"]
        if len(cwe["child_of"]) > 0:
            for name in cwe["child_of"]:
                res = txn.query(query, variables={'$name':name})
                uid = json.loads(res.json)["q"][0]["uid"]
                txn.mutate(set_nquads='<'+currentUid + '> <child_of> <' + uid + '> .')
                print("child_of")
        if len(cwe["peer_of"]) > 0:
            for name in cwe["peer_of"]:
                res = txn.query(query, variables={'$name':name})
                uid = json.loads(res.json)["q"][0]["uid"]
                txn.mutate(set_nquads='<'+currentUid + '> <peer_of> <' + uid + '> .')
                print("peer_of")
        if len(cwe["can_precede"]) > 0:
            for name in cwe["can_precede"]:
                res = txn.query(query, variables={'$name':name})
                uid = json.loads(res.json)["q"][0]["uid"]
                txn.mutate(set_nquads='<'+currentUid + '> <can_precede> <' + uid + '> .')
                print("can_precede")
        if len(cwe["can_also_be"]) > 0:
            for name in cwe["can_also_be"]:
                res = txn.query(query, variables={'$name':name})
                uid = json.loads(res.json)["q"][0]["uid"]
                txn.mutate(set_nquads='<'+currentUid + '> <can_also_be> <' + uid + '> .')
                print("can_also_be")
        # cannot create link to capec now
        # if len(cwe["capec"]) > 0:
        #     for name in cwe["capec"]:
                # res = txn.query(query, variables={'$name':name})
                # uid = json.loads(res.json)["q"][0]["uid"]
                # txn.mutate(set_nquads='<'+currentUid + '> <capec> <' + uid + '> .')
                # print("capec")
        txn.commit()
    print("cwe to cwe relations created")
    
if __name__ == '__main__':
    client_stub = pydgraph.DgraphClientStub('localhost:9080')
    client = pydgraph.DgraphClient(client_stub)
    clearDatabase(client)
    initGraphTypes(client)
    loadFromJsonFile(client, "./result.json")
    
    # takes around 1 minute