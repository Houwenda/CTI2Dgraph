import pydgraph
import json

def save2dgraph():
    pass

def initGraphTypes(client):
    schema = '''
cwe: [uid] @reverse . 
reference: [uid] .

impact: uid .
publishedDate: dateTime .
lastModifiedDate: dateTime .

type Cve {
    name 
    cwe
    reference
    description
    impact
    publishedDate
    lastModifiedDate
}

url: string .
refsource: string .
tag: [string] .

type Reference {
    url
    name
    refsource
    tag
}

severity: string .
exploitabilityScore: float .
impactScore: float .
obtainAllPrivilege: bool .
obtainUserPrivilege: bool .
obtainOtherPrivilege: bool .
userInteractionRequired: bool .

type Impact {
    severity
    exploitabilityScore
    impactScore
    obtainAllPrivilege
    obtainUserPrivilege
    obtainOtherPrivilege
    userInteractionRequired
}
'''
    op = pydgraph.Operation(
        schema=schema, run_in_background=False)
    client.alter(op)
    print("schema initialized")


def testJsonLoad(client):
    testCve = {
        "name": "CVE-test-test",
        "cwe": [],
        "reference": [
            {
                "url": "http://houwenda.github.io",
                "name": "houwenda",
                "refsource": "houwenda",
                "tag":[],
                "dgraph.type": "Reference"
            }
        ],
        "description": ["test description", "test description2"],
        "impact": {
            "severity":"MEDIUM",
            "exploitabilityScore":10.0,
            "impactScore":2.9,
            "obtainAllPrivilege":False,
            "obtainUserPrivilege":False,
            "obtainOtherPrivilege":False,
            "userInteractionRequired":False,
            "dgraph.type":"Impacet"
        },
        "publishedDate": "1999-12-30T05:00Z",
        "lastModifiedDate": "2010-12-16T05:00Z",
        "dgraph.type": "Cve"
    }

    print(json.dumps(testCve).encode('utf8'))

    txn = client.txn()
    try:
        mu = pydgraph.Mutation(set_json=json.dumps(testCve).encode('utf8'))
        txn.mutate(mu)
        txn.commit()
    except pydgraph.AbortedError:
        print("error")
    finally:
        txn.discard()
    print("test json loaded")

def testJsonQuery(client):
    query = '''
{
  test(func: type(Cve)) {
    uid
    name 
    cwe{
      name
    }
    reference {
      url
      name
      refsource
      tag
    }
    description
    impact {
      severity
      exploitabilityScore
      impactScore
      obtainAllPrivilege
      obtainUserPrivilege
      obtainOtherPrivilege
      userInteractionRequired
    }
    publishedDate
    lastModifiedDate
  }
}
'''
    txn = client.txn()
    res = txn.query(query)
    print(json.loads(res.json))

def loadFromJsonFile(client, fileName):
    with open(fileName) as f:
        dataWithoutRelation = json.load(f) # json validation
        
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
    print("json data without relation loaded into dgraph")

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
    print("relations created")

if __name__ == '__main__':
    client_stub = pydgraph.DgraphClientStub('localhost:9080')
    client = pydgraph.DgraphClient(client_stub)
    initGraphTypes(client)
    # testJsonLoad(client)
    # testJsonQuery(client)
    loadFromJsonFile(client, "./result.json")
    
    # takes around 10 minutes