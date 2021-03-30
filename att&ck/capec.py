from stix2 import FileSystemSource
from stix2 import Filter
import pydgraph
import json
from dateutil.parser import parse
import rfc3339

def initGraphTypes(client):
    schema = '''
created_date: datetime .
last_modified_date: datetime .
likelihood: string .
prerequisites: [string] .
resources_required: [string] .
severity: string .
attack_technique: [uid] @reverse .
type Capec {
    name
    created_date
    last_modified_date
    name_full
    description
    reference
    likelihood
    prerequisites
    resources_required
    severity
    attack_technique
}
'''
    op = pydgraph.Operation(
        schema=schema, run_in_background=False)
    client.alter(op)
    print("schema initialized")

def load(client, src):
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.source_name', '=', 'capec'),
    ]
    results = src.query(filt)
    data = []
    for capecItem in results:
        tmpResult = {
            "name": "",
            "created_date": rfc3339.rfc3339(capecItem["created"]),
            "last_modified_date": rfc3339.rfc3339(capecItem["modified"]),
            "name_full": capecItem["name"],
            "description": [capecItem["description"]],
            "reference": [],
            "prerequisites": [],
            "resources_required": [],
            "dgraph.type": "Capec"
        }
        if "x_capec_likelihood_of_attack" in capecItem.keys():
            tmpResult["likelihood"] = capecItem["x_capec_likelihood_of_attack"]
        if "x_capec_prerequisites" in capecItem.keys():
            tmpResult["prerequisites"] = capecItem["x_capec_prerequisites"]
        if "x_capec_resources_required" in capecItem.keys():
            tmpResult["resources_required"] = capecItem["x_capec_resources_required"]
        if "x_capec_typical_severity" in capecItem.keys():
            tmpResult["severity"] = capecItem["x_capec_typical_severity"]
        
        
        for external_reference in capecItem["external_references"]:
            if external_reference["source_name"] == "capec":
                tmpResult["name"] = external_reference["external_id"]
            elif external_reference["source_name"] == "cwe":
                pass
            else:
                tmpExternalReference = {
                    "description": [external_reference["description"]],
                    "refsource": external_reference["source_name"],
                    "dgraph.type": "Reference"
                }
                if "url" in external_reference.keys():
                    tmpExternalReference["url"] = external_reference["url"]
                tmpResult["reference"].append(tmpExternalReference)

        data.append(tmpResult)

    print("Total capec:", len(data))

    totalCount = len(data)
    index = 0
    span = 100 # 100 records per transaction
    while index + span < totalCount :
        txn = client.txn()
        try:
            mu = pydgraph.Mutation(set_json=json.dumps(data[index:index+span]).encode('utf8'))
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
        mu = pydgraph.Mutation(set_json=json.dumps(data[index:]).encode('utf8'))
        txn.mutate(mu)
        txn.commit()
        index += span
    except pydgraph.AbortedError:
        print("error")
    finally:
        txn.discard()
    print("capec data without relations loaded")

# create link with cwe
def link2cwe(client, src):
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.source_name', '=', 'capec'),
    ]
    results = src.query(filt)

    query = '''query all($name: string) {
        q(func: eq(name, $name)) {
            uid
            name
        }
    }
'''

    for result in results:
        capecId = ""
        cweIds = []
        for external_reference in result["external_references"]:
            if external_reference["source_name"] == "capec":
                # print(external_reference["external_id"], end=" ")
                capecId = external_reference["external_id"]
            if external_reference["source_name"] == "cwe":
                # print(external_reference["external_id"], end=" ")
                cweIds.append(external_reference["external_id"])
        print(capecId, cweIds)

        txn = client.txn()
        res = txn.query(query, variables={'$name':capecId})
        capecUid = json.loads(res.json)["q"][0]["uid"]
        for cweId in cweIds:
            res = txn.query(query, variables={'$name':cweId})
            if len(json.loads(res.json)["q"]) > 0:
                cweUid = json.loads(res.json)["q"][0]["uid"]
                txn.mutate(set_nquads='<' + cweUid + '> <capec> <' + capecUid + '> .')
        txn.commit()

    print("cwe to capec relations created")

if __name__ == "__main__":
    fs = FileSystemSource('./att&ck/cti-ATT-CK-v8.2/capec')
    client_stub = pydgraph.DgraphClientStub('localhost:9080')
    client = pydgraph.DgraphClient(client_stub)

    initGraphTypes(client)
    load(client, fs) # total: 581
    link2cwe(client, fs)