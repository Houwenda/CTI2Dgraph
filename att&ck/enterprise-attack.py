from stix2 import FileSystemSource
from stix2 import Filter
import pydgraph
import json
from dateutil.parser import parse
import rfc3339

def initGraphTypes(client):
    schema = '''
kill_chain_phase: [string] .
platform: [string] .
type AttackTechnique {
    name
    created_date
    last_modified_date
    name_full
    description
    reference
    kill_chain_phase
    platform
    url
}
'''
    op = pydgraph.Operation(
        schema=schema, run_in_background=False)
    client.alter(op)
    print("schema initialized")


def load(client, src):
    filt = [
        Filter('type', '=', 'attack-pattern'),
    ]
    results = src.query(filt)
    data = []
    
    for attackItem in results:
        tmpResult = {
            "name": "",
            "created_date": rfc3339.rfc3339(attackItem["created"]),
            "last_modified_date": rfc3339.rfc3339(attackItem["modified"]),
            "name_full": attackItem["name"],
            "reference": [],
            "kill_chain_phase": [],
            "dgraph.type": "AttackTechnique"
        }
        if "description" in attackItem.keys():
            tmpResult["description"] = [attackItem["description"]]
        if "x_mitre_platforms" in attackItem.keys():
            tmpResult["platform"] = attackItem["x_mitre_platforms"]
        if "kill_chain_phases" in attackItem.keys():
            for kill_chain_phase in attackItem["kill_chain_phases"]:
                tmpResult["kill_chain_phase"].append(kill_chain_phase["phase_name"])

        for external_reference in attackItem["external_references"]:
            if external_reference["source_name"] == "mitre-attack":
                tmpResult["name"] = external_reference["external_id"]
                tmpResult["url"] = external_reference["url"]
            elif external_reference["source_name"] == "capec":
                # print(external_reference["external_id"], end=" ")
                pass
            else:
                tmpExternalReference = {
                    "description": external_reference["description"],
                    "refsource": external_reference["source_name"],
                    "dgraph.type": "Reference"
                }
                if "url" in external_reference.keys():
                    tmpExternalReference["url"] = external_reference["url"]
                tmpResult["reference"].append(tmpExternalReference)
        
        data.append(tmpResult)
        
    print("Total attach techniques:", len(results)) # 670

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
    print("enterprise att&ck technique data without relations loaded")

# create link with cwe
def link2capec(client, src):
    filt = [
        Filter('type', '=', 'attack-pattern'),
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
        attackTechniqueId = ""
        capecIds = []
        for external_reference in result["external_references"]:
            if external_reference["source_name"] == "mitre-attack":
                attackTechniqueId = external_reference["external_id"]
            elif external_reference["source_name"] == "capec":
                capecIds.append(external_reference["external_id"])
        print(attackTechniqueId, capecIds)

        txn = client.txn()
        res = txn.query(query, variables={'$name':attackTechniqueId})
        attackTechniqueUid = json.loads(res.json)["q"][0]["uid"]
        for capecId in capecIds:
            res = txn.query(query, variables={'$name':capecId})
            if len(json.loads(res.json)["q"]) > 0:
                capecUid = json.loads(res.json)["q"][0]["uid"]
                txn.mutate(set_nquads='<' + capecUid + '> <attack_technique> <' + attackTechniqueUid + '> .')
        txn.commit()

    print("capec to att&ck technique relations created")

if __name__ == '__main__':
    client_stub = pydgraph.DgraphClientStub('localhost:9080')
    client = pydgraph.DgraphClient(client_stub)
    fs = FileSystemSource('./att&ck/cti-ATT-CK-v8.2/enterprise-attack')
    
    initGraphTypes(client)
    load(client, fs)
    link2capec(client, fs)