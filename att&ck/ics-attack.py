from stix2 import FileSystemSource
from stix2 import Filter
import pydgraph
import json
from dateutil.parser import parse
import rfc3339

def load(client, src):
    filt = [
        Filter('type', '=', 'attack-pattern'),
    ]
    results = src.query(filt)

    # print(len(results)) # 81
    # print(results[0])

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
            if external_reference["source_name"] == "mitre-ics-attack":
                tmpResult["name"] = external_reference["external_id"]
                tmpResult["url"] = external_reference["url"]
            else: # no link with capec
                tmpExternalReference = {
                    "description": external_reference["description"],
                    "refsource": external_reference["source_name"],
                    "dgraph.type": "Reference"
                }
                if "url" in external_reference.keys():
                    tmpExternalReference["url"] = external_reference["url"]
                tmpResult["reference"].append(tmpExternalReference)
        
        data.append(tmpResult)
    # print(data)

    txn = client.txn()
    try:
        mu = pydgraph.Mutation(set_json=json.dumps(data[:]).encode('utf8'))
        txn.mutate(mu)
        txn.commit()
    except pydgraph.AbortedError:
        print("error")
    finally:
        txn.discard()
    print("ics att&ck technique data without relations loaded")


if __name__ == '__main__':
    client_stub = pydgraph.DgraphClientStub('localhost:9080')
    client = pydgraph.DgraphClient(client_stub)
    fs = FileSystemSource('./att&ck/cti-ATT-CK-v8.2/ics-attack')

    load(client, fs)