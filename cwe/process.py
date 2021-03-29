import csv
import os
import json

header = [
    'CWE-ID', 
    'Name', 
    'Weakness Abstraction', 
    'Status', 
    'Description', 
    'Extended Description', 
    'Related Weaknesses', 
    'Weakness Ordinalities', 
    'Applicable Platforms', 
    'Background Details', 
    'Alternate Terms', 
    'Modes Of Introduction',
    'Exploitation Factors', 
    'Likelihood of Exploit', 
    'Common Consequences', 
    'Detection Methods', 
    'Potential Mitigations', 
    'Observed Examples', 
    'Functional Areas', 
    'Affected Resources', 
    'Taxonomy Mappings', 
    'Related Attack Patterns', 
    'Notes']

def process(fileName, result):
    lineCount = 0
    with open(fileName) as f:
        reader = csv.reader(f)
        for row in reader:
            if lineCount == 0:
                lineCount += 1
                continue
            tmpResult = {
                "name": "CWE-"+row[0],
                "name_full": row[1],
                "description": [
                    row[4]
                ],
                "child_of": [],
                "peer_of": [],
                "can_precede": [],
                "can_also_be": [],
                "capec": [],
                "dgraph.type": "Cwe"
            }
            if len(row[5]) > 0 :
                tmpResult["description"].append(row[5])

            # Related Weaknesses -> child_of, peer_of, can_precede, can_also_be
            related = row[6]
            related = related.split("::")
            for item in related:
                if len(item) == 0:
                    continue
                keyValueStream = item.split(":")
                print(keyValueStream)
                if keyValueStream[0] == "NATURE": # valid
                    relation = keyValueStream[1]
                    cweId = keyValueStream[3]
                    if relation == "ChildOf":
                        tmpResult["child_of"].append("CWE-"+cweId)
                    elif relation == "PeerOf":
                        tmpResult["peer_of"].append("CWE-"+cweId)
                    elif relation == "CanPrecede":
                        tmpResult["can_precede"].append("CWE-"+cweId)
                    elif relation == "CanAlsoBe":
                        tmpResult["can_also_be"].append("CWE-"+cweId)
                    else:
                        print("unknown relation:", related)
                        break

            # Related Attack Patterns -> capec
            related = row[21].split("::")
            for item in related:
                if len(item) == 0:
                    continue
                tmpResult["capec"].append("CAPEC-"+item)

            result[row[0]] = tmpResult
    return result

def processDir(path):
    result = {}
    for (_, _, fileNames) in os.walk(path):
        for fileNameRaw in fileNames:
            _, extension = os.path.splitext(fileNameRaw)
            if extension == ".csv":
                result = process(path + "/" + fileNameRaw, result)
                print(len(result))
    print("Total CWE : "+ str(len(result))) 
    return result

def dump2jsonFile(path, targetFile):
    results = processDir(path)
    dumps = []
    for index in results:
        dumps.append(results[index])
    with open(targetFile,"w") as f:
        json.dump(dumps, f)
    print("dumped to json file")

if __name__ == '__main__':
    dump2jsonFile("./cwe", "result.json")

    # processDir("./cwe")

    # result = {}
    # result = process("./cwe/699.csv", result)
    # print(result)
