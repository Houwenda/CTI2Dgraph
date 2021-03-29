import json
import re
import os
from dateutil.parser import parse
import rfc3339

cweRegex = re.compile(r"CWE-\d+")


def cweCount(fileName):
    with open(fileName) as f:
        cveData = json.load(f)
    print(len(cveData["CVE_Items"]))
    withCweCount = 0
    for cveItem in cveData["CVE_Items"]:
        cve = cveItem["cve"]
        cveId = cve["CVE_data_meta"]["ID"]
        for problemtype_data in cve["problemtype"]["problemtype_data"]:
            for description in problemtype_data["description"]:
                if "NVD" not in description["value"]:  # valid cwe-id
                    print(cveId, "--", description["value"])
                    withCweCount += 1
            if len(problemtype_data["description"]) > 1:
                print("More than 1 cwe found")
    print("Total cve records with cwe label:", withCweCount)
    return withCweCount


def cve2cweCount():
    totalCount = 0
    for i in range(2, 22):
        if i < 10:
            totalCount += cweCount("./cve/nvdcve-1.1-200"+str(i)+".json")
        else:
            totalCount += cweCount("./cve/nvdcve-1.1-20"+str(i)+".json")
    print(totalCount)  # 110752 cve records have linked cwe id


def process(fileName, result):
    with open(fileName) as f:
        cveData = json.load(f)
    for cveItem in cveData["CVE_Items"]:
        tmpResult = {
            "name": cveItem["cve"]["CVE_data_meta"]["ID"],
            "cwe": [],
            "reference": [],
            "description": [],
            "impact": {},
            "publishedDate": rfc3339.rfc3339(parse(cveItem["publishedDate"])),
            "lastModifiedDate": rfc3339.rfc3339(parse(cveItem["lastModifiedDate"])),
            "dgraph.type": "Cve"
        }
        cve = cveItem["cve"]
        # cwe
        for problemtype_data in cve["problemtype"]["problemtype_data"]:
            for description in problemtype_data["description"]:
                if cweRegex.match(description["value"]) != None:  # valid cwe-id
                    tmpResult["cwe"].append({
                        "name": description["value"],
                        "dgraph.type": "Cwe"
                    })
        # reference
        for reference_data in cve["references"]["reference_data"]:
            tmpResult["reference"].append({
                "url": reference_data["url"],
                "name": reference_data["name"],
                "refsource": reference_data["refsource"],
                "tag": reference_data["tags"],
                "dgraph.type": "Reference"
            })
        # description
        for description_data in cve["description"]["description_data"]:
            tmpResult["description"].append(description_data["value"])
        # impact
        if "baseMetricV2" in cveItem["impact"].keys():
            baseMetricV2 = cveItem["impact"]["baseMetricV2"]
            if "userInteractionRequired" in baseMetricV2.keys():
                tmpResult["impact"]["userInteractionRequired"] = baseMetricV2["userInteractionRequired"]
            tmpResult["impact"] = {
                    "severity": baseMetricV2["severity"],
                    "exploitabilityScore": baseMetricV2["exploitabilityScore"],
                    "impactScore": baseMetricV2["impactScore"],
                    "obtainAllPrivilege": baseMetricV2["obtainAllPrivilege"],
                    "obtainUserPrivilege": baseMetricV2["obtainUserPrivilege"],
                    "obtainOtherPrivilege": baseMetricV2["obtainOtherPrivilege"],
                    # "userInteractionRequired": baseMetricV2["userInteractionRequired"],
                    "dgraph.type": "Impact"
                }
        result.append(tmpResult)
        # print(json.dumps(tmpResult))
    return result

def processDir(path):
    result = []
    for (_, _, fileNames) in os.walk(path):
        for fileNameRaw in fileNames:
            _, extension = os.path.splitext(fileNameRaw)
            if extension == ".json":
                result = process(path + "/" + fileNameRaw, result)
                # print(len(result))
    print("Total NVD-CVE : "+ str(len(result))) # 159442 (2021.3.18)
    return result

def dump2jsonFile(path, targetFile):
    result = processDir(path)
    with open(targetFile, "w") as f:
        json.dump(result, f)
    print("dumped to json file")


if __name__ == '__main__':
    dump2jsonFile("./cve", "./result.json")

    # processDir("./cve")

    # result = []
    # process("./cve/nvdcve-1.1-2002.json", result)
    # print(json.dumps(result))

    # cweCount("./cve/nvdcve-1.1-2002.json")

    
