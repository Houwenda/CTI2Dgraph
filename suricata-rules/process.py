import re
import os
import json

cveRegex0 = re.compile(r"cve,\d{4}-\d+[^;]")  # cve,2000-0884;
cveRegex1 = re.compile(r"CVE-\d{4}-\d+") # CVE-2016-1287
cveRegex2 = re.compile(r"CVE_\d{4}_\d+") # CVE_2016_1287
cveRegex3 = re.compile(r"cve-\d{4}-\d+") # cve-2008-2992
cveRegex4 = re.compile(r"cve,CAN-\d{4}-\d+[^;]") # cve,CAN-2001-0540
cveRegex5 = re.compile(r"cve_\d{4}_\d+") # cve_2018_12636

sidRegex = re.compile(r"sid:\d+[^;]")

def getCveId0(line):
    m = cveRegex0.search(line)
    if m != None:
        cveIdRaw = line[m.start():m.end()]
        cveId = "CVE-"
        m = re.findall(r"\d+", cveIdRaw)
        cveId += m[0] + "-" + m[1]
        return cveId
    else:
        return ""
    
def getCveId1(line):
    m = cveRegex1.search(line)
    if m != None:
        cveId = line[m.start():m.end()]
        return cveId
    else:
        return ""

def getCveId2(line):
    m = cveRegex2.search(line)
    if m != None:
        cveIdRaw = line[m.start():m.end()]
        cveId = "CVE-"
        m = re.findall(r"\d+", cveIdRaw)
        cveId += m[0] + "-"+ m[1]
        return cveId
    else:
        return ""

def getCveId3(line):
    m = cveRegex3.search(line)
    if m != None:
        cveIdRaw = line[m.start():m.end()]
        cveId = "CVE-"
        m = re.findall(r"\d+", cveIdRaw)
        cveId += m[0] + "-"+ m[1]
        return cveId
    else:
        return ""

def getCveId4(line):
    m = cveRegex4.search(line)
    if m != None:
        cveIdRaw = line[m.start():m.end()]
        cveId = "CVE-"
        m = re.findall(r"\d+", cveIdRaw)
        cveId += m[0] + "-"+ m[1]
        return cveId
    else:
        return ""

def getCveId5(line):
    m = cveRegex5.search(line)
    if m != None:
        cveIdRaw = line[m.start():m.end()]
        cveId = "CVE-"
        m = re.findall(r"\d+", cveIdRaw)
        cveId += m[0] + "-"+ m[1]
        return cveId
    else:
        return ""

def getSigId(line):
    m = sidRegex.search(line)
    sigId = line[m.start()+4:m.end()]
    return sigId

def process(ruleFile, result):
    with open(ruleFile) as f:
        content = f.readlines()
    for line in content:
        if len(content) == 0 or content[0] == "#":
            continue

        # regex0
        cveId = getCveId0(line) # match result
        if len(cveId) != 0:
            sigId = getSigId(line)
            result.append((cveId, sigId))
            continue

        # regex1
        cveId = getCveId1(line) # match result
        if len(cveId) != 0:
            sigId = getSigId(line)
            result.append((cveId, sigId))
            continue

        # regex2
        cveId = getCveId2(line) # match result
        if len(cveId) != 0:
            sigId = getSigId(line)
            result.append((cveId, sigId))
            continue

        # regex3
        cveId = getCveId3(line) # match result
        if len(cveId) != 0:
            sigId = getSigId(line)
            result.append((cveId, sigId))
            continue

        # regex4
        cveId = getCveId4(line) # match result
        if len(cveId) != 0:
            sigId = getSigId(line)
            result.append((cveId, sigId))
            continue

        # regex5
        cveId = getCveId5(line) # match result
        if len(cveId) != 0:
            sigId = getSigId(line)
            result.append((cveId, sigId))
            continue

        # other circumstances
        # if re.search("cve", line.lower()) != None:
        #     print(line)

    return result

def processDir(path):
    result = []
    for (_, _, fileNames) in os.walk(path):
        for fileNameRaw in fileNames:
            _, extension = os.path.splitext(fileNameRaw)
            if extension == ".rules":
                result = process(path + "/" + fileNameRaw, result)
                # print(len(result))
    print("Total (cve,sig) : "+ str(len(result))) # 5475 (2021.3.17)
    return result

def rulesCountDir(path):
    totalCount = 0
    for (_, _, fileNames) in os.walk(path):
        for fileNameRaw in fileNames:
            _, extension = os.path.splitext(fileNameRaw)
            if extension == ".rules":
                with open(path + "/" + fileNameRaw) as f:
                    content = f.readlines()
                for line in content:
                    if len(line) > 0 and line[0] != "#":
                        totalCount += 1
    print("Total Rules: "+ str(totalCount)) # 48940 (2021.3.17)

def dump2jsonFile(path, targetFile):
    results = processDir(path)
    data = {}
    for result in results:
        data[result[1]] = {
            "sid": result[1],
            "cve": [],
            "dgraph.type": "SuricataRule"
        }
    for result in results:
        data[result[1]]["cve"].append(result[0])

    dumped = []
    for index in data:
        dumped.append(data[index])
    with open(targetFile, "w") as f:
        json.dump(dumped, f)
    print("dumped to file")

if __name__ == '__main__':
    # rulesCountDir("./rules")
    # processDir("./rules")
    dump2jsonFile("./rules", "./result.json")

    # print(process("./rules/emerging-attack_response.rules",[]))


# cat *.rules | grep cve | wc -l
# 5236

# cat *.rules | grep CVE | wc -l
# 4370

# cat *.rules | grep cve | grep CVE | wc -l
# 4115
