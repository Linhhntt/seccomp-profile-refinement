import re
import json
import seccomp
import optparse

TEMPORAL_INITPHASE = "temporalMaster"
TEMPORAL_SERVINGPHASE = "temporalWorker"
INITPHASE = "init"
SERVINGPHASE = "serv"

def readFile(path):
    file = open(path, "r")
    data = file.read()
    file.close()
    return data

def str2Set(str, subCharacter):
    str = re.sub(subCharacter,'', str)
    str = re.split(', ', str)
    str = set(str)
    return str

def seccompHandler(appName):
    pathSeccomp = "../static_analysis/results/" + appName + ".syscall.out"
    seccomp_dict = dict()
    data = readFile(pathSeccomp)

    res = re.split('},', data)
    for i in range (0, len(res) - 1):
        tmp = re.split(': {', res[i].strip())
        if(TEMPORAL_INITPHASE in tmp[0]):
            seccomp_dict[TEMPORAL_INITPHASE] = tmp[1]
        if(TEMPORAL_SERVINGPHASE in tmp[0]):
            seccomp_dict[TEMPORAL_SERVINGPHASE] = tmp[1]

    # Get syscall lists of two phases
    syscalls = appPropertiesHandlerJson(appName)
    subChar = "'"
    seccomp1 = seccomp_dict[TEMPORAL_INITPHASE]
    seccomp1 = str2Set(seccomp1, subChar) | syscalls
    seccomp2 = seccomp_dict[TEMPORAL_SERVINGPHASE]
    seccomp2 = str2Set(seccomp2, subChar) | syscalls

    return seccomp1, seccomp2

def createSeccompProfile(appname, seccomp, phase, resultsFolder):
    if ( "/" in appname):
        outputPath = resultsFolder + "/" + appname.replace("/", "-") + "-" + phase + "seccomp.json"
    else:
        outputPath = resultsFolder + "/" + appname + "-" + phase + ".seccomp.json"
    outputFile = open(outputPath, 'w')
    outputFile.write(seccomp)
    outputFile.flush()
    outputFile.close()

def appPropertiesHandlerJson(appName):
    data = readFile('app.properties.json')
    data = json.loads(data)
    for appData in data["apps"]:
        syscalls = json.dumps(appData[appName])
        syscallsJson = json.loads(syscalls)
        syscalls = json.dumps(syscallsJson["syscalls"])
    
    subChar = '"'
    syscalls = str2Set(syscalls[1:len(syscalls)-1], subChar)
    
    return syscalls

if __name__ == "__main__":

    usage = "Usage: %prog -a <appName> -o <a temporary output folder to store seccomp profiles>"

    parser = optparse.OptionParser(usage=usage, version="1")
    parser.add_option("-a", "--appname", dest="appName", default=None, nargs=1,
                      help="AppName")

    parser.add_option("-o", "--outputfolder", dest="outputfolder", default=None, nargs=1,
                      help="Output folder path")

    (options, args) = parser.parse_args()
    appName = options.appName
    whileList = seccompHandler(appName)

    seccompProfile = seccomp.Seccomp()
    outputFolder = options.outputfolder
    

    whiteListProfile = seccompProfile.createProfile(list(whileList[0]))
    createSeccompProfile(appName, whiteListProfile, INITPHASE, outputFolder)
    whiteListProfile = seccompProfile.createProfile(list(whileList[1]))
    createSeccompProfile(appName, whiteListProfile, SERVINGPHASE, outputFolder)
