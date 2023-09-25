import os, sys, subprocess, signal
import re

sys.path.insert(0, './python-utils/')

import container
import util
import bisect
import time
from datetime import datetime
import sysdig
import constants as C
import processMonitorFactory


class ContainerProfiler():
    """
    This class can be used to create a seccomp profile for a container through static anlyasis of the useful binaries
    """
    def __init__(self, name, imagePath, options,
                strictmode, fineGrain, extractAllBinaries, 
                 binLibList, monitoringTool, logger, maptype, args, isDependent=False):
        self.logger = logger
        self.name = name
        self.args = args
        self.imagePath = imagePath
        self.options = options
        self.strictMode = strictmode
        self.maptype = maptype
        self.status = False
        self.runnable = False
        self.installStatus = False
        self.debloatStatus = False
        self.errorMessage = ""
        self.languageSet = set()
        self.fineGrain = fineGrain
        self.extractAllBinaries = extractAllBinaries
        self.isDependent = isDependent
        self.containerName = None
        self.binLibList = binLibList
        self.monitoringTool = monitoringTool

    #TODO List
    '''
    1. Create required list of functions required by the container
        1.1. Run container
        1.2. Take snapshot of processes
        1.3. Copy binaries required and dependent libraries to host
        1.4. Extract imported libraries with objdump
    2. Map those functions to the required system calls
        2.1. Use libc callgraph to map imported libc functions to system calls
    3. Generate seccomp profile
    4. Test if the profile works with the container
    '''

    #New TODO
    '''
    1. Fix bug in tracking executed processes (SOLVED)
    2. Prevent single-time useable containers from stopping (hello-world, ubuntu, centos) (The true,false ones) (SOLVED in some cases)
    '''

    def usesMusl(self, folder):
        #return True
        for fileName in os.listdir(folder):
            if ( "musl" in fileName ):
                return True
        return False

    def getStatus(self):
        return self.status

    def getRunnableStatus(self):
        return self.runnable

    def getInstallStatus(self):
        return self.installStatus

    def getDebloatStatus(self):
        return self.debloatStatus

    def getErrorMessage(self):
        return self.errorMessage

    def getLanguageSet(self):
        return self.languageSet

    def getContainerName(self):
        return self.containerName

    def createSeccompProfile(self, tempOutputFolder):
        returnCode = 0
        if os.geteuid() != 0:
            self.logger.error("This script must be run as ROOT only!")
            exit("This script must be run as ROOT only. Exiting.")
        self.logger.debug("tempOutputFolder: %s", tempOutputFolder)

        binaryReady = False
        libFileReady = False

        try:
            self.logger.debug("Checking cache in %s", tempOutputFolder)
            myFile = open(tempOutputFolder + "/" + C.CACHE, 'r')
            binaryReady = True
            myFile = open(tempOutputFolder + "/" + C.LIBFILENAME, 'r')
            libFileReady = True
        except OSError as e:
            self.logger.info("Cache doesn't exist, must extract binaries and libraries")

        self.logger.debug("binaryReady: %s libFileReady: %s", str(binaryReady), str(libFileReady))

        myContainer = container.Container(self.imagePath, self.options, self.logger, self.args)
        self.containerName = myContainer.getContainerName()

        if ( not myContainer.pruneVolumes() ):
            self.logger.warning("Pruning volumes failed, storage may run out of space\n")
        returncode, out, err = util.runCommand("mkdir -p " + tempOutputFolder)
        if ( returncode != 0 ):
            self.logger.error("Failed to create directory: %s with error: %s", tempOutputFolder, err)
        else:
            self.logger.debug("Successfully created directory: %s", tempOutputFolder)

        ttr = 10
        logSleepTime = 60
        sysdigTotalRunCount = 3
        if ( binaryReady ):
            sysdigTotalRunCount = 1
        sysdigRunCount = 1

        if ( self.name == "softwareag-apigateway" ):
            logSleepTime = 60

        if ( self.name == "cirros" ):
            logSleepTime = 120
        

        psListAll = set()

        self.logger.info("--->Starting MONITOR phase:")
        while ( sysdigRunCount <= sysdigTotalRunCount ):
            myMonitor = processMonitorFactory.Factory(self.logger, self.monitoringTool, psListFilePath=self.binLibList)
            # subprocess.run(["insmod", "/lib/modules/5.8.0-050800-generic/updates/dkms/sysdig-probe.ko"])
            #mySysdig = sysdig.Sysdig(self.logger)
            self.logger.debug("Trying to kill and delete container which might not be running in loop... Not a problem if returns error")
            str(myContainer.kill())
            str(myContainer.delete())
            self.logger.info("Running %s multiple times. Run count: %d from total: %d",myMonitor, sysdigRunCount, sysdigTotalRunCount)

            sysdigRunCount += 1
            #sysdigResult = mySysdig.runSysdigWithDuration(logSleepTime)
            monitorResult = myMonitor.runWithDuration(logSleepTime)
            if ( not monitorResult ):
                self.logger.error("Running sysdig with execve failed, not continuing for container: %s", self.name)
                self.logger.error("Please make sure sysdig is installed and you are running the script with root privileges. If problem consists please contact our support team.")
                self.errorMessage = "Running sysdig with execve failed"
            
            if ( monitorResult and myContainer.runWithoutSeccomp() ):#myContainer.run() ):
                self.status = True
                self.logger.info("Ran container sleeping for %d seconds to generate logs and extract execve system calls", logSleepTime)
                time.sleep(logSleepTime)
                myMonitor.waitUntilComplete()
                originalLogs = myContainer.checkLogs()
                self.logger.debug("originalLog: %s", originalLogs)
                time.sleep(10)
                if ( not myContainer.checkStatus() ):
                    self.logger.warning("Container exited after running, trying to run in attached mode!")
                    self.logger.debug(str(myContainer.delete()))
                    if ( not myContainer.runInAttachedMode() ):
                        self.errorMessage = "Container didn't run in attached mode either, forfeiting!"
                        self.logger.error("Container didn't run in attached mode either, forfeiting!")
                        self.logger.error("There is a problem launching a container for %s. Please validate you can run the container without Confine. If so, contact our support team.", self.name)
                        self.logger.debug(str(myContainer.delete()))
                        return C.NOATTACH
                    else:
                        time.sleep(10)
                        if ( not myContainer.checkStatus() ):
                            self.errorMessage = "Container got killed after running in attached mode as well!"
                            self.logger.error("Container got killed after running in attached mode as well, forfeiting!")
                            self.logger.error("There is a problem launching a container for %s. Please validate you can run the container without Confine. If so, contact our support team.", self.name)
                            self.logger.debug(str(myContainer.kill()))
                            self.logger.debug(str(myContainer.delete()))
                            return C.CONSTOP
                self.runnable = True
                self.logger.debug("Ran container %s successfully, sleeping for %d seconds", self.name, ttr)
                time.sleep(ttr)
                self.logger.debug("Finished sleeping, extracting psNames for %s", self.name)
                self.logger.debug("Starting to identify running processes and required binaries and libraries through dynamic analysis.")

                if ( not binaryReady ):
                    psList = myMonitor.extractPsNames("execve", myContainer.getContainerName(), myContainer.getContainerId())

                    if ( not psList ):
                        self.logger.error("PS List is None from extractPsNames(). Retrying this container: %s", self.name)
                        self.logger.debug(str(myContainer.kill()))
                        self.logger.debug(str(myContainer.delete()))
                        self.errorMessage = "PS List is None from extractPsNames(), error in sysdig, retrying this container"
                        return C.SYSDIGERR
                    if ( len(psList) == 0 ):
                        self.logger.error("PS List is None from extractPsNames(). Retrying this container: %s", self.name)
                        self.logger.debug(str(myContainer.kill()))
                        self.logger.debug(str(myContainer.delete()))
                        self.errorMessage = "PS List is None from extractPsNames(), error in sysdig, retrying this container"
                        return C.NOPROCESS
                    self.logger.info("len(psList) from sysdig: %d", len(psList))
                    # TODO: Do we need to do this?  Or can we just rely on copyFromContainerWithLibs below
                    psList = psList.union(myContainer.extractLibsFromProc())
                    self.logger.debug("len(psList) after extracting proc list: %d", len(psList))
                    self.logger.debug("Container: %s PS List: %s", self.name, str(psList))
                    self.logger.debug("Container: %s extracted psList with %d elements", self.name, len(psList))
                    self.logger.debug("Entering not binaryReady")
                    if ( not util.deleteAllFilesInFolder(tempOutputFolder, self.logger) ):
                        self.logger.error("Failed to delete files in temporary output folder, exiting...")
                        self.errorMessage = "Failed to delete files in temporary output folder"
                        sys.exit(-1)

                    psListAll.update(psList)
                    self.logger.info("Container: %s extracted psList with %d elements", self.name, len(psListAll))

        if ( self.status ):
            if ( not binaryReady ):
                self.logger.info("Container: %s PS List: %s", self.name, str(psListAll))
                self.logger.info("Starting to copy identified binaries and libraries (This can take some time...)")#Will try to copy from different paths. Some might not exist. Errors are normal.")
                if ( self.extractAllBinaries ):
                    psListAll.update(myContainer.extractAllBinaries())

                for binaryPath in psListAll:
                    if ( binaryPath.strip() != "" ):
                        myContainer.copyFromContainerWithLibs(binaryPath, tempOutputFolder)
                        #if ( not myContainer.copyFromContainerWithLibs(binaryPath, tempOutputFolder) ):
                        #    self.logger.error("Problem copying files from container!")
                binaryReady = True
                myFile = open(tempOutputFolder + "/" + C.CACHE, 'w')
                myFile.write("complete")
                myFile.flush()
                myFile.close()
                self.logger.info("Finished copying identified binaries and libraries")
                self.logger.info("<---Finished MONITOR phase\n")

            self.logger.debug(str(myContainer.kill()))
            self.logger.debug(str(myContainer.delete()))

        return returnCode

import logging
if __name__ == '__main__':
    rootLogger = logging.getLogger("test")
    rootLogger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    rootLogger.addHandler(handler)
    mySysdig = sysdig.Sysdig(rootLogger)

    myContainer = container.Container("nginx", "", rootLogger)
    sysdigResult = mySysdig.runWithDuration(60)
    if ( not sysdigResult ):
        rootLogger.error("Running sysdig with execve failed, not continuing for container: %s", self.name)
        rootLogger.error("Please make sure sysdig is installed and you are running the script with root privileges. If problem consists please contact our support team.")

    if ( sysdigResult and myContainer.runWithoutSeccomp() ):#myContainer.run() ):
        rootLogger.info("Ran container sleeping for %d seconds to generate logs and extract execve system calls", 60)
        time.sleep(60)
        originalLogs = myContainer.checkLogs()
        rootLogger.debug("originalLog: %s", originalLogs)

    rootLogger.debug("Trying to kill and delete container which might not be running in loop... Not a problem if returns error")
    str(myContainer.kill())
    str(myContainer.delete())

    psList = mySysdig.extractPsNames("execve", myContainer.getContainerName())

    rootLogger.info("psList: %s", psList)