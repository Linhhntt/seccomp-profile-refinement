import sys
import os
import re
sys.path.insert(0, './python-utils/')

import util
import graph
import binaryAnalysis

class Piecewise:
    """
    This class can be used to perform debloating based on the piece-wise paper (they should've released and extendable code, but didn't)
    """
    def __init__(self, appName, binaryPath, binaryCfgPath, libcCfgPath, cfgPath, logger, cfginputseparator=":"):
        self.appName = appName
        self.binaryPath = binaryPath
        self.binaryCfgPath = binaryCfgPath
        self.libcCfgPath = libcCfgPath
        self.cfgPath = cfgPath
        self.libcSeparator = cfginputseparator
        self.logger = logger

    def cleanLib(self, libName):
        if ( ".so" in libName ):
            libName = re.sub("-.*so",".so",libName)
            libName = libName[:libName.index(".so")]
            #libName = libName + ".so"
        return libName
    
    def extractDirectSyscalls(self, folder):
        #exceptList = ["lib", "grep", "sed", "bash", "sh"]
        exceptList = ["ld.so", "libc.so", "libdl.so", "libcrypt.so", "libnss_compat.so", "libnsl.so", "libnss_files.so", "libnss_nis.so", "libpthread.so", "libm.so", "libresolv.so", "librt.so", "libutil.so", "libnss_dns.so", "gosu"]
        lib = ".so"

        fileList = list()
        filesAdded = set()
        finalSyscallSet = set()
        for fileName in os.listdir(folder):
            if ( util.isElf(folder + "/" + fileName) ):
                if ( lib in fileName ):
                    tmpFileName = re.sub("-.*so",".so",fileName)
                    tmpFileName = tmpFileName[:tmpFileName.index(".so")]
                    tmpFileName = tmpFileName + ".so"
                else:
                    tmpFileName = fileName
                if ( tmpFileName not in exceptList and tmpFileName not in filesAdded ):
                    fileList.append(folder + "/" + fileName)
                    filesAdded.add(tmpFileName)
        finalSet = set(fileList)# - set(removeList)
        for filePath in finalSet:
            self.logger.info("extraction direct syscall for %s", filePath)
            binAnalysis = binaryAnalysis.BinaryAnalysis(filePath, self.logger)
            syscallSet, successCount, failCount = binAnalysis.extractDirectSyscalls()
            self.logger.info("Successfull direct syscalls: %d list: %s, Failed direct syscalls: %d", successCount, str(syscallSet), failCount)
            #self.logger.warning("Failed syscalls: %d", failCount)
            finalSyscallSet.update(syscallSet)
        return finalSyscallSet

    def createCompleteGraph(self, exceptList=list()):
        '''TODO
        1. Extract required libraries from binary (ldd)
        2. Find call graph for each library from specified folder (input: callgraph folder)
        3. Create start->leaves graph from complete call graph
        4. Create complete global graph for application along with all libraries
            Complete graph:
                Application: entire graph
                Libc: entire graph
                Other Libraries: start->leave partition
        '''

        # Extract Direct Binaries
        self.logger.info("--->Starting Direct Syscall Extraction")
        self.logger.info("Extracting direct system call invocations")
        directSyscallSet = self.extractDirectSyscalls(self.binaryPath)
        self.logger.info("<---Finished Direct Syscall Extraction\n")
        self.logger.info("directSyscallSet: %s", directSyscallSet)

        # librarySyscalls.update(directSyscallSet)
        
        # functionList = util.extractImportedFunctions(self.binaryPath + "libs.out", self.logger)
        # self.logger.info("functionList init: %s", functionList)

        # functionListTmp = util.extractImportedFunctions(self.binaryPath + "libs.out.copy", self.logger)
        # self.logger.info("functionListTmp init: %s", functionListTmp)

        # functionList.append(functionListTmp)
        # self.logger.info("functionList final: %s", functionList)



        libcRelatedList = ["ld", "libc", "libdl", "libcrypt", "libnss_compat", "libnsl", "libnss_files", "libnss_nis", "libpthread", "libm", "libresolv", "librt", "libutil", "libnss_dns"]
        libraryCfgGraphs = dict()
        librarySyscalls = set()  #Only for libraries which we DO NOT have the CFG
        librarySyscalls.update(directSyscallSet) 
        libraryToPathDict = util.readLibrariesWithLdd(self.binaryPath + self.appName)
        # libraryToPathDictAdd = util.readLibrariesWithLdd(self.binaryPath + self.appName + ".copy")
        # libraryToPathDict.update(libraryToPathDictAdd)

        startNodeToLibDict = dict()

        libcGraph = graph.Graph(self.logger)
        libcGraph.createGraphFromInput(self.libcCfgPath, self.libcSeparator)

        completeGraph = graph.Graph(self.logger)
        self.logger.info("binaryCfgPath: %s", self.binaryCfgPath)
        result = completeGraph.createGraphFromInput(self.binaryCfgPath)
        if ( result == -1 ):
            self.logger.error("Failed to create graph for input: %s", self.binaryCfgPath)
            sys.exit(-1)
        
        for libraryName, libPath in libraryToPathDict.items():
            #self.logger.info("Checking library: %s", libraryName)
            libraryCfgFileName = self.cleanLib(libraryName) + ".callgraph.out"
            libraryCfgFilePath = self.cfgPath + "/" + libraryCfgFileName
            if ( libraryName not in libcRelatedList and libraryName not in exceptList ):
                if ( os.path.isfile(libraryCfgFilePath) ):
                    #We have the CFG for this library
                    self.logger.info("The library call graph exists for: %s", libraryName)

                    libraryGraph = graph.Graph(self.logger)
                    libraryGraph.createGraphFromInput(libraryCfgFilePath)
                    #self.logger.info("Finished create graph object for library: %s", libraryName)
                    libraryStartNodes = libraryGraph.extractStartingNodes()
                    #self.logger.info("Finished extracting start nodes for library: %s", libraryName)

                    #We're going keep a copy of the full library call graph, for later stats creation
                    libraryCfgGraphs[libraryName] = libraryGraph

                    #(Step 3 in todo list): We're going to make a smaller graph containing only start nodes and end nodes
                    #libraryStartToEndGraph = graph.Graph(self.logger)

                    for startNode in libraryStartNodes:
                        #if ( startNodeToLibDict.get(startNode, None) ):
                        #    self.logger.warning("library startNode seen in more than one library: %s and %s", libraryName, startNodeToLibDict[startNode])
                        startNodeToLibDict[startNode] = libraryName
                        leaves = libraryGraph.getLeavesFromStartNode(startNode, list(), list())
                        for leaf in leaves:
                            #self.logger.debug("Adding edge %s->%s from library: %s to complete graph.", startNode, leaf, libraryName)
                            #libraryStartToEndGraph.addEdge(startNode, leaf)
                            completeGraph.addEdge(startNode, leaf)
                    #libraryGraphs[libraryName] = libraryStartToEndGraph
                elif ( os.path.isfile(libPath) ):
                    #We don't have the CFG for this library, all exported functions will be considered as starting nodes in our final graph
                    self.logger.info("The library call graph doesn't exist, considering all imported functions for: %s", libraryName)
                    libraryProfiler = binaryAnalysis.BinaryAnalysis(libPath, self.logger)
                    directSyscallSet, successCount, failedCount  = libraryProfiler.extractDirectSyscalls()
                    indirectSyscallSet = libraryProfiler.extractIndirectSyscalls(libcGraph)

                    librarySyscalls.update(directSyscallSet)
                    librarySyscalls.update(indirectSyscallSet)
            #    else:
                    #self.logger.warning("Skipping library: %s because path: %s doesn't exist", libraryName, libPath)
            #else:
            #    self.logger.info("Skipping except list library: %s", libraryName)
        libsWithCfg = set()
        libsInLibc = set()
        functionStartsFineGrain = set()
        self.logger.info("self.cfgPath: %s", self.cfgPath)
        for fileName in os.listdir(self.cfgPath):
            libsWithCfg.add(fileName)
        
        libsInLibc.add("libcrypt.callgraph.out")
        libsInLibc.add("libdl.callgraph.out")
        libsInLibc.add("libnsl.callgraph.out")
        libsInLibc.add("libnss_compat.callgraph.out")
        libsInLibc.add("libnss_files.callgraph.out")
        libsInLibc.add("libnss_nis.callgraph.out")
        libsInLibc.add("libpthread.callgraph.out")
        libsInLibc.add("libm.callgraph.out")
        libsInLibc.add("libresolv.callgraph.out")
        libsInLibc.add("librt.callgraph.out")
        libsInLibc.add("libutil.callgraph.out")
        libsInLibc.add("libnss_dns.callgraph.out")

        StartNodes = set()
        for fileName in os.listdir(self.binaryPath):
            self.logger.info("fileName in binary call: %s", fileName)
            tmpFileName = fileName
            if ( fileName.startswith("lib") and fileName != "libs.out" and fileName != "libs.out.copy"):
                cfgAvailable = True
                tmpFileName = re.sub("-.*so",".so",fileName)
                tmpFileName = tmpFileName[:tmpFileName.index(".so")]
                self.logger.info("tmpFileName lib: %s", tmpFileName)
                tmpFileName = tmpFileName + ".callgraph.out"
            if ( tmpFileName in libsWithCfg):
                self.logger.info("The call graph exists for: %s", fileName)
                # self.logger.info("tmpFileName: %s", tmpFileName)
                tmpGraph = graph.Graph(self.logger)
                tmpGraph.createGraphFromInput(self.cfgPath + "/" + tmpFileName, "->")
                # self.logger.info("tmpGraphDir: %s", self.cfgPath + "/" + tmpFileName)
                # funcFile = open(self.cfgPath + "/" + tmpFileName, 'r')
                # funcFile.seek(0)
                # funcLine = funcFile.readline()
                # while ( funcLine ):
                #     funcName = funcLine.strip()
                #     leaves = tmpGraph.getLeavesFromStartNode(funcName, list(), list())
                #     if ( len(leaves) != 0 and funcName not in leaves ):
                #         self.logger.debug("funcName: %s leaves: %s", funcName, str(leaves))
                #         functionList.update(set(leaves))
                #     funcLine = funcFile.readline()
                
                tmpStartNodes = tmpGraph.extractStartingNodes()
                StartNodes.update(tmpStartNodes)
                for startNode in tmpStartNodes:
                    leaves = tmpGraph.getLeavesFromStartNode(startNode, list(), list())
                    for leaf in leaves:
                        completeGraph.addEdge(startNode, leaf)
            elif ( tmpFileName in libsInLibc ):
                continue
            else:
                self.logger.info("Adding function starts for %s", fileName)
                functionList = util.extractImportedFunctions(self.binaryPath + fileName, self.logger)
                if ( not functionList ):
                    self.logger.warning("Function extraction for file: %s failed!", fileName)
                functionStartsFineGrain.update(set(functionList))
            # if(tmpFileName != self.appName):
            #     functionList = util.extractImportedFunctions(self.binaryPath + fileName, self.logger)
            #     if ( not functionList ):
            #         self.logger.warning("Function extraction for file: %s failed!", fileName)
            #     functionStartsFineGrain.update(set(functionList))

                    # self.logger.info("The library call graph doesn't exist, considering all imported functions for: %s", fileName)
                    # libraryProfiler = binaryAnalysis.BinaryAnalysis(self.binaryPath + fileName, self.logger)
                    # directSyscallSet, successCount, failedCount  = libraryProfiler.extractDirectSyscalls()
                    # indirectSyscallSet = libraryProfiler.extractIndirectSyscalls(libcGraph)

                    # librarySyscalls.update(directSyscallSet)
                    # librarySyscalls.update(indirectSyscallSet)
        
        tmpSet = set()
        glibcSyscallList = list()
        i = 0
        while i < 400:
            glibcSyscallList.append("syscall(" + str(i) + ")")
            glibcSyscallList.append("syscall ( " + str(i) + " )")
            glibcSyscallList.append("syscall( " + str(i) + " )")
            i += 1
        # self.logger.info("function list: %s", functionList)
        for function in functionStartsFineGrain:
            leaves = libcGraph.getLeavesFromStartNode(function, glibcSyscallList, list())
            tmpSet = tmpSet.union(leaves)
        
        allSyscallsFineGrain = set()
        for syscallStr in tmpSet:
            syscallStr = syscallStr.replace("syscall( ", "syscall(")
            syscallStr = syscallStr.replace("syscall ( ", "syscall(")
            syscallStr = syscallStr.replace(" )", ")")
            syscallNum = int(syscallStr[8:-1])
            allSyscallsFineGrain.add(syscallNum)
        
        self.logger.info("allSyscallsFineGrain: %s", allSyscallsFineGrain)
        
        librarySyscalls.update(allSyscallsFineGrain)

        #  functionStartsOriginal
        # functionStartsOriginal = set()
        # funcFilePath = self.binaryPath + "libs.out"
        # funcFile = open(funcFilePath, 'r')
        # funcLine = funcFile.readline()
        # funcFile.seek(0)
        # funcLine = funcFile.readline()
        # while ( funcLine ):
        #     funcLine = funcLine.strip()
        #     functionStartsOriginal.add(funcLine)
        #     funcLine = funcFile.readline()

        # funcFile.close()
        # tmpSet = set()
        # allSyscallsOriginal = set()
        # for function in functionStartsOriginal:
        #     leaves = libcGraph.getLeavesFromStartNode(function, glibcSyscallList, list())
        #     tmpSet = tmpSet.union(leaves)
        # for syscallStr in tmpSet:
        #     syscallStr = syscallStr.replace("syscall( ", "syscall(")
        #     syscallStr = syscallStr.replace("syscall ( ", "syscall(")
        #     syscallStr = syscallStr.replace(" )", ")")
        #     syscallNum = int(syscallStr[8:-1])
        #     allSyscallsOriginal.add(syscallNum)
        
        # self.logger.info("allSyscallsOriginal: %s", allSyscallsOriginal)

        # librarySyscalls.update(allSyscallsOriginal)
                
        return completeGraph, librarySyscalls, libraryCfgGraphs, libcGraph, StartNodes

    def extractAccessibleSystemCalls(self, masterstartNodes,workerstartNodes, exceptList):
        completeGraph, librarySyscalls, libraryCfgGraphs, libcGraph, libStartNodes = self.createCompleteGraph(exceptList)
        # masterstartNodes.extend(list(libStartNodes))
        self.logger.info("masterstartNodes: %d", len(masterstartNodes))
        masteraccessibleSyscalls, addSyscalls = self.extractAccessibleSystemCallsFromStartNodes(masterstartNodes, completeGraph, libcGraph, librarySyscalls)
        # workerstartNodes.extend(list(libStartNodes))
        self.logger.info("workerstartNodes: %d", len(workerstartNodes))

        workeraccessibleSyscalls, _ = self.extractAccessibleSystemCallsFromStartNodes(workerstartNodes, completeGraph, libcGraph, addSyscalls)

        return masteraccessibleSyscalls, workeraccessibleSyscalls

    
    def extractAccessibleSystemCallsFromStartNodes(self, startNodes, completeGraph, libcGraph, librarySyscalls):
        accessibleFuncs = set()
        allVisitedNodes = set()
        accessibleSyscalls = set()
        accessibleSyscallsBefore = set()
        # self.logger.info("startNodes: %d, %s", len(startNodes), startNodes)
        # startNodes.extend(list(libStartNodes))
        # self.logger.info("updatedStartNodes: %d, %s", len(startNodes), startNodes)
        for startNode in startNodes:
            #self.logger.debug("Iterating startNode: %s", startNode)
            accessibleFuncs.update(completeGraph.getLeavesFromStartNode(startNode, list(), list()))

        self.logger.info("accessibleFuncsLen: %d", len(accessibleFuncs))
        for accessibleFunc in accessibleFuncs:
            # self.logger.info("Iterating accessible function: %s", accessibleFunc)
            currentSyscalls, currentVisitedNodes = libcGraph.getSyscallFromStartNodeWithVisitedNodes(accessibleFunc)
            accessibleSyscalls.update(currentSyscalls)
            allVisitedNodes.update(currentVisitedNodes)
        accessibleSyscallsBefore.update(accessibleSyscalls)
        # self.logger.info("Accessible system calls after library specialization: %d, %s", len(accessibleSyscalls), str(accessibleSyscalls))
        # self.logger.info("len(librarySyscalls): %d", len(librarySyscalls))
        accessibleSyscalls.update(librarySyscalls)
        # self.logger.info("accessibleSyscalls %d", len(accessibleSyscalls))
        # self.logger.info("accessibleSyscallsBefore %d", len(accessibleSyscallsBefore))
        addSyscalls = accessibleSyscalls - accessibleSyscallsBefore
        # self.logger.info("Accessible system calls after adding libraries without cfg: %d, %s", len(accessibleSyscalls), str(accessibleSyscalls))
        # self.logger.info("addSyscalls %d", len(addSyscalls))
        return accessibleSyscalls, addSyscalls

    def extractAccessibleSystemCallsFromIndirectFunctions(self, directCfg, separator, exceptList=list()):
        indirectFunctionToSyscallMap = dict()

        tempGraph = graph.Graph(self.logger)
        result = tempGraph.createGraphFromInput(self.binaryCfgPath)
        indirectFunctions = tempGraph.extractIndirectOnlyFunctions(directCfg, separator)
        completeGraph, librarySyscalls, libraryCfgGraphs, libcGraph = self.createCompleteGraph(exceptList)

        for startNode in indirectFunctions:
            accessibleFuncs = set()
            allVisitedNodes = set()
            accessibleSyscalls = set()
            #self.logger.debug("Iterating indirect-only function: %s", startNode)
            accessibleFuncs.update(completeGraph.getLeavesFromStartNode(startNode, list(), list(indirectFunctions)))

            for accessibleFunc in accessibleFuncs:
                #self.logger.debug("Iterating accessible function: %s", accessibleFunc)
                currentSyscalls, currentVisitedNodes = libcGraph.getSyscallFromStartNodeWithVisitedNodes(accessibleFunc)
                accessibleSyscalls.update(currentSyscalls)
                allVisitedNodes.update(currentVisitedNodes)
            indirectFunctionToSyscallMap[startNode] = accessibleSyscalls
        return indirectFunctionToSyscallMap
