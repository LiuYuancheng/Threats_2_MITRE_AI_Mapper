#-----------------------------------------------------------------------------
# Name:        dataManager.py
#
# Purpose:     A manager class running in the sub-thead to handle all the data
#              shown in the ***state page.
#              
# Author:      Yuancheng Liu, 
#
# Version:     v_0.2
# Created:     2022/09/04
# Copyright:   
# License:     
#-----------------------------------------------------------------------------
import os
import json
import time
import threading
import threats2MitreGlobal as gv
from threats2MitreUtils import llmMITREMapper, llmMITRECWEMatcher

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def loadScenarioFromFile(scenarioFile):
    """ Read the attack scenario from a text format file.
        Args:
            scenarioFile (str): fileName. The file need to be put in the scenario
                bank folder defined in the config file.
    """
    if not gv.gCheckFileType(scenarioFile): 
        gv.gDebugPrint("Error: The file need to be *.txt format.", logType=gv.LOG_ERR)
        return None
    filePath = os.path.join(gv.gSceBank, scenarioFile)
    scenarioStr = None 
    if os.path.exists(filePath):
        try:
            with open(filePath, 'r') as fh:
                scenarioStr = fh.read()
            return scenarioStr
        except Exception as err:
            gv.gDebugPrint("loadScenarioFromFile(): Error open the scenario file: %s" %str(err), 
                            logType=gv.LOG_ERR)
            return None 
    else:
        gv.gDebugPrint("Scenario file not exist: %s" %str(filePath), 
                        logType=gv.LOG_WARN)
    return scenarioStr

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class DataManager(threading.Thread):

    def __init__(self, parent) -> None:
        threading.Thread.__init__(self)
        self.parent = parent
        os.environ["OPENAI_API_KEY"] = gv.API_KEY
        # Init the data manager
        self.attackMapper = llmMITREMapper(openAIkey=gv.API_KEY)
        self.startProFlg = False
        self.terminate = False 

    def updateWebLog(self, logMsg, logType='ATK'):
        if gv.iSocketIO:
            gv.gWeblogCount +=1
            gv.iSocketIO.emit('serv_response',{'data': str(logMsg), 'count': gv.gWeblogCount})

#-----------------------------------------------------------------------------
    def run(self):
        """ Thread run() function call by start(). """
        #Log.info("gv.iDataMgr: run() function loop start, terminate flag [%s]", str(
        #    self.terminate), printFlag=LOG_FLAG)
        time.sleep(1)  # sleep 1 second to wait socketIO start to run.
        while not self.terminate:
            if self.startProFlg:
                self.processScenarioFile(gv.gAppParmDict['srcName'])
                self.startProFlg = False
            time.sleep(0.5)

    def startProcess(self):
        gv.gWeblogCount = 0
        self.startProFlg = True

    #-----------------------------------------------------------------------------
    def processScenarioFile(self, scenarioFile):
        """ Process the input threats scenario description file and generate the
            MITRE mapping report(json format) in the current execution foler. 
            Args:
                scenarioFile (str): threats scenario file name.
        """
        gv.gDebugPrint("Start to process scenario file: %s" %str(scenarioFile),
                       logType=gv.LOG_INFO)
        resultDict = {}
        # 1. load thread scenario description file. 
        secContent = loadScenarioFromFile(scenarioFile)
        if secContent is None: return
        resultDict['ScenarioName'] = scenarioFile
        gv.gDebugPrint("Step1: Scenario load ready.", logType=gv.LOG_INFO)
        self.updateWebLog("Step1: Scenario load ready.")

        # 2. Summarize the contents and parse all the attack behaviors.
        gv.gDebugPrint("Step2: Summarize scenario and get attack behaviors list.", 
                       logType=gv.LOG_INFO)
        self.updateWebLog("Step2: Summarize scenario and get attack behaviors list.")
        atkBehList = self.attackMapper.getAttackInfo(secContent)
        if atkBehList is None or len(atkBehList) == 0:
            gv.gDebugPrint("No attack behavior found in scenario file: %s" %str(scenarioFile),
                           logType=gv.LOG_WARN)
        resultDict['AttackBehaviors'] = atkBehList
        gv.gDebugPrint(" - Found %s attack behaviors" %str(len(atkBehList)), 
                       logType=gv.LOG_INFO)
        self.updateWebLog(" - Found %s attack behaviors" %str(len(atkBehList)))


        # 3. Map every attack/malicious behavior
        gv.gDebugPrint("Step3: Map every behavior to MITRE ATT&CK Matrix (tactic, technique)",
                       logType=gv.LOG_INFO)
        self.updateWebLog("Step3: Map every behavior to MITRE ATT&CK Matrix (tactic, technique)")
        mapResult = self.attackMapper.getAttackTechnique(atkBehList)
        gv.gDebugPrint(" - Found %s mapped MITRE ATT&CK tactic" %str(len(mapResult.keys())),
                       logType=gv.LOG_INFO)
        self.updateWebLog(" - Found %s mapped MITRE ATT&CK tactic" %str(len(mapResult.keys())))

        # 4. Verify the mapper result to orignal scenario
        gv.gDebugPrint("Step4: verifiy whether the technique can match the scenario",
                       logType=gv.LOG_INFO)
        self.updateWebLog("Step4: verifiy whether the technique can match the scenario")
        self.attackMapper.setVerifier(secContent)
        for tactic in mapResult.keys():
            resultDict[tactic] = {}
            for technique in mapResult[tactic]:
                rst = self.attackMapper.verifyAttackTechnique(technique)
                resultDict[tactic][technique] = rst
        self.updateWebLog("- verifiy finished")
        # 5. Generate the mapping result report.
        gv.gDebugPrint("Step5: Generate the report file", logType=gv.LOG_INFO)
        self.updateWebLog("Step5: Generate the report file",)
        resultJson = json.dumps(resultDict, indent=4)
        reportFile = str(scenarioFile).replace('.txt', '_Atk.json')
        reportPath= os.path.join(gv.dirpath, reportFile)
        with open(reportPath, "w") as outfile:
            outfile.write(resultJson)
        gv.gRstPath = reportPath
        self.updateWebLog("Downloading result...")