#-----------------------------------------------------------------------------
# Name:        threats2MitreAppDataMgr.py
#
# Purpose:     Data manager class running in the sub-thread to handle all the 
#              mapping and matching request from the web page.
#              
# Author:      Yuancheng Liu 
#
# Version:     v_0.1.2
# Created:     2024/03/02
# Copyright:   Copyright (c) 2024 LiuYuancheng
# License:     MIT License
#-----------------------------------------------------------------------------

import os
import json
import time
from datetime import datetime
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
def creatReport(dataDict):
    """Generate the mapping/matching report.
        Args:
            dataDict (dict): map/match result dictionary.
    """
    now = datetime.now()
    dateTime = now.strftime("%Y_%m_%d_%H_%M_%S")
    dataDict['Time'] = dateTime  
    fileExtention =  "_Cwe_%s.json" %str(dateTime) if dataDict['ReportType'] == 'CWE' else "_Atk_%s.json" %str(dateTime)
    reportName = str(dataDict['ScenarioName']).replace('.txt', fileExtention)
    gv.gAppParmDict['rstName'] = reportName
    reportPath= os.path.join(gv.gRstFolder, reportName)
    jsonStr = json.dumps(dataDict, indent=4)
    try:
        with open(reportPath, "w") as outfile:
            outfile.write(jsonStr)
        gv.gDebugPrint("creatReport(): Report file created: %s" %str(reportPath),
                        logType=gv.LOG_INFO)
    except Exception as err:
        gv.gDebugPrint("creatReport(): Error write the report file: %s" %str(err),
                    logType=gv.LOG_ERR)
    return reportPath

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class DataManager(threading.Thread):
    """ Subthread data manager contents the ATT&CK mapper and CWD matching. """

    def __init__(self, parent) -> None:
        threading.Thread.__init__(self)
        self.parent = parent
        os.environ["OPENAI_API_KEY"] = gv.API_KEY
        # Init the data manager
        self.attackMapper = llmMITREMapper(openAIkey=gv.API_KEY)
        self.cweMatch = llmMITRECWEMatcher(openAIkey=gv.API_KEY)
        self.startProFlg = False
        self.terminate = False 

    #-----------------------------------------------------------------------------
    def _updateWebLog(self, logMsg, logType='ATK'):
        """ Use socketIO to send the log to the page front end.
            Args:
                logMsg (str): log message
                logType (str, optional): log type used to identify whehter the message 
                    will update on the mitreattack.html(ATK) page or mitrecwe.html(CWE) 
                    page. Defaults to 'ATK'.
        """
        if gv.iSocketIO:
            gv.gWeblogCount += 1
            gv.gDebugPrint(logMsg, logType=gv.LOG_INFO)
            gv.iSocketIO.emit('serv_response',
                              {'data': str(logMsg), 'count': gv.gWeblogCount, 'logType': str(logType)})

    #-----------------------------------------------------------------------------
    def run(self):
        """ Thread run() function call by start(). """
        #Log.info("gv.iDataMgr: run() function loop start, terminate flag [%s]", str(
        #    self.terminate), printFlag=LOG_FLAG)
        time.sleep(1)  # sleep 1 second to wait socketIO start to run.
        while not self.terminate:
            if self.startProFlg:
                if gv.gAppParmDict['rstType'] == 'ATK':
                    self.processScenario2ATK(gv.gAppParmDict['srcName'])
                else:
                    self.processScenario2CWE(gv.gAppParmDict['srcName'])
                self.startProFlg = False
            time.sleep(0.5)

    #-----------------------------------------------------------------------------
    def startProcess(self):
        gv.gWeblogCount = 0
        self.startProFlg = True

    #-----------------------------------------------------------------------------
    def processScenario2CWE(self, scenarioFile):
        """ Process the input threats scenario description file and generate the
            MITRE CWE match report(json format).
            Args:
                scenarioFile (str): threats scenario file name.
        """
        self._updateWebLog("Start to process scenario file: %s" %str(scenarioFile),
                logType='CWE')
        # 1. load thread scenario description file.
        self._updateWebLog("Step1: load threats report.", logType='CWE')
        secContent = loadScenarioFromFile(scenarioFile)
        if secContent is None: return
        self._updateWebLog("- Finished.", logType='CWE')
        time.sleep(0.1)
        # 2. get the CWE mapping result
        self._updateWebLog("Step2: parse the vulnerabilies.", 
                       logType='CWE')
        matchRst = self.cweMatch.getCWEInfo(secContent)
        cweNum = len(matchRst.keys())
        self._updateWebLog("- Get %s matched CWE." %str(cweNum), logType='CWE')
        if cweNum == 0: return
        time.sleep(0.1)
        # 3. Generate the  result report.
        self._updateWebLog("Step3: generate the report file", logType='CWE')
        resultDict  = {
            'ScenarioName': scenarioFile,
            'ReportType': 'CWE'
        }
        resultDict.update(matchRst)
        gv.gAppRptPath = creatReport(resultDict)
        self._updateWebLog("Downloading result...", logType='CWE')

    #-----------------------------------------------------------------------------
    def processScenario2ATK(self, scenarioFile):
        """ Process the input threats scenario description file and generate the
            MITRE ATT&CK mapping report(json format) in the current execution foler. 
            Args:
                scenarioFile (str): threats scenario file name.
        """
        
        self._updateWebLog("Start to process scenario file: %s" %str(scenarioFile))
        resultDict = {}
        # 1. load thread scenario description file. 
        secContent = loadScenarioFromFile(scenarioFile)
        if secContent is None: return
        resultDict['ScenarioName'] = scenarioFile
        resultDict['ReportType'] = 'ATT&CK'
        self._updateWebLog("-Finished")
        time.sleep(0.1)

        # 2. Summarize the contents and parse all the attack behaviors.
        self._updateWebLog("Step2: summarize scenario and get attack behaviors list.")
        atkBehList = self.attackMapper.getAttackInfo(secContent)
        if atkBehList is None or len(atkBehList) == 0:
            gv.gDebugPrint("No attack behavior found in scenario file: %s" %str(scenarioFile),
                           logType=gv.LOG_WARN)
        resultDict['AttackBehaviors'] = atkBehList
        self._updateWebLog(" - Found %s attack behaviors" %str(len(atkBehList)))
        time.sleep(0.1)

        # 3. Map every attack/malicious behavior
        self._updateWebLog("Step3: map every behavior to MITRE ATT&CK Matrix (tactic, technique)")
        mapResult = self.attackMapper.getAttackTechnique(atkBehList)
        self._updateWebLog(" - Found %s mapped MITRE ATT&CK tactic" %str(len(mapResult.keys())))
        time.sleep(0.1)

        self._updateWebLog("Step4: verifiy whether the technique can match the scenario")
        self.attackMapper.setVerifier(secContent)
        for tactic in mapResult.keys():
            resultDict[tactic] = {}
            for technique in mapResult[tactic]:
                rst = self.attackMapper.verifyAttackTechnique(technique)
                resultDict[tactic][technique] = rst
        self._updateWebLog("- verifiy finished")
        time.sleep(0.1)

        # 5. Generate the mapping result report.
        self._updateWebLog("Step5: Generate the report file",)
        gv.gAppRptPath = creatReport(resultDict)
        self._updateWebLog("Downloading result...")
