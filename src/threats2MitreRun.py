#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        threats2MitreRun.py
#
# Purpose:     This module will load the threats scenario description from the 
#              file and call the AI-llm MITRE ATT&CK-Mapper/ CWE-Matcher module 
#              to generate the related report.
#              
# Author:      Yuancheng Liu
#
# Created:     2024/02/29
# Version:     v_0.1.1
# Copyright:   Copyright (c) 2024 LiuYuancheng
# License:     MIT License
#-----------------------------------------------------------------------------

import os
import json
from datetime import datetime

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
        gv.gDebugPrint("Thret scenario file not exist: %s" %str(filePath), 
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

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class threats2CWEMatcher(object):
    """ Main threats scenario description MITRE CWE matcher program. """

    def __init__(self, openAIkey=gv.API_KEY) -> None:
        self.openAIkey = openAIkey
        os.environ["OPENAI_API_KEY"] = openAIkey
        self.cweMatch = llmMITRECWEMatcher(openAIkey=self.openAIkey)
        gv.gDebugPrint("threats2CWEMatcher init finished")

    #-----------------------------------------------------------------------------
    def processScenarioFile(self, scenarioFile):
        """ Process the input threats scenario description file and generate the
            MITRE match report(json format).
            Args:
                scenarioFile (str): threats scenario file name.
        """
        gv.gDebugPrint("Start to process scenario file: %s" %str(scenarioFile),
                logType=gv.LOG_INFO)
        # 1. load thread scenario description file.
        gv.gDebugPrint("Step1: load threats report.", logType=gv.LOG_INFO)
        secContent = loadScenarioFromFile(scenarioFile)
        if secContent is None: return
        gv.gDebugPrint("- Finished.", logType=gv.LOG_INFO)
        # 2. get the CWE mapping result
        gv.gDebugPrint("Step2: parse the vulnerabilies.", 
                       logType=gv.LOG_INFO)
        matchRst = self.cweMatch.getCWEInfo(secContent)
        cweNum = len(matchRst.keys())
        gv.gDebugPrint("- Get %s matched CWE." %str(cweNum), logType=gv.LOG_INFO)
        if cweNum == 0: return
        # 3. Generate the  result report.
        gv.gDebugPrint("Step3: generate the report file", logType=gv.LOG_INFO)
        resultDict  = {
            'ScenarioName': scenarioFile,
            'ReportType': 'CWE'
        }
        resultDict.update(matchRst)
        creatReport(resultDict)

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class threats2MitreMapper(object):
    """ Main threats scenario description MITRE ATT&CK mapper program. """

    def __init__(self, openAIkey=gv.API_KEY) -> None:
        self.openAIkey = openAIkey
        os.environ["OPENAI_API_KEY"] = openAIkey
        self.attackMapper = llmMITREMapper(openAIkey=self.openAIkey)
        gv.gDebugPrint("threats2MitreMapper init finished")

    #-----------------------------------------------------------------------------
    def processScenarioFile(self, scenarioFile):
        """ Process the input threats scenario description file and generate the
            MITRE mapping report(json format).
            Args:
                scenarioFile (str): threats scenario file name.
        """
        gv.gDebugPrint("Start to process scenario file: %s" %str(scenarioFile),
                       logType=gv.LOG_INFO)
        resultDict = {}
        # 1. load thread scenario description file. 
        gv.gDebugPrint("Step1: load threats report.", logType=gv.LOG_INFO)
        secContent = loadScenarioFromFile(scenarioFile)
        if secContent is None: return
        gv.gDebugPrint("- Finished.", logType=gv.LOG_INFO)
        resultDict['ScenarioName'] = scenarioFile
        resultDict['ReportType'] = 'ATT&CK'
        # 2. Summarize the contents and parse all the attack behaviors.
        gv.gDebugPrint("Step2: summarize scenario and get attack behaviors list.", 
                       logType=gv.LOG_INFO)
        atkBehList = self.attackMapper.getAttackInfo(secContent)
        if atkBehList is None or len(atkBehList) == 0:
            gv.gDebugPrint("No attack behavior found in scenario file: %s" %str(scenarioFile),
                           logType=gv.LOG_WARN)
        resultDict['AttackBehaviors'] = atkBehList
        gv.gDebugPrint(" - Found %s attack behaviors" %str(len(atkBehList)), 
                       logType=gv.LOG_INFO)
        # 3. Map every attack/malicious behavior
        gv.gDebugPrint("Step3: map every behavior to MITRE ATT&CK Matrix (tactic, technique)",
                       logType=gv.LOG_INFO)
        mapResult = self.attackMapper.getAttackTechnique(atkBehList)
        gv.gDebugPrint(" - Found %s mapped MITRE ATT&CK tactic" %str(len(mapResult.keys())),
                       logType=gv.LOG_INFO)
        # 4. Verify the mapper result to orignal scenario
        gv.gDebugPrint("Step4: verifiy whether the technique can match the scenario",
                       logType=gv.LOG_INFO)
        self.attackMapper.setVerifier(secContent)
        for tactic in mapResult.keys():
            resultDict[tactic] = {}
            for technique in mapResult[tactic]:
                rst = self.attackMapper.verifyAttackTechnique(technique)
                resultDict[tactic][technique] = rst
        gv.gDebugPrint("- Finished.", logType=gv.LOG_INFO)
        # 5. Generate the mapping result report.
        gv.gDebugPrint("Step5: generate the report file", logType=gv.LOG_INFO)
        creatReport(resultDict)

#-----------------------------------------------------------------------------
def main():
    threatsMapper = threats2MitreMapper()
    threatsMatcher = threats2CWEMatcher()
    while True:
        print("***\nPlease type in the threats fileName you want to process(q for exist): ")
        uInput = str(input())
        scenarioFile = uInput
        if scenarioFile.lower() == 'exit' or scenarioFile.lower() == 'q':
            print('Exist...')
            break
        print("Select the AI-LLM data process program 1.MITRE-ATT&CK-Mapper, 2.MITRE-CWE-Matcher")
        uInput = str(input())
        if uInput == '1':
            threatsMapper.processScenarioFile(scenarioFile)
        elif uInput == '2':
            threatsMatcher.processScenarioFile(scenarioFile)
        else:
            print("Invalid input, please try again.")
            continue
        
#-----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
