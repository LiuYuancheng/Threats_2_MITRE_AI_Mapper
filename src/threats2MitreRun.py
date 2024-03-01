#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        threats2MitreRun.py
#
# Purpose:     This module will load the threats scenario description from the 
#              file and call the AI llmMITREMapper to generate the scenario to
#              MITRE ATT&CK mapping report.
#              
# Author:      Yuancheng Liu
#
# Created:     2024/02/29
# Version:     v_0.1.0
# Copyright:   Copyright (c) 2024 LiuYuancheng
# License:     MIT License
#-----------------------------------------------------------------------------

import os
import json

import threats2MitreGlobal as gv
from threats2MitreUtils import llmMITREMapper

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class threats2MitreMapper(object):
    """ Main threats scenario description mapper program. """

    def __init__(self, openAIkey=gv.API_KEY) -> None:
        self.openAIkey = openAIkey
        os.environ["OPENAI_API_KEY"] = openAIkey
        self.attackMapper = llmMITREMapper(openAIkey=self.openAIkey)
        gv.gDebugPrint("threats2MitreMapper init finished")

    #-----------------------------------------------------------------------------
    def loadScenarioFromFile(self, scenarioFile):
        """ Read the attack scenario from a text format file.
            Args:
                scenarioFile (str): fileName. The file need to be put in the scenario
                    bank folder defined in the config file.
        """
        filePath = os.path.join(gv.SCE_BANK, scenarioFile)
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
        secContent = self.loadScenarioFromFile(scenarioFile)
        if secContent is None: return
        resultDict['ScenarioName'] = scenarioFile
        gv.gDebugPrint("Step1: Scenario load ready.", logType=gv.LOG_INFO)
        
        # 2. Summarize the contents and parse all the attack behaviors.
        gv.gDebugPrint("Step2: Summarize scenario and get attack behaviors list.", 
                       logType=gv.LOG_INFO)
        atkBehList = self.attackMapper.getAttackInfo(secContent)
        if atkBehList is None or len(atkBehList) == 0:
            gv.gDebugPrint("No attack behavior found in scenario file: %s" %str(scenarioFile),
                           logType=gv.LOG_WARN)
        resultDict['AttackBehaviors'] = atkBehList
        gv.gDebugPrint(" - Found %s attack behaviors" %str(len(atkBehList)), 
                       logType=gv.LOG_INFO)
        
        # 3. Map every attack/malicious behavior
        gv.gDebugPrint("Step3: Map every behavior to MITRE ATT&CK Matrix (tactic, technique)",
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
        
        # 5. Generate the mapping result report.
        gv.gDebugPrint("Step5: Generate the report file", logType=gv.LOG_INFO)
        resultJson = json.dumps(resultDict, indent=4)
        reportFile = str(scenarioFile).replace('.txt', '.json')
        reportPath= os.path.join(gv.dirpath, reportFile)
        with open(reportPath, "w") as outfile:
            outfile.write(resultJson)

#-----------------------------------------------------------------------------
def main():
    threatsAnalyzer = threats2MitreMapper()
    #scenarioFile = 'maliciousMacroReport.txt'
    # scenarioFile = 'railwayITattackReport.txt'
    while True:
        print("***\nPlease type in the threats fileName you want to process: ")
        uInput = str(input())
        if uInput.lower() == 'exit' or uInput.lower() == 'q':
            print('Exist...')
            break

        scenarioFile = uInput
        threatsAnalyzer.processScenarioFile(scenarioFile)

#-----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
