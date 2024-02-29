#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        threats2MitreRun.py
#
# Purpose:     This module will provide two LLM-AI MITRE frame work
#              
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

    def __init__(self, openAIkey=gv.API_KEY) -> None:
        self.openAIkey = openAIkey
        os.environ["OPENAI_API_KEY"] = openAIkey
        self.attackMapper = llmMITREMapper(openAIkey=self.openAIkey)
        gv.gDebugPrint("threats2MitreMapper init finished")

    #-----------------------------------------------------------------------------
    def loadScenarioFromFile(self, scenarioFile):
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

        gv.gDebugPrint("Start to process scenario file: %s" %str(scenarioFile),
                       logType=gv.LOG_INFO)
        resultDict = {}
        # 1. load 
        secContent = self.loadScenarioFromFile(scenarioFile)
        if secContent is None: return
        resultDict['ScenarioName'] = scenarioFile
        gv.gDebugPrint("Step1: Scenario load ready", logType=gv.LOG_INFO)
        
        # 2. summerize
        gv.gDebugPrint("Step2: Summerize Scensrio and get attack behaviors list ", 
                       logType=gv.LOG_INFO)
        atkBehList = self.attackMapper.getAttackInfo(secContent)
        if atkBehList is None or len(atkBehList) == 0:
            gv.gDebugPrint("No attack behavior found in scenario file: %s" %str(scenarioFile),
                           logType=gv.LOG_WARN)
        resultDict['AttackBehaviors'] = atkBehList
        gv.gDebugPrint(" - Found %s attack behaviors" %str(len(atkBehList)), 
                       logType=gv.LOG_INFO)
        
        # 3. 
        gv.gDebugPrint("Step3: Map every behaviors to MITRE ATT&CK Matrix (tactic, technique)",
                       logType=gv.LOG_INFO)
        mapResult = self.attackMapper.getAttackTechnique(atkBehList)
        gv.gDebugPrint(" - Found %s mapped MITRE ATT&CK tactic" %str(len(mapResult.keys())),
                       logType=gv.LOG_INFO)

        # 4 
        gv.gDebugPrint("Step4: verfiy the technique can match the scenario",
                       logType=gv.LOG_INFO)
        self.attackMapper.setVerifier(secContent)
        for tactic in mapResult.keys():
            resultDict[tactic] = {}
            for technique in mapResult[tactic]:
                rst = self.attackMapper.verifyAttackTechnique(technique)
                resultDict[tactic][technique] = rst
        
        # 
        gv.gDebugPrint("Step5: Generate the report file", logType=gv.LOG_INFO)
        resultJson = json.dumps(resultDict, indent=4)
        reportFile= scenarioFile+".json"
        with open(reportFile, "w") as outfile:
            outfile.write(resultJson)

#-----------------------------------------------------------------------------
def main():
    threatsAnalyzer = threats2MitreMapper()
    #scenarioFile = 'maliciousMacroReport.txt'
    scenarioFile = 'railwayITattackReport.txt'
    threatsAnalyzer.processScenarioFile(scenarioFile)


#-----------------------------------------------------------------------------
if __name__ == '__main__':
    main()
