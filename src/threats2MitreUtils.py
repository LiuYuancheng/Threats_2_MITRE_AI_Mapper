#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        threats2MitreUtils.py
#
# Purpose:     This module will provide two LLM-AI MITRE frame work mapper module
#              - llmMITREMapper : map the attack scenario attack flow path to the 
#                   MITRE ATT&CK Matrix to get the related tactic and technique.
#              - llmMITREMatcher ; match the vulnerbilities appeared in the attack
#                   scenario to MITRE CWE frame work to get the related CWE. 
#                
# Author:      Yuancheng Liu
#
# Created:     2024/02/29
# Version:     v_0.1.0
# Copyright:   Copyright (c) 2024 LiuYuancheng
# License:     MIT License
#-----------------------------------------------------------------------------

import os

# load the langchain libs
from langchain.llms import OpenAI
from langchain.chains import LLMChain
from langchain.chains.llm import LLMChain
from langchain.chat_models import ChatOpenAI

from langchain.prompts import PromptTemplate
from langchain.prompts.chat import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
)
from langchain.schema import BaseOutputParser

import threats2MitreGlobal as gv

#-----------------------------------------------------------------------------
class CommaSeparatedListOutputParser(BaseOutputParser):
    """Parse the output of an LLM call to a comma-separated list."""
    def parse(self, text: str):
        """Parse the output of an LLM call."""
        return text.strip().split("\n")

#-----------------------------------------------------------------------------
class llmMITREMapper(object):
    """ A LLM-AI mapper program map the attack scenario attack flow path to the 
        MITRE ATT&CK Matrix to get the related tactic and technique.
    """
    def __init__(self, openAIkey=None) -> None:
        # init the openAI conersation 
        if openAIkey: os.environ["OPENAI_API_KEY"] = openAIkey
        self.llm = ChatOpenAI(temperature=0, model_name=gv.AI_MODEL)
        self.llmAnalyzerChain = None 
        self._initASDAnalyzer()

        self.llmActMapperChain = None 
        self._initActionMapper()

        self.llmTecVerifyChain = None

        #self.llmMaperChain = None 
        #self._initASDMapper()

    #-----------------------------------------------------------------------------
    def _initASDAnalyzer(self, systemTemplate=gv.gSceAnalysePrompt):
        """ Init the attack scenario description(ASD) analyze chain used to parse the 
            attack flow path behaviors.
        """
        sysTemplate = SystemMessagePromptTemplate.from_template(systemTemplate)
        human_template = "Attack Scenario: {text}"
        human_message_prompt = HumanMessagePromptTemplate.from_template(human_template)
        chat_prompt = ChatPromptTemplate.from_messages([sysTemplate, human_message_prompt])
        self.llmAnalyzerChain = LLMChain(llm=self.llm, 
                            prompt=chat_prompt, 
                            output_parser=CommaSeparatedListOutputParser())

    #-----------------------------------------------------------------------------
    def _initASDMapper(self, systemTemplate=gv.gSce2MitrePrompt):
        sysTemplate = SystemMessagePromptTemplate.from_template(systemTemplate)
        human_template = "{text}"
        human_message_prompt = HumanMessagePromptTemplate.from_template(human_template)
        chat_prompt = ChatPromptTemplate.from_messages([sysTemplate, human_message_prompt])
        self.llmMaperChain = LLMChain(llm=self.llm, 
                            prompt=chat_prompt, 
                            output_parser=CommaSeparatedListOutputParser())

    #-----------------------------------------------------------------------------
    def _initActionMapper(self, systemTemplate=gv.gBeh2MitrePrompt):
        """ Init the attack action mapping chain used to map the malicious behaivors  
            to the MITRE ATT&CK tactic and technique.
        """
        sysTemplate = SystemMessagePromptTemplate.from_template(systemTemplate)
        human_template = "{text}"
        human_message_prompt = HumanMessagePromptTemplate.from_template(human_template)
        chat_prompt = ChatPromptTemplate.from_messages([sysTemplate, human_message_prompt])
        self.llmActMapperChain = LLMChain(llm=self.llm, 
                            prompt=chat_prompt, 
                            output_parser=CommaSeparatedListOutputParser())

    #-----------------------------------------------------------------------------
    def setVerifier(self, scenarioStr, verifyTemplate=gv.gMitreVerifyPrompt):
        """ Init the scenario technique verifier.
            Args:
                scenarioStr (str): orignal attack scenario description(ASD) string
        """
        self.llmTecVerifyChain = None 
        systemTemplate = verifyTemplate %str(scenarioStr)
        sysTemplate = SystemMessagePromptTemplate.from_template(systemTemplate)
        human_template = "MITRE ATT&CK technique: {text}"
        human_message_prompt = HumanMessagePromptTemplate.from_template(human_template)
        chat_prompt = ChatPromptTemplate.from_messages([sysTemplate, human_message_prompt])
        self.llmTecVerifyChain = LLMChain(llm=self.llm, 
                            prompt=chat_prompt, 
                            output_parser=CommaSeparatedListOutputParser())

    #-----------------------------------------------------------------------------
    def getAttackInfo(self, scenarioStr):
        """ Use AI to summarize the attack scenario report and split the attack 
            flow path to a list of single element attack behaviors.
            Args:
                scenarioStr (str): attack scenario description string
            Returns:
                list(str): list of attack behaviors.
        """
        gv.gDebugPrint("getAttackInfo() > Start to summarize the attack flow path.")
        answerList = self.llmAnalyzerChain.run(scenarioStr)
        actionList = []
        for ansStr in answerList:
            #print(ansStr)
            ansStr = ansStr.strip()
            if ansStr == 'Attack behavior:' or ansStr == '' or ansStr=='\t':
                continue
            elif '.' in ansStr:
                idx = str(ansStr.split('.')[0])
                if idx.isdigit(): actionList.append(ansStr)
            elif len(actionList) > 0:
                # the answer is splitted in 2 lines by the LLM, append the line to the previous
                actionList[-1] += ansStr
        return actionList

    #-----------------------------------------------------------------------------
    def testAttackTTP(self, scenarioStr):
        """ Get the MITRE ATT&CK TTP for a given scenario. """
        answerList = self.llmMaperChain.run(scenarioStr)
        print(answerList)
        for ansStr in answerList:
            print(ansStr)

    #-----------------------------------------------------------------------------
    def getAttackTechnique(self, behaviorList):
        """ Check a list of attack behaviors and get the technique list.
            Args:
                behaviorList (list(str)): behaviors string list.
            Returns:
                dict: {<tactic:tacticNae>:[list of technique] }
                example:
                {
                    'tactic: Initial Access': 
                        ['technique: Spearphishing Attachment (T1193)', 
                        'technique: Drive-by Compromise (T1189)']}
        """
        resultDict = {}
        for behaviorStr in behaviorList:
            rstDict = self.getBehaviorTechnique(behaviorStr)
            tacticStr = rstDict['tactic']
            techniqueList = rstDict['technique']
            if tacticStr is None: continue
            if tacticStr in resultDict.keys():
                for tech in techniqueList:
                    if not tech in resultDict[tacticStr]:
                        resultDict[tacticStr].append(tech)
            else:
                resultDict[tacticStr] = techniqueList
        return resultDict
    
    #-----------------------------------------------------------------------------
    def getBehaviorTechnique(self, behaviorStr):
        """ Use AI to getthe MITRE ATT&CK TTP for a given behaviors. 
            Args:
                behaviorStr (str): _description_
            Returns:
                dict : { 'tactic': None, 'technique': [] }
        """
        answerList = self.llmActMapperChain.run(behaviorStr)
        ttDict = { 'tactic': None, 'technique': [] }
        #print(answerList)
        for ansStr in answerList:
            ansStr = ansStr.strip()
            if ansStr.startswith('tactic'): 
                ttDict['tactic'] = ansStr
            elif ansStr.startswith('technique') :
                ttDict['technique'].append(ansStr)
        return ttDict

    #-----------------------------------------------------------------------------
    def verifyAttackTechnique(self, technique):
        """ Verify whether the technique can be find from the orignal attack scenario
            description (ASD)
            Args:
                technique (string): _description_
            Returns:
                _type_: _description_
        """
        if self.llmTecVerifyChain:
            rstDict = {'match': False , 'detail': None }
            answerList = self.llmTecVerifyChain.run(technique)
            #print(answerList)
            for ansStr in answerList:
                ansStr = ansStr.strip()
                if ansStr.lower().startswith('match' ):
                    rstDict['match'] = True if 'yes' in ansStr.lower() else False
                elif ansStr.lower().startswith('explanation'):
                    rstDict['detail'] = ansStr
            return rstDict
        else:
            gv.gDebugPrint("The tecVerifier is not define.", logType=gv.LOG_ERR)
            return None

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def testCase(mode):
    mapper = llmMITREMapper(openAIkey=gv.API_KEY)
    # Add the test threats scenario description string.
    scenarioStr = """This scenario illustrates how the red team attacker, Alice, 
    constructs a malicious macro within a MS-Office Word document (CVE-2015-1641). 
    She then embeds an auto-phishing email malware into the document, disguising all 
    malware as a harmless lucky draw USB driver. Subsequently, Alice sends this document 
    to the unsuspecting victim Bob."""
    if mode == 1:
        print("TestCase1: get the attack behaviors list.")
        atkBehList = mapper.getAttackInfo(scenarioStr)
        for atkBeh in atkBehList:
            print(atkBeh)
    elif mode == 2:
        print("TestCase2: test get TTP based on one behaviors string")
        behStr = '1. Constructing a malicious macro within a MS-Office Word document (CVE-2015-1641).'
        behStr = '4. Sending the malicious document to the unsuspecting victim.'
        ttp = mapper.getBehaviorTechnique(behStr)
        print(ttp)
    elif mode == 3:
        hehaviorsList = [
            '1. Constructing a malicious macro within a MS-Office Word document (CVE-2015-1641).',
            '2. Embedding an auto-phishing email malware into the document.',
            '3. Disguising the malware as a harmless lucky draw USB driver.',
            '4. Sending the malicious document to the unsuspecting victim.'
        ]
        ttps = mapper.getAttackTechnique(hehaviorsList)
        print(ttps)
    elif mode == 4: 
        techList = ['technique: Spearphishing Attachment (T1193)', 'technique: Drive-by Compromise (T1189)']
        mapper.setVerifier(scenarioStr)
        for tech in techList:
            rst = mapper.verifyAttackTechnique(tech)
            print(rst)
            print("---")
    else:
        pass 
        # put other test case here

#-----------------------------------------------------------------------------
if __name__ == '__main__':
    print("Please type in the test case number you want to run: ")
    uInput = str(input())
    testmode = int(uInput)
    testCase(testmode)
