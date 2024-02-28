#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        mitreMapperUtils.py
#
# Purpose:     This module will provide two LLM-AI MITRE frame work
#              
#                
# Author:      Yuancheng Liu
#
# Created:     2023/08/14
# Version:     v_0.1.2
# Copyright:   Copyright (c) 2023 LiuYuancheng
# License:     MIT License
#-----------------------------------------------------------------------------

import os
import time
import json

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
    """ MCQ solving module. """

    def __init__(self, openAIkey=None) -> None:
        # init the openAI conersation 
        if openAIkey: os.environ["OPENAI_API_KEY"] = openAIkey
        self.llm = ChatOpenAI(temperature=0, model_name=gv.AI_MODEL)

        self.llmAnalyzerChain = None 
        self._initASDAnalyzer()

        self.llmMaperChain = None 
        self._initASDMapper()

        self.llmActMapperChain = None 
        self._initActionMapper()

        self.llmTecVerifyChain = None

#-----------------------------------------------------------------------------
    def _initASDAnalyzer(self, systemTemplate=gv.gSceAnalysePrompt):
        """ Init the attack action and behavior analyser chain.
        """
        sysTemplate = SystemMessagePromptTemplate.from_template(systemTemplate)
        human_template = "Attack Scenario : {text}"
        human_message_prompt = HumanMessagePromptTemplate.from_template(human_template)
        chat_prompt = ChatPromptTemplate.from_messages([sysTemplate, human_message_prompt])
        self.llmAnalyzerChain = LLMChain(llm=self.llm, 
                            prompt=chat_prompt, 
                            output_parser=CommaSeparatedListOutputParser())

    def _initASDMapper(self, systemTemplate=gv.gSce2MitrePrompt):
        sysTemplate = SystemMessagePromptTemplate.from_template(systemTemplate)
        human_template = "{text}"
        human_message_prompt = HumanMessagePromptTemplate.from_template(human_template)
        chat_prompt = ChatPromptTemplate.from_messages([sysTemplate, human_message_prompt])
        self.llmMaperChain = LLMChain(llm=self.llm, 
                            prompt=chat_prompt, 
                            output_parser=CommaSeparatedListOutputParser())

    def _initActionMapper(self, systemTemplate=gv.gBeh2MitrePrompt):
        sysTemplate = SystemMessagePromptTemplate.from_template(systemTemplate)
        human_template = "{text}"
        human_message_prompt = HumanMessagePromptTemplate.from_template(human_template)
        chat_prompt = ChatPromptTemplate.from_messages([sysTemplate, human_message_prompt])
        self.llmActMapperChain = LLMChain(llm=self.llm, 
                            prompt=chat_prompt, 
                            output_parser=CommaSeparatedListOutputParser())

    def setVerifier(self, scenarioStr, verifyTemplate=gv.gMitreVerifyPrompt):
        self.llmTecVerifyChain = None 
        systemTemplate = verifyTemplate %str(scenarioStr)
        sysTemplate = SystemMessagePromptTemplate.from_template(systemTemplate)
        human_template = "MITRE ATT&CK technique: {text}"
        human_message_prompt = HumanMessagePromptTemplate.from_template(human_template)
        chat_prompt = ChatPromptTemplate.from_messages([sysTemplate, human_message_prompt])
        self.llmTecVerifyChain = LLMChain(llm=self.llm, 
                            prompt=chat_prompt, 
                            output_parser=CommaSeparatedListOutputParser())


    def getAttackInfo(self, scenarioStr):
        gv.gDebugPrint("Start to summarize the attack flow path.")
        answerList = self.llmAnalyzerChain.run(scenarioStr)
        actionList = []
        for ansStr in answerList:
            print(ansStr)
            #ansStr = ansStr.strip()
            #if ansStr == 'Attack behavior:': continue



    def getAttackTTP(self, scenarioStr):
        """ Get the MITRE ATT&CK TTP for a given scenario. """ 
        answerList = self.llmMaperChain.run(scenarioStr)
        print(answerList)
        for ansStr in answerList:
            print(ansStr)

    def getAttackTechnique(self, actionStr):
        answerList = self.llmActMapperChain.run(actionStr)
        print(answerList)
        for ansStr in answerList:
            print(ansStr)

    def verifyAttackTechnique(self, technique):
        if self.llmTecVerifyChain:
            answerList = self.llmTecVerifyChain.run(technique)
            print(answerList)
            for ansStr in answerList:
                print(ansStr)


def testCase():
    mapper = llmMITREMapper(openAIkey=gv.API_KEY)
    scenarioStr = """This scenario illustrates how the red team attacker, Alice, 
    constructs a malicious macro within a MS-Office Word document (CVE-2015-1641). 
    She then embeds an auto-phishing email malware into the document, disguising all 
    malware as a harmless lucky draw USB driver. Subsequently, Alice sends this document 
    to the unsuspecting victim Bob."""
    #mapper.getAttackInfo(scenarioStr)
    #mapper.getAttackTTP(scenarioStr)
    actionstr = "Alice constructs a malicious macro within a MS-Office Word document."
    mapper.getAttackTechnique(actionstr)
    print(">> verify result")
    mapper.setVerifier(scenarioStr)
    mapper.verifyAttackTechnique("T1203")

#-----------------------------------------------------------------------------
if __name__ == '__main__':
    testCase()
