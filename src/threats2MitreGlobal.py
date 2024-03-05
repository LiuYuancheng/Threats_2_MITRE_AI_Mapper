#-----------------------------------------------------------------------------
# Name:        threats2MitreGlobal.py
#
# Purpose:     This module is used as a project global config file to set the 
#              constants, parameters and instances which will be used in the 
#              other modules in the project.
#              
# Author:      Yuancheng Liu
#
# Created:     2024/02/26
# Version:     v_0.1.0
# Copyright:   Copyright (c) 2023 LiuYuancheng
# License:     MIT License
#-----------------------------------------------------------------------------
"""
For good coding practice, follow the below naming convention:
    1) Global variables should be defined with initial character 'g'.
    2) Global instances should be defined with initial character 'i'.
    3) Global CONSTANTS should be defined with UPPER_CASE letters.
"""

import os, sys

print("Current working directory is : %s" % os.getcwd())
DIR_PATH = dirpath = os.path.dirname(__file__) if os.path.dirname(__file__) else os.getcwd()
print("Current source code location : %s" % dirpath)
APP_NAME = ('OpenAI', 'threats2Mitre')

TOPDIR = 'src'
LIBDIR = 'lib'

#-----------------------------------------------------------------------------
# find the lib folder for importing the library modules
idx = dirpath.find(TOPDIR)
gTopDir = dirpath[:idx + len(TOPDIR)] if idx != -1 else dirpath   # found it - truncate right after TOPDIR
# Config the lib folder 
gLibDir = os.path.join(gTopDir, LIBDIR)
if os.path.exists(gLibDir): sys.path.insert(0, gLibDir)

#-----------------------------------------------------------------------------
# load the config file.
import ConfigLoader
CONFIG_FILE_NAME = 'config.txt'
gGonfigPath = os.path.join(dirpath, CONFIG_FILE_NAME)
iConfigLoader = ConfigLoader.ConfigLoader(gGonfigPath, mode='r')
if iConfigLoader is None:
    print("Error: The config file %s is not exist.Program exit!" %str(gGonfigPath))
    exit()
CONFIG_DICT = iConfigLoader.getJson()

#-----------------------------------------------------------------------------
# Init the logger
import Log
Log.initLogger(gTopDir, 'Logs', APP_NAME[0], APP_NAME[1], historyCnt=100, fPutLogsUnderDate=True)
# Init the log type parameters.
DEBUG_FLG   = False
LOG_INFO    = 0
LOG_WARN    = 1
LOG_ERR     = 2
LOG_EXCEPT  = 3

def gDebugPrint(msg, prt=True, logType=None):
    if prt: print(msg)
    if logType == LOG_WARN:
        Log.warning(msg)
    elif logType == LOG_ERR:
        Log.error(msg)
    elif logType == LOG_EXCEPT:
        Log.exception(msg)
    elif logType == LOG_INFO or DEBUG_FLG:
        Log.info(msg)

#-----------------------------------------------------------------------------
# Init the openAI parameters.
API_KEY = CONFIG_DICT['API_KEY']
os.environ["OPENAI_API_KEY"] = API_KEY
AI_MODEL = CONFIG_DICT['AI_MODEL']

# Init the attack scenario storage folder
gSceBank = os.path.join(dirpath, CONFIG_DICT['SCE_BANK']) if 'SCE_BANK' in CONFIG_DICT.keys() else dirpath 
gRstFolder = os.path.join(dirpath, CONFIG_DICT['RST_FOLDER']) if 'RST_FOLDER' in CONFIG_DICT.keys() else dirpath

#-----------------------------------------------------------------------------
# init the web interface parameter here
APP_SEC_KEY = 'secrete-key-goes-here'
UPDATE_PERIODIC = 15
COOKIE_TIME = 30
ALLOWED_EXTENSIONS = ('txt',)
# verify file type
def gCheckFileType(filename):
    return '.' in filename and str(filename).rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Flask App parameters : 
gflaskHost = '0.0.0.0'
gflaskPort = int(CONFIG_DICT['FLASK_SER_PORT']) if 'FLASK_SER_PORT' in CONFIG_DICT.keys() else 5000
gflaskDebug = CONFIG_DICT['FLASK_DEBUG_MD']
gflaskMultiTH =  CONFIG_DICT['FLASK_MULTI_TH']
# App global paramters dict.
gAppParmDict = {} 
gParserMode = 1
gAppRptPath = None
gWeblogCount = 0

#-----------------------------------------------------------------------------
# Init all the prompt

# Prompt use to guide AI to analyze the attack scenario to parse the attack behaviors. 
gSceAnalysePrompt="""
Check the given cyber attack scenario description and split the attack flow path to a 
list of attack behaviors. Please use the following format: 
Attack behavior:
1.attack behavior 1
2.attack behavior 2
...
"""

# Prompt used to guide AI to map behaviors to the MITRE tactic and technique
gBeh2MitrePrompt = """
You are a helpful assistant who help mapping the cyber attack behavior description to the 
tactic and technique in MITRE Adversarial Tactics, Techniques, and Common Knowledge (ATT&CK) Enterprise Matrix
Please list the tactic and technique can match the attack behavior under below format:
tactic: 
technique: 
"""

# Prompt used to guide AI to verify whether the technique can be applied/found directly
# to/from the attack scenario.
gMitreVerifyPrompt = """
Verify whether the given MITRE ATT&CK technique can be found from the attack scenario: 
%s

Description and give a short explanation about the given technique can match
which part of the scenario description. Please use the below answer format:
match: Yes/No
explanation: <Given short summary about the technique can match which part of the scenario description>
"""

# Prompt used to guide AI to map scenario contents directly to the MITRE ATT&CK  
gSce2MitrePrompt = """
You are a helpful assistant who help mapping the cyber attack scenario description's 
attack behavior to the tactic and technique in MITRE Adversarial Tactics, Techniques, 
and Common Knowledge (ATT&CK) Enterprise Matrix. Please list tactic and technique in Enterprise Matrix.
"""

# Prompt used to guide AI to find the MITRE CWE
gSceVulCheckPrompt_old = """
You are a helpful assistant who help analyzing the attack scenario description and finding
the vulnerabilities. Match the vulnerabilities to the MITRE Common Weakness Enumeration and give 
a short explanation. Please list the matched MITRE CWE under the following format:
MITRE_CWE: CWE-<number>
- vulnerability: <vulnerability name>
- explanation:  <Give a short summary about how the CWE match to the attack scenario>
"""

gSceVulCheckPrompt = """
You are a helpful assistant who help analyzing the attack scenario description and finding
the vulnerabilities. Match the vulnerabilities to the MITRE Common Weakness Enumeration and give 
a short explanation. Please list the matched MITRE CWE under the following format:
MITRE_CWE: CWE-<number>
- CWE_Name: <MITRE CWE name>
- vulnerability: short summary of the vulnerability in the scenario can match the CWE
"""

#-----------------------------------------------------------------------------
iAppDataMgr = None
iSocketIO = None