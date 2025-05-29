#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        ConfigLoader.py
#
# Purpose:     This module will provide API to load the not stand text format 
#              config file's data. The user can call different get__ method to 
#              fetch the related and call append__ method to new data line into
#              the config file.
#
# Author:      Yuancheng Liu
#
# Created:     2019/11/12
# Version:     v_0.1.2
# Copyright:   Copyright (c) 2019 LiuYuancheng
# License:     MIT License
#-----------------------------------------------------------------------------
""" Program Design:
    Some times we want to read some program's simple customized config files which 
    are created not under stand format (Json, Yaml). This module is deisgned to 
    solve this problem. 
    Running Platform: Win, Linux, Mac
    Development Env: Python 3.7.10
    Additional Lib: N.A
    Function:
    1. Load the file in list and filtered the comments line based on the user's setting.
    2. Users can customized the comments line identify char for the lines they want to igore.
    3. Append the new data line into the config file with time stamps.
"""
import os
import json
import datetime

FILTER_CHAR = ('#', '', '\n', '\r', '\t') # comment lines 1st identify charactors.
ENCODE = 'utf-8'    # file encode format.

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class ConfigLoader(object):

    def __init__(self, filePath, mode='r', filterChars=None, logFlg=True):
        """ Init the config loader.
            example: cfg = ConfigLoader('cfg.txt', mode='r', filterChars=('#', '\n'), logFlg=False)
        Args:
            filePath ([str]): Configfile path.
            mode (str, optional): 'r'-read, 'w'-write ,'rw'-read&write, 'a'-append. Defaults to 'r'.
            filterChars ([str], optional): Comment lines 1st identify charators list.
            logFlg (bool, optional): Flag to show the running log. Defaults to True.
        """
        self.filePath = filePath
        self.mode = mode
        self.logFlg = logFlg
        self.filterCharList = filterChars if not filterChars is None and len(filterChars) > 0 else FILTER_CHAR
        if self.mode == 'r' and not os.path.exists(filePath):
            if self.logFlg: print('> Error: can not find the config file %s' % str(filePath))
            return
        self.configLines = []
        if 'r' in self.mode:
            try:
                with open(filePath) as fp:
                    for line in fp.readlines():
                        if line[0] in self.filterCharList: continue
                        line = line.strip()
                        self.configLines.append(line)
                if self.logFlg: print('> Init(): load %s lines of config' %str(len(self.configLines)))
            except:
                if self.logFlg: print('> Error: can not find the config file %s' % str(filePath))
                return
    
    #-----------------------------------------------------------------------------
    def getLines(self, filterFun=None):
        """ Get all the filered lines of the config file.
        Args:
            filterFun ([function], optional): function for filter. Defaults to None.
        Returns:
            list[str]: configfile lines data after filtered.
        """
        if not filterFun: return self.configLines
        return list(filter(filterFun, self.configLines))
    
    #-----------------------------------------------------------------------------
    def getJson(self, specChar=':'):
        """ Get the config data under json format (python dict).
        Args:
            specChar (str, optional): The key/value pair split char: key<specChar>value. 
                Defaults to ':'.
        Returns:
            dict: data json dict.
        """
        result = {}
        for line in self.configLines:
            if specChar in line:
                key, val = line.split(':', 1)
                if val.lower() == 'true':
                    val = True
                elif val.lower() == 'false': 
                    val = False
                result[key] = val
        return result

    #-----------------------------------------------------------------------------
    def setMode(self, mode):
        """ Set the file process mode.
        Args:
            mode ([str]): mode string.
        """
        self.mode = mode
    
    #-----------------------------------------------------------------------------
    def appendLine(self, line, timeFlg=False, cmtChar=None):
        """ Append a new line in the config file.
        Args:
            line ([str]): line data.
            timeFlg (bool, optional): Add the time stamp before the line. Defaults to False.
            cmtChar ([str], optional):Set char if you want to append the line as comments 
                line. Defaults to None.
        Returns:
            [bool]: Whether the line is append successfully.
        """
        if self.mode == 'r':
            if self.logFlg: print('> Cannot Append line, config loader under read only mode.')
            return False
        try:
            with open(self.filePath, 'a', encoding=ENCODE) as fh:
                if cmtChar: line = cmtChar + str(line)
                if timeFlg: line += str(datetime.datetime.now())
                fh.write(line+"\n")
            return True
        except:
            if self.logFlg: print('> Error: appendline() can not open file.')
            return False

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
class JsonLoader(object):

    def __init__(self):
        """ Init the Json file loader class."""
        self.jsonFilePath = None
        self.jsonData = None

    def _haveData(self):
        return not (self.jsonData is None or self.jsonFilePath is None)
    
    #-----------------------------------------------------------------------------
    def loadFile(self, filePath):
        """" Load the json file. """
        if not str(filePath).endswith('.json'):
            print("> Error: JsonLoader.loadFile() file path is not a json file.")
            return False
        if os.path.exists(filePath):
            try:
                with open(filePath, 'r') as fh:
                    self.jsonData= json.loads(fh.read())
                    self.jsonFilePath = filePath
            except Exception as err:
                print("Error to load the json file: %s" % str(err))
                return False
        else:
            print("> Error: JsonLoader.loadFile() file path does not exist: %s" % filePath)
            return False

    #-----------------------------------------------------------------------------
    def getJsonData(self):
        return self.jsonData

    def getJsonFilePath(self):
        return self.jsonFilePath
    
    #-----------------------------------------------------------------------------
    def updateRcdFile(self, indent=4):
        if self._haveData():
            try:
                with open(self.jsonFilePath, 'w') as fh:
                    fh.write(json.dumps(self.jsonData, indent=indent))
                    return True
            except Exception as err:
                print("Error to write the json file: %s" % str(err))
                return False
        return False

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def testCaseFilter(line):
    if 'IPADD' in line: return True
    return False
    
def testCase(mode=0):
    print("ConfigLoader TestCase() program start:")
    tCount, tPass = 0, True
    if mode == 0:
        dirpath = os.path.dirname(__file__)
        cfgfilePath = os.path.join(dirpath, 'cfgLoaderR.txt')
        
        # test case 0
        print("0. Init the config loader :\n----")
        cfgLoader = ConfigLoader(
            cfgfilePath, mode='r', filterChars=('#', '', '\n'))
        tPass = len(cfgLoader.getLines()) == 7
        if tPass:
            tCount += 1
        print("Test passed: %s \n----\n" % str(tPass))
        
        # test case 1
        print("1. Get specific line with filter test:\n----")
        datalist = cfgLoader.getLines(filterFun=testCaseFilter)
        tPass = datalist[0] == 'IPADD:127.0.0.1'
        tPass = tPass and len(datalist) == 1
        if tPass:
            tCount += 1
        print("Test passed: %s \n----\n" % str(tPass))
        
        # test case 2
        print("2. Get json data :\n----")
        jsonDict = cfgLoader.getJson()
        tPass = jsonDict['IPADD'] == '127.0.0.1'
        tPass = tPass and jsonDict['FRATE'] == '20'
        tPass = tPass and jsonDict['DISMD'] == '0'
        tPass = tPass and jsonDict['SENLV'] == '60'
        tPass = tPass and jsonDict['TGMIN'] == '400'
        tPass = tPass and jsonDict['TGMAX'] == '10000'
        tPass = tPass and jsonDict['SILAT'] == '500'
        if tPass:
            tCount += 1
        print("Test passed: %s \n----\n" % str(tPass))
        
        # test case 3
        print("3. Append data test:\n----")
        cfgfilePathW = os.path.join(dirpath, 'cfgLoaderW.txt')
        cfgLoaderW = ConfigLoader(cfgfilePathW, mode='r')
        cfgLoaderW.setMode('a')
        cfgLoaderW.appendLine('', timeFlg=True, cmtChar='#')
        cfgLoaderW.appendLine(
            '1st line we want to append in cfg with time stamp', timeFlg=True)
        cfgLoaderW.appendLine(
            '2st line we want to append in cfg without time stamp', timeFlg=False)
        tPass = os.path.exists(cfgfilePathW)
        if tPass:
            tCount += 1
        print("Test passed: %s \n----\n" % str(tPass))

        print(" => All test finished: %s/4" % str(tCount))


#-----------------------------------------------------------------------------
if __name__ == '__main__':
    testCase()
