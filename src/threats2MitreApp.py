#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        threats2MitreApp.py [python3]
#
# Purpose:     This module is the main web interface to call the AI-llm MITRE 
#              ATT&CK-Mapper/ CWE-Matcher module to generate the related report.
#  
# Author:      Yuancheng Liu
#
# Created:     2024/03/02
# version:     v0.1.2
# Copyright:   Copyright (c) 2024 LiuYuancheng
# License:     MIT License    
#-----------------------------------------------------------------------------
import os
import threading

from flask import Flask, render_template, flash, redirect, url_for, request, session
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit # pip install Flask-SocketIO==5.3.5

import threats2MitreGlobal as gv
import threats2MitreAppDataMgr as dataManager
TestMd= False

#-----------------------------------------------------------------------------
# Init the flask web app program.
def createApp():
    """ Create the flask App."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = gv.APP_SEC_KEY
    app.config['UPLOAD_FOLDER'] = gv.gSceBank
    # init the data manager
    if not TestMd:
        gv.iAppDataMgr = dataManager.DataManager(app)
        if not gv.iAppDataMgr: exit()
        gv.iAppDataMgr.start()
    return app

#-----------------------------------------------------------------------------
def uploadfile(file):
    """ upload a file from the post request"""
    print(file.filename)
    if file.filename == '':
        flash('No selected file')
    elif file and gv.gCheckFileType(file.filename):
        filename = secure_filename(file.filename)
        gv.gAppParmDict['srcName'] = filename
        gv.gAppParmDict['srcPath'] = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(gv.gAppParmDict['srcPath'])
        return True
    return False 

#-----------------------------------------------------------------------------
def createThrestsFile(contents):
    filename = 'tempScenarioFile.txt'
    gv.gAppParmDict['srcName'] = filename
    gv.gAppParmDict['srcPath'] = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    with open(gv.gAppParmDict['srcPath'] , "w") as outfile:
        outfile.write(contents)
    return True

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
# Init the app used globals
gv.gAppParmDict['srcName'] = None
gv.gAppParmDict['srcPath'] = None
gv.gAppParmDict['rstType'] = None
gv.gAppParmDict['rstName'] = None

app = createApp()

# SocketIO asynchronous mode
async_mode = None
socketio = SocketIO(app, async_mode=async_mode)
gv.iSocketIO = socketio
thread = None
threadLock = threading.Lock()

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
# web request handling functions. 
@app.route('/')
def index():
    """ route to introduction index page."""
    posts = {'page': 0} # page index is used to highlight the left page slide bar.
    return render_template('index.html', posts=posts)

#-----------------------------------------------------------------------------
@app.route('/mitreattack')
def mitreattack():
    """ route to the MITRE-ATT&CK mapper page."""
    posts = {'mode': gv.AI_MODEL,
             'page': 1}
    return render_template('mitreattack.html', async_mode=socketio.async_mode, 
                           posts=posts)

#-----------------------------------------------------------------------------
@app.route('/mitrecwe')
def mitrecwe():
    """ route to the MITRE-CWD matcher page."""
    posts = {'mode': gv.AI_MODEL,
             'page': 2}
    return render_template('mitrecwe.html', async_mode=socketio.async_mode, 
                           posts=posts)

#-----------------------------------------------------------------------------
@app.route('/configuration')
def configuration():
    """ route to the configuration page."""
    posts = {'mode': gv.AI_MODEL,
             'key': gv.API_KEY,
             'gSceAnalysePrompt': gv.gSceAnalysePrompt,
             'gBeh2MitrePrompt': gv.gBeh2MitrePrompt,
             'gMitreVerifyPrompt': gv.gMitreVerifyPrompt,
             'gSce2MitrePrompt': gv.gSce2MitrePrompt,
             'gSceVulCheckPrompt': gv.gSceVulCheckPrompt,
             'page': 3
             }
    return render_template('configuration.html', posts=posts)

#-----------------------------------------------------------------------------
@app.route('/fileatkupload', methods = ['POST', 'GET'])
def fileatkupload():
    """ Handle the threats report file upload from MITRE-ATT&CK mapper page."""
    posts = {
        'mode': gv.AI_MODEL, 
        'page': 1,
        'filename': None
    }
    if request.method == 'POST':
        file = request.files['file']
        rst = uploadfile(file)
        gv.gAppParmDict['rstType'] = 'ATK'
        if rst: posts['filename'] = gv.gAppParmDict['srcName']
    return render_template('mitreattack.html', posts=posts)

#-----------------------------------------------------------------------------
@app.route('/textatkupload', methods = ['POST', 'GET'])  
def textatkupload():
    """ Handle the threats description contents upload from MITRE-ATT&CK mapper page."""
    posts = {
        'mode': gv.AI_MODEL,
        'page': 1,
        'filename': None
    }
    if request.method == 'POST':
        data = request.form['text']
        rst = createThrestsFile(data)
        gv.gAppParmDict['rstType'] = 'ATK'
        if rst: posts['filename'] = gv.gAppParmDict['srcName']
    return render_template('mitreattack.html', posts=posts)

#-----------------------------------------------------------------------------
@app.route('/filecweupload', methods = ['POST', 'GET'])  
def filecweupload():
    """ Handle the threats report file upload from MITRE-CWE matcher page."""
    posts = {
        'mode': gv.AI_MODEL, 
        'page': 2,
        'filename': None
    }
    if request.method == 'POST':
        file = request.files['file']
        rst = uploadfile(file)
        gv.gAppParmDict['rstType'] = 'CWE'
        if rst: posts['filename'] = gv.gAppParmDict['srcName']
    return render_template('mitrecwe.html', posts=posts)

#-----------------------------------------------------------------------------
@app.route('/textcweupload', methods = ['POST', 'GET'])  
def textcweupload():
    """ Handle the threats description contents upload from MITRE-CWE matcher page."""
    posts = {
        'mode': gv.AI_MODEL,
        'page': 2,
        'filename': None
    }
    if request.method == 'POST':
        data = request.form['text']
        rst = createThrestsFile(data)
        gv.gAppParmDict['rstType'] = 'CWE'
        if rst: posts['filename'] = gv.gAppParmDict['srcName']
    return render_template('mitrecwe.html', posts=posts)

#-----------------------------------------------------------------------------
# socketIO communication handling functions. 
@socketio.event
def connect():
    gv.gWeblogCount = 0
    emit('serv_response', 
         {'data': 'LLM-LangChain Ready', 'count': gv.gWeblogCount, 'logType':'ATK'})

@socketio.event
def cli_request(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    if message['data'] == 'download' and gv.gAppRptPath:
        if os.path.exists(gv.gAppRptPath):
            gv.gDebugPrint("Download the file.")
            with open(gv.gAppRptPath) as fh:
                socketio.emit('file_ready', {'filename': gv.gAppParmDict['rstName'], 'content': fh.read()})
    else:
        emit('serv_response',
             {'data': message['data'], 'count': session['receive_count'], 'logType':'ATK'})
    
@socketio.on('startprocess')
def startProcess(data):
    print('received message: ' + str(data))
    gv.iAppDataMgr.startProcess()
    emit('startprocess', {'data': 'Starting to process thread source: %s' %str(gv.gAppParmDict['srcName'])})

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
if __name__ == '__main__':
    #app.run(host="0.0.0.0", port=5000,  debug=False, threaded=True)
    app.run(host=gv.gflaskHost,
        port=gv.gflaskPort,
        debug=gv.gflaskDebug,
        threaded=gv.gflaskMultiTH)
