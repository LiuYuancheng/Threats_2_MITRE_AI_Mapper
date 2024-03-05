#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        threats2MitreApp.py [python3]
#
# Purpose:     This module is the main web interafce to call the AI-llm MITRE 
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

from flask import Flask, render_template, flash, redirect, request, session
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit # pip install Flask-SocketIO==5.3.5

import threats2MitreGlobal as gv
#import threats2MitreAppDataMgr as dataManager
TestMd= True

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
#-----------------------------------------------------------------------------
# Init the app used globals
gv.gAppParmDict['srcName'] = None
gv.gAppParmDict['srcPath'] = None
gv.gAppParmDict['rstPath'] = None

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
    posts = {'mode': gv.gParserMode,
             'page': 1
             }
    return render_template('index.html', async_mode=socketio.async_mode, 
                           posts=posts)

@app.route('/fileupload', methods = ['POST', 'GET'])  
def fileupload():
    posts = None
    if request.method == 'POST':
        file = request.files['file']
        print(file.filename)
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        elif file and gv.gCheckFileType(file.filename):
            filename = secure_filename(file.filename)
            gv.gSrceName = filename
            gv.gSrcPath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            gv.gSrcType = filename.rsplit('.', 1)[1].lower()
            gv.gRstPath = None
            file.save(gv.gSrcPath)
            posts = {
                'mode': gv.gParserMode,
                'filename': gv.gSrceName}
    return render_template('index.html', posts=posts)

#-----------------------------------------------------------------------------
# socketIO communication handling functions. 
@socketio.event
def connect():
    gv.gWeblogCount = 0
    emit('serv_response', {'data': 'MITRE-ATT&CK Mapper Ready', 'count': gv.gWeblogCount})

@socketio.event
def cli_request(message):
    session['receive_count'] = session.get('receive_count', 0) + 1
    if message['data'] == 'download' and gv.gRstPath:
        if os.path.exists(gv.gRstPath):
            gv.gDebugPrint("Download the file.")
            with open(gv.gRstPath) as fh:
                socketio.emit('file_ready', {'filename': gv.gSrceName, 'content': fh.read()})
    else:
        emit('serv_response',
             {'data': message['data'], 'count': session['receive_count']})
    
@socketio.on('startprocess')
def startProcess(data):
    print('received message: ' + str(data))
    gv.iDataMgr.startProcess()
    emit('startprocess', {'data': 'Starting to process MCQ-source: %s' %str(gv.gSrceName)})

#-----------------------------------------------------------------------------
if __name__ == '__main__':
    #app.run(host="0.0.0.0", port=5000,  debug=False, threaded=True)
    app.run(host=gv.gflaskHost,
        port=gv.gflaskPort,
        debug=gv.gflaskDebug,
        threaded=gv.gflaskMultiTH)