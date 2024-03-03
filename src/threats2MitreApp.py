#!/usr/bin/python
#-----------------------------------------------------------------------------
# Name:        app.py [python3]
#
# Purpose:     This module is the main website host program to host the scheduled
#              tasks monitor Hub webpage by using python-Flask frame work. 
#  
# Author:      Yuancheng Liu
#
# Created:     2023/08/23
# version:     v0.1.2
# Copyright:   National Cybersecurity R&D Laboratories
# License:     
#-----------------------------------------------------------------------------
# CSS lib [bootstrap]: https://www.w3schools.com/bootstrap4/default.asp
# https://www.w3schools.com/howto/howto_css_form_on_image.asp
# https://medium.com/the-research-nest/how-to-log-data-in-real-time-on-a-web-page-using-flask-socketio-in-python-fb55f9dad100

import os
import threading

from datetime import timedelta 
from flask import Flask, render_template, flash, url_for, redirect, request, session
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit # pip install Flask-SocketIO==5.3.5

import threats2MitreGlobal as gv
import threats2MitreAppDataMgr as dataManager

async_mode = None

#-----------------------------------------------------------------------------
# Init the flask web app program.
def createApp():
    """ Create the flask App."""
    app = Flask(__name__)
    app.config['SECRET_KEY'] = gv.APP_SEC_KEY
    #app.config['REMEMBER_COOKIE_DURATION'] = timedelta(seconds=gv.COOKIE_TIME)
    app.config['UPLOAD_FOLDER'] = gv.SCE_BANK
    # init the data manager
    gv.iDataMgr = dataManager.DataManager(app)
    if not gv.iDataMgr: exit()
    gv.iDataMgr.start()
    return app

def checkFile(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in gv.ALLOWED_EXTENSIONS

def initGlobal():
    gv.gSrceName = None
    gv.gSrcPath = None
    gv.gSrcType = None
    gv.gRstPath = None

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
app = createApp()
socketio = SocketIO(app, async_mode=async_mode)
gv.iSocketIO = socketio
thread = None
threadLock = threading.Lock()

#-----------------------------------------------------------------------------
# web request handling functions. 

@app.route('/')
def index():
    posts = {'mode': gv.gParserMode}
    return render_template('index.html', 
                           async_mode=socketio.async_mode, 
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
        elif file and checkFile(file.filename):
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
    app.run(host="0.0.0.0", port=5000,  debug=False, threaded=True)