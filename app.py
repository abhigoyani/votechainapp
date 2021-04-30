from flask import send_file
from types import MethodType
from flask import Flask, app, json, session, render_template,redirect,jsonify,make_response
from flask.globals import request
from flask.helpers import url_for
from flask_cors import CORS
from flask_pymongo import PyMongo
import bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session
from datetime import timedelta

import requests
from requests.api import options
from werkzeug.wrappers import ResponseStreamMixin

from util import verfiyKey,SendOtp
import os
from bson import ObjectId

app = Flask(__name__)
CORS(app)


app.secret_key = 'secret'

app.config['MONGO_DBNAME'] = 'votechain'
app.config['MONGO_URI'] = os.environ.get('mongoURI')
mongo = PyMongo(app)

# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sdb.sqlite3'
# app.config['SESSION_TYPE'] = 'sqlalchemy'

# sdb = SQLAlchemy(app)

# app.config['SESSION_SQLALCHEMY'] = sdb

# sess = Session(app)

txURL =  'http://0.0.0.0:5001/transaction'
rURL = 'http://0.0.0.0:5001/result'

@app.route('/')
def index():
    if 'emailSession' in session:
        users = mongo.db.users
        existing_user = users.find_one({'_id':session['emailSession']})
        return render_template('dashbord.html',email=session['emailSession'],user_name=existing_user['name'])

    return render_template('dashboard.html')


@app.route('/account',methods=['GET'])
def accounts():
    if 'emailSession' in session:
        return redirect(url_for('index'))
    return render_template('login-signup.html')


@app.route('/register',methods=['POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    if request.method == 'POST':
        users = mongo.db.users

        existing_user = users.find_one({'_id':request.form['email']})
        if existing_user is None:
            pubkey = verfiyKey(request.form['pKey'])
            if not pubkey:
                return render_template('invalid-key.html')
            
            # users.insert({'name' : request.form['userName'], 'email': request.form['email'], 'pKey':request.form['pKey'] , 'password' : hashpass})
            session.permanent = True
            app.permanent_session_lifetime = timedelta(minutes=15)
            session['otp'] = SendOtp(request.form['email'],'Verify')
            session['name'] = request.form['userName']
            session['email'] = request.form['email']
            session['pKey'] = request.form['pKey']
            session['pubKey'] = pubkey
            session['password'] = request.form['pass']

            return redirect(url_for('verifyOtp'))
    
        return render_template('email-used.html')


@app.route('/otp',methods=['GET','POST'])
def  verifyOtp():
    if request.method == 'GET': 
        return render_template('otp.html')
    
    if request.method == 'POST':
        print(session['otp']) 
        if 'otp' not in session:
            return 'somthing fishy'
        if session['otp'] == request.form['otp']:
            users = mongo.db.users
            hashpass = bcrypt.hashpw(session['password'].encode("utf-8"), salt=bcrypt.gensalt())
            users.insert({'name' : session['name'], '_id': session['email'], 'privateKey':session['pKey'], 'publicKey':session['pubKey'], 'password' : hashpass})
            session.pop('name')
            session.pop('pKey')
            session.pop('password')
            session.pop('otp')
            session['emailSession'] = session['email']
            session.pop('email')
            return redirect(url_for('index'))
        else:
            return redirect(url_for('verifyOtp'))


@app.route('/login',methods=['POST'])
def login(): 
    if request.method == 'POST':
        users = mongo.db.users
        login_user = users.find_one({'_id' : request.form['email']})
        if login_user:
            passVerif = bcrypt.checkpw(request.form['pass'].encode("utf-8"), login_user['password'])
            # print(request.form['pass'] + ' from dbb] '+ login_user['password'])
            if (passVerif == True):
                session.permanent = True
                app.permanent_session_lifetime = timedelta(minutes=60)
                session['emailSession'] = request.form['email']
                return redirect(url_for('index'))
            else:
                return render_template('wrong-pass.html')
        else:
            return render_template('wrong-pass.html')


@app.route('/forgotPass',methods=['GET','POST'])
def forgotPass():
    if request.method == 'GET':
        return render_template('forgotpass-new.html')
    elif request.method == 'POST':
        if 'email' in request.form:
            users = mongo.db.users
            existing_user = users.find_one({'_id':request.form['email']})
            if existing_user :
                session['resetotp'] = SendOtp(request.form['email'],'Reset')
                session['forgotemail'] = request.form['email']
                return render_template('reset-otp.html')
            else:
                return render_template('user-not-exist.html')
        if  request.form['resetotp']:
            if session['resetotp'] == request.form['resetotp']:
                users = mongo.db.users
                if users.update_one({'_id':session['forgotemail']},{"$set": { 'password': bcrypt.hashpw(request.form['newpass'].encode("utf-8"), salt=bcrypt.gensalt())}}) :
                    return render_template('pass-updated.html')
                else:
                    return render_template('servererror.html')
            else:
                return render_template('reset-pass-wrong-otp.html')


@app.route('/new-poll',methods=['GET','POST'])
def new_poll():
    if 'emailSession' in session:
        if request.method == 'GET':
            return render_template('create-poll.html')
        elif request.method == 'POST':
            users = mongo.db.users
            user = users.find_one({'_id':session['emailSession']})

            if request.form['visiblity'] == 'private':
                election = mongo.db.election
                election_data = {
                    'owner' : session['emailSession'],
                    'title': request.form['title'],
                    'option': request.form.getlist('option'),
                    'voter': request.form.getlist('voter'),
                    'visiblity': False
                }
                election_id = election.insert_one(election_data)

                election = mongo.db.electionResult
                
                result = {}
                for i in range(len(request.form.getlist('option'))):
                    result.update({request.form.getlist('option')[i]:0})

                election_data = {
                    '_id': election_id.inserted_id,
                    'owner' : session['emailSession'],
                    'title': request.form['title'],
                    'result':result,
                    'voterVoted': [],
                    'visiblity': False
                }

                election_id = election.insert_one(election_data)

                memo = [str(election_id.inserted_id),'private',request.form['title'],request.form.getlist('option')]

                initTx = {
                    'recipient': 'voteChain',
                    'amount':0.00,
                    'memo':memo,
                    'publicKey':user['publicKey'],
                    'privateKey':user['privateKey']
                }

                requests.post(txURL,json=initTx)
                
                for voter in request.form.getlist('voter'):

                    initTx = {
                        'recipient': voter,
                        'amount':0.00,
                        'memo':str(election_id.inserted_id),
                        'publicKey':user['publicKey'],
                        'privateKey':user['privateKey']
                    }
                    requests.post(txURL,json=initTx)

                return render_template('private-init.html',electionid1=str(election_id.inserted_id))
            else:
                election = mongo.db.election
                election_data = {
                    'owner' : session['emailSession'],
                    'title': request.form['title'],
                    'option': request.form.getlist('option'),
                    'voter': request.form.getlist('voter'),
                    'visiblity': True
                }
                election_id = election.insert_one(election_data)

                election = mongo.db.electionResult
                
                result = {}
                for i in range(len(request.form.getlist('option'))):
                    result.update({request.form.getlist('option')[i]:0})

                election_data = {
                    '_id': election_id.inserted_id,
                    'owner' : session['emailSession'],
                    'title': request.form['title'],
                    'result':result,
                    'voterVoted': [],
                    'visiblity': False
                }

                memo = [str(election_id.inserted_id),'public',request.form['title'],request.form.getlist('option')]

                initTx = {
                    'recipient': 'voteChain',
                    'amount':0.00,
                    'memo':memo,
                    'publicKey':user['publicKey'],
                    'privateKey':user['privateKey']
                }

                requests.post(txURL,json=initTx)

                return render_template('private-init.html',electionid1=str(election_id.inserted_id))
    else :
        return render_template('not-loggedin.html')
    

@app.route('/vote',methods=['GET'])
def voteTemplet():
    return render_template('find_election.html')

@app.route('/vote/<electionId>',methods=['GET'])
def election(electionId):
    if request.method == 'GET':
        if electionId == '' or electionId == None :
            return redirect(url_for(voteTemplet))
        else:
            if len(electionId) != 24:
                return render_template('eid-not-found.html')
            election = mongo.db.election
            electionData = election.find_one({'_id':ObjectId(electionId)})
            if not electionData:
                return render_template('eid-not-found.html')
            electionData['_id'] = str(electionData['_id'])
            # electionData['option']
            # options={}
            # for i in range(len(electionData['option'])):
            #         options.update({electionData['option'][i]:0})
            # result =requests.get(rURL,json={'eid':electionData['_id'],'options':options}).json()
            # print(result)
            # res.set_cookie('result',json.dumps(result))
            return render_template('result.html')


@app.route('/vote/<electionId>/vote',methods=['GET','POST'])
def vote(electionId):
    if request.method == 'GET':
        election = mongo.db.election
        electionData = election.find_one({'_id':ObjectId(electionId)})
        if electionData is None:
            return render_template('eid-not-found.html')
        electionData['_id'] = str(electionData['_id'])
        resp = make_response(render_template('do_vote.html'))
        resp.set_cookie('eData',json.dumps(electionData))
        print(json.dumps(electionData))
        return resp
    elif request.method == 'POST':
        if len(electionId) != 24:
            return render_template('eid-not-found.html')
        election = mongo.db.election
        electionData = election.find_one({'_id':ObjectId(electionId)})
        if electionData is None:
            return render_template('eid-not-found.html')
        pubKey = verfiyKey(request.form['pKey'])
        if pubKey is False:
            return render_template('invalid-key.html')
        if electionData['visiblity'] == False:
            if pubKey not in electionData['voter']:
                return render_template('not-eligible.html')
            if not requests.get('http://0.0.0.0:5001/first-vote-verify',json={"eId":electionId,"publicKey":pubKey}).json():
                return render_template('not-eligible.html')
            else:
                requests.post(txURL,json={
                    'publicKey':pubKey,
                    'privateKey':request.form['pKey'],
                    'memo':[electionId,request.form['option']],
                    'amount':0.0,
                    'recipient':'voteChain'
                })
                return render_template('private-init.html',electionid1=electionId)
        else:
            requests.post(txURL,json={
                'publicKey':pubKey,
                'privateKey':request.form['pKey'],
                'memo':[electionId,request.form['option']],
                'amount':0.0,
                'recipient':'voteChain'
            })
            return render_template('private-init.html',electionid1=electionId)

@app.route('/get-option/<nodeid>',methods=['GET'])
def get_option(nodeid):
    # values = request.get_json()
    election = mongo.db.election
    electionData = election.find_one({'_id':ObjectId(nodeid)})
    if not election:
        return 'not found'
    electionData['_id'] = str(electionData['_id']) 
    options={}
    for i in range(len(electionData['option'])):
        options.update({electionData['option'][i]:0})
    # print(options)
    result =requests.get(rURL,json={'eid':electionData['_id'],'options':options}).json()
    result['title'] = electionData['title']
    print(result)
    return jsonify(result)


@app.route('/getelectionlist/<email>',methods=['GET'])
def getElist(email):
    users = mongo.db.election
    result={
        "elect":[]
    }
    for x in users.find({'owner':email},{ "_id": 1, "title": 1 }):
        x['_id'] = str(x['_id'])
        result['elect'].append(x)
    print(result)
    return jsonify(result)


@app.route('/download',methods=['GET'])
def downloadNode():
    return send_file('static/blockchain/node.zip',as_attachment=True)

    

        


if __name__ == '__main__' :
    app.run(debug=True,port=5001)