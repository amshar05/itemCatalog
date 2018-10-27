from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from db import Base, MainMenu, ItemMenu, User
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests


app = Flask(__name__)

engine = create_engine('sqlite:///item_catalog.db',connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/menu/')
@app.route('/')
def mainMenu():
    menu = session.query(MainMenu).all()
    if 'username' not in login_session:
        return render_template('home.html',menu=menu)
    else:
        return render_template('userhome.html',menu=menu)

@app.route('/menu/<int:menu_id>/')
def itemMenu(menu_id):
    menu = session.query(MainMenu).filter_by(id=menu_id).one()
    item = session.query(ItemMenu).filter_by(mainmenu_id= menu_id).all()
    if 'username' not in login_session:
        return render_template('item.html', item=item, menu=menu,
            menu_id=menu_id)
    else:
        return render_template('useritem.html', item=item, menu=menu,
            menu_id=menu_id)

@app.route('/menu/<int:menu_id>/<int:item_id>/desc/')
def description(menu_id,item_id):
    menu = session.query(MainMenu).filter_by(id=menu_id).one()
    item = session.query(ItemMenu).filter_by(id= item_id).one()
    if 'username' not in login_session:
        return render_template('description.html', item=item, menu= menu,
            menu_id=menu_id,item_id=item_id)
    else:
        return render_template('userdescription.html', item=item, menu= menu,
            menu_id=menu_id,item_id=item_id)

######EDIT########
@app.route('/menu/<int:menu_id>/edit/',methods=['GET','POST'])
def editMenu(menu_id):
    menu = session.query(MainMenu).filter_by(id=menu_id).one()
    if 'username' not in login_session:
        return redirect ('/login')
    if menu.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this restaurant. Please create your own restaurant in order to edit.');}</script><body onload='myFunction()'>"
    if request.method =='POST':
        if request.form['name']:
            menu.name=request.form['name']
        session.add(menu)
        session.commit()
        flash('Menu %s edited successfully' %menu.name)
        return redirect(url_for('mainMenu'))
    else:
        return render_template('editMenu.html',menu_id=menu_id,menu=menu)

@app.route('/menu/<int:menu_id>/<int:item_id>/edit/',methods=['GET','POST'])
def editItemName(menu_id,item_id):
    menu = session.query(MainMenu).filter_by(id=menu_id).one()
    item= session.query(ItemMenu).filter_by(id=item_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if item.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this item. Please create your own in order to edit.');}</script><body onload='myFunction()'>"
    if request.method=='POST':
        if request.form['name']:
            item.name = request.form['name']
        session.add(item)
        session.commit()
        flash('Item %s name edited successfully ' %item.name)
        return redirect(url_for('itemMenu',menu_id=menu_id,item_id=item_id))
    else:
        return render_template('editItemName.html', menu_id=menu_id,
            item_id=item_id,menu=menu, item=item)

@app.route('/menu/<int:menu_id>/<int:item_id>/desc/edit/',methods=['GET','POST'])
def editItemDesc(menu_id,item_id):
    menu = session.query(MainMenu).filter_by(id=menu_id).one()
    item= session.query(ItemMenu).filter_by(id=item_id).one()
    if 'username' not in login_session:
        return redirect ('/login')
    if item.description.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this restaurant. Please create your own restaurant in order to edit.');}</script><body onload='myFunction()'>"
    if request.method=='POST':
        if request.form['description']:
            item.description = request.form['description']
        session.add(item)
        session.commit()
        flash('Item %s description edited successfully ' %item.name)
        return redirect(url_for('description',menu_id=menu_id,item_id=item_id))
    else:
        return render_template('editItemDesc.html', menu_id=menu_id,
            item_id=item_id,menu=menu, item=item)

######ADD#####
@app.route('/menu/add/',methods=['GET','POST'])
def addMenu():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method=='POST':
        if request.form['name']:
            newMenu=MainMenu(name=request.form['name'])
        session.add(newMenu)
        session.commit()
        flash('new menu %s added!' %newMenu.name)
        return redirect(url_for('mainMenu'))
    else:
        return render_template('addMenu.html')

@app.route('/menu/<int:menu_id>/add/',methods=['GET','POST'])
def addItem(menu_id):
    menu=session.query(MainMenu).filter_by(id=menu_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if request.method=='POST':
        newItem=ItemMenu(name=request.form['name'],
            mainmenu_id=menu.id)
        session.add(newItem)
        session.commit()
        return redirect(url_for('itemMenu',menu_id=menu_id,menu=menu))
    else:
        return render_template('addItem.html',menu_id=menu_id,menu=menu)
#####DELETE#######
@app.route('/menu/<int:menu_id>/delete/',methods=['GET','POST'])
def deleteMenu(menu_id):
    delmenu = session.query(MainMenu).filter_by(id=menu_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if delmenu.user_id!= login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this restaurant. Please create your own restaurant in order to edit.');}</script><body onload='myFunction()'>"
    if request.method=='POST':
        session.delete(delmenu)
        session.commit()
        flash('Menu deleted successfully!')
        return redirect(url_for('mainMenu'))
    else:
        return render_template('deleteMenu.html',menu_id=menu_id)

@app.route('/menu/<int:menu_id>/<int:item_id>/delete/',methods=['GET','POST'])
def deleteItem(menu_id,item_id):
    delitem= session.query(ItemMenu).filter_by(id=item_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if delitem.user_id!= login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this restaurant. Please create your own restaurant in order to edit.');}</script><body onload='myFunction()'>"
    if request.method=='POST':
        session.delete(delitem)
        session.commit()
        flash('Item deleted successfully!')
        return redirect(url_for('itemMenu',menu_id=menu_id,item_id=item_id))
    else:
        return render_template('deleteItem.html',menu_id=menu_id,item_id=item_id)


@app.route('/login/')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state')!=login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'),401)
        response.headers['Content-Type']='application/json'
        return response

    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make.response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type']='application/json'
        return response

    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
            % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET') [1])
    if result.get('error') is not None:
        response=make_response(json.dumps(result.get('error')), 500)
        response.headers['contentType'] = 'application/json'
        return response

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token;s user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    userinfo_url = ""
    params = {'access_token': credentials.access_token, 'alt':'json'}
    answer = requests.get(userindo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture']= data['picture']
    login_session['email']= data['data']

    login_session['provider'] = 'google'

    user_id = getUserID(data['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"



if __name__ == '__main__':
    app.debug = True
    app.secret_key='super_secret_key'
    app.run(host='0.0.0.0', port=8000)
