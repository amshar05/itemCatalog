from flask import Flask, render_template, request
from flask import redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Menu, MenuItem, User
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

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"
# Connect to Database and create database session
engine = create_engine('sqlite:///menuwithusers.db', connect_args={'check_same_thread': False})
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

#google login
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
            # Obtain authorization code
    code = request.data
    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'
    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = """width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"""> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output

# User Helper Functions
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

#google dissconnect
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

#JSON API's
@app.route('/menu/<int:menu_id>/item/JSON/')
def MenuJSON(menu_id):
    menu = session.query(Menu).filter_by(id=menu_id).one()
    items = session.query(MenuItem).filter_by(
        menu_id=menu_id).all()
    return jsonify(Items=[i.serialize for i in items])


@app.route('/menu/JSON/')
def menusJSON():
    menus = session.query(Menu).all()
    return jsonify(menu=[r.serialize for r in menus])


@app.route('/menu/<int:menu_id>/item/<int:item_id>/JSON/')
def ItemJSON(menu_id, item_id):
    menu = session.query(Menu).filter_by(id=menu_id).one()
    items = session.query(MenuItem).filter_by(
        id=item_id, menu_id=menu.id).all()
    return jsonify(Items=[i.serialize for i in items])

#show all menu
@app.route('/')
@app.route('/menu/')
def showMenu():
    menus = session.query(Menu).order_by(asc(Menu.name))
    if 'username' not in login_session:
        return render_template('publicmenus.html', menus=menus)
    else:
        return render_template('menus.html', menus=menus)

#new menu
@app.route('/menu/new/', methods=['GET', 'POST'])
def newMenu():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        if len(request.form['name']) != 0:
            newMenu = Menu(
                name=request.form['name'], user_id=login_session['user_id'])
            session.add(newMenu)
            flash('New Menu %s Successfully Created' % newMenu.name)
            session.commit()
        else:
            return "<script>function myFunction() {alert('Please give a valid name');}</script><body onload='myFunction()'>"
        return redirect(url_for('showMenu'))
    else:
        return render_template('newMenu.html')

#edit menu
@app.route('/menu/<int:menu_id>/edit/', methods=['GET', 'POST'])
def editMenu(menu_id):
    menus = session.query(
        Menu).filter_by(id=menu_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if menus.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this Menu. Please create your own Menu in order to edit.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            menus.name = request.form['name']
            flash('Menu Successfully Edited %s' % menus.name)
            return redirect(url_for('showMenu'))
    else:
        return render_template('editMenu.html', menus=menus)

#delete menu
@app.route('/menu/<int:menu_id>/delete/', methods=['GET', 'POST'])
def deleteMenu(menu_id):
    menuToDelete = session.query(
        Menu).filter_by(id=menu_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if menuToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this Menu. Please create your own Menu in order to delete.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(menuToDelete)
        flash('%s Successfully Deleted' % menuToDelete.name)
        session.commit()
        return redirect(url_for('showMenu', menu_id=menu_id))
    else:
        return render_template('deleteMenu.html', menu=menuToDelete)

#show item
@app.route('/menu/<int:menu_id>/')
@app.route('/menu/<int:menu_id>/item/')
def showItem(menu_id):
    menus = session.query(Menu).filter_by(id=menu_id).one()
    creator = getUserInfo(menus.user_id)
    items = session.query(MenuItem).filter_by(
        menu_id=menu_id).all()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicmenu.html', items=items, menus=menus, creator=creator, menu_id=menu_id)
    else:
        return render_template('menu.html', items=items, menus=menus, creator=creator, menu_id=menu_id)

#new item
@app.route('/menu/<int:menu_id>/item/new/', methods=['GET', 'POST'])
def newMenuItem(menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    menus = session.query(Menu).filter_by(id=menu_id).one()
    if login_session['user_id'] != menus.user_id:
        return "<script>function myFunction() {alert('You are not authorized to add menu items to this Menu. Please create your own Menu in order to add items.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if len(request.form['name']) != 0:
            if len(request.form['description']) != 0:
                newItem = MenuItem(name=request.form['name'], description=request.form['description'],
                                menu_id=menu_id, user_id=menus.user_id)
                session.add(newItem)
                session.commit()
                flash('New Menu %s Item Successfully Created' % (newItem.name))
            else:
                return "<script>function myFunction() {alert('Please give a valid description');}</script><body onload='myFunction()'>"
        else:
            return "<script>function myFunction() {alert('Please give a valid name');}</script><body onload='myFunction()'>"
        return redirect(url_for('showItem', menu_id=menu_id))
    else:
        return render_template('newmenuitem.html', menu_id=menu_id)

#edit item
@app.route('/Menu/<int:menu_id>/menu/<int:item_id>/edit', methods=['GET', 'POST'])
def editMenuItem(menu_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(MenuItem).filter_by(id=item_id).one()
    menus = session.query(Menu).filter_by(id=menu_id).one()
    if login_session['user_id'] != menus.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit menu items to this Menu. Please create your own Menu in order to edit items.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showItem', menu_id=menu_id))
    else:
        return render_template('editmenuitem.html', menu_id=menu_id, item_id=item_id, item=editedItem)

#delete item
@app.route('/menu/<int:menu_id>/menu/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteMenuItem(menu_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    menus = session.query(Menu).filter_by(id=menu_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id=item_id).one()
    if login_session['user_id'] != menus.user_id:
        return "<script>function myFunction() {alert('You are not authorized to delete menu items to this Menu. Please create your own Menu in order to delete items.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showItem', menu_id=menu_id))
    else:
        return render_template('deletemenuitem.html', item=itemToDelete)

#description
@app.route('/menu/<int:menu_id>/menu/<int:item_id>/desc/', methods=['GET', 'POST'])
def description(menu_id, item_id):
    menus = session.query(Menu).filter_by(id=menu_id).one()
    creator = getUserInfo(menus.user_id)
    items = session.query(MenuItem).filter_by(
            id=item_id).one()
    if 'username' not in login_session or creator.id != login_session['user_id']:
        return render_template('publicdescription.html', items=items, menus=menus, creator=creator, menu_id=menu_id, item_id=item_id)
    else:
        return render_template('description.html', items=items, menus=menus, creator=creator, menu_id=menu_id, item_id=item_id)


@app.route('/menu/<int:menu_id>/menu/<int:item_id>/desc/edit', methods=['GET', 'POST'])
def editItemDesc(menu_id, item_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(MenuItem).filter_by(id=item_id).one()
    menus = session.query(Menu).filter_by(id=menu_id).one()
    if login_session['user_id'] != menus.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit menu items to this Menu. Please create your own Menu in order to edit items.');}</script><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('description', menu_id=menu_id, item_id=item_id))
    else:
        return render_template('editD.html', menu_id=menu_id, item_id=item_id, item=editedItem)


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showMenu'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showMenu'))

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
