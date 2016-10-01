from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, desc, update, asc, func
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, Item, User

from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response 
import requests

loginUserId = 0 

CLIENT_ID = json.loads(
	open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"
	
#Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

@app.route('/')
@app.route('/login')
def showLogin():
	state = ''.join(random.choice(string.ascii_uppercase + string.digits)
		for x in xrange(32))
	login_session['state'] = state
	return render_template('login.html', STATE=state)

# Login using a Google account.  Create user record in database if it does not exist.	
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
	url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
	h = httplib2.Http()
	result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
	if result.get('error') is not None:
		response = make_response(json.dumps(result.get('error')), 500)
		response.headers['Content-Type'] = 'application/json'

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
		response = make_response(json.dumps('Current user is already connected.'),200)
		response.headers['Content-Type'] = 'application/json'
		return response

    # Store the access token in the session for later use.
	login_session['access_token'] = credentials.access_token
	login_session['gplus_id'] = gplus_id

    # Get user infouserinfo_url
	userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
	params = {'access_token': credentials.access_token, 'alt': 'json'}
	answer = requests.get(userinfo_url, params=params)
	
	data = answer.json()
	
	login_session['username'] = data['name']
	login_session['picture'] = data['picture']
	login_session['email'] = data['email']
	
	output = ''
	output += '<h1>Welcome, '
	output += login_session['username']
	output += '!</h1>'
	output += '<img src="'
	output += login_session['picture']
	output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
	flash("you are now logged in as %s" % login_session['username'])
	
	login_session['user_id'] = getUserID(login_session['email'])
	if login_session['user_id'] is None:
		login_session['user_id'] = createUser(login_session)
		if login_session['user_id'] is None:
			flash("Error creating user record for %s." % login_session['email'])
		else:
			flash ("User record for %s was successfully created." % login_session['email'])
	else:
		print "User %s is already created." % login_session['email']
	print "done!"
	return output	

# Create user record in database	
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter(User.email==login_session['email']).one()
    return user.id

# Get user information
def getUserInfo(user_id):
    user = session.query(User).filter(User.id==user_id).one()
    return user

# get User ID
def getUserID(email):
	try:
		user = session.query(User).filter(User.email==email).one()
		return user.id
	except:
		return None

# Log off and clear out session information		
@app.route('/gdisconnect')
def gdisconnect():
	access_token = login_session['access_token']
	if access_token is None:
		response = make_response(json.dumps('Current user not connected.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
	h = httplib2.Http()
	result = h.request(url, 'GET')[0]
	if result['status'] == '200':
		del login_session['access_token'] 
		del login_session['gplus_id']
		del login_session['username']
		del login_session['email']
		del login_session['picture']
		response = make_response(json.dumps('Successfully disconnected.'), 200)
		response.headers['Content-Type'] = 'application/json'
		return response	
	else:
		response = make_response(json.dumps('Failed to revoke token for given user.', 400))
		response.headers['Content-Type'] = 'application/json'
		return response
	
	
#JSON APIs to list Catalog-Items Information
@app.route('/category/<string:category_name>/JSON')
def categoryJSON(category_name):
	category = session.query(Category).filter(Category.name == category_name).first()
	items = session.query(Item).filter(Item.category_id == category.id).all()
	return jsonify(Items=[i.serialize for i in items])

# JSON API to list item data
@app.route('/category/<string:category_name>/item/<string:item_name>/JSON')
def itemJSON(category_name, item_name):
	category = session.query(Category).filter(Category.name == category_name).first()
	item = session.query(Item).filter(Item.name == item_name, Item.category_id == category.id).one()
	return jsonify(Item = item.serialize)

#Show all Categories & Items.  Enable user to create new items if logged in.  Otherwise, user has view only access.
@app.route('/showAllItems')
def showAllItems():
  items = session.query(Item).order_by(desc(Item.created_date))
  categories = session.query(Category).order_by(asc(Category.name))
  heading = "Latest Items"
  if 'username' not in login_session:
	showLogin()
	return render_template('publicShowAllItems.html',items=items, categories=categories, heading=heading)
  else:
	return render_template('showAllItems.html',items=items, categories=categories, heading=heading)

#Show Item details.  Enable user to update or delete item created by user.  Otherwise, item is display only.
@app.route('/category/<string:category_name>/item/<string:item_name>')
def showItem(category_name, item_name):
  category = session.query(Category).filter(Category.name==category_name).one()
  item = session.query(Item).filter(Item.name==item_name, Item.category_id==category.id).one()
  if 'username' not in login_session or item.user_id != login_session['user_id']:
    return render_template('publicShowItem.html',item=item)
  else:
    return render_template('showItem.html',item=item) 
  
#Show items of category 
@app.route('/category/<string:category_name>')
def showCategory(category_name):
  categories = session.query(Category).order_by(asc(Category.name))
  category = session.query(Category).filter(Category.name==category_name).one()
  items = session.query(Item).filter(Item.category_id==category.id).order_by(asc(Item.name)).all()
  item_count = session.query(Item).filter(Item.category_id==category.id).order_by(asc(Item.name)).count() 
  heading = "%s Items (%s items) " % (category.name, item_count) 
  if 'username' not in login_session:
    return render_template('publicShowAllItems.html',items=items, categories=categories, heading=heading)
  else:
    return render_template('showAllItems.html',items=items, categories=categories, heading=heading)

#Create a new item
@app.route('/new/',methods=['GET','POST'])
def newItem():
  if 'username' not in login_session:
	flash('You must be logged in to add item.')
	return redirect('/login')
  if request.method == 'POST': 
	if numberOfSameItemInCategory(request.form['category'],
		request.form['name']) > 0:
		flash('Item %s already exist' % request.form['name'])
		categories = session.query(Category).order_by(asc(Category.name))
		return render_template('newitem.html', categories = categories)
	else:
		newItem = Item(name = request.form['name'], 
			description = request.form['description'],
			category_id = request.form['category'],
			user_id = login_session['user_id'])
		session.add(newItem)
		try:
			session.commit()
			flash('%s item was successfully created' % (newItem.name))
		except:
			session.rollback()
			flash('An error was encountered while adding the new item')
		return redirect(url_for('showAllItems'))
  else:
	categories = session.query(Category).order_by(asc(Category.name))
	return render_template('newitem.html', categories = categories)
 
def numberOfSameItemInCategory(category_id, item_name):
	recCount = session.query(Item).filter(Item.name==item_name, Item.category_id==category_id).count() 
	return recCount

#Edit item
@app.route('/category/<string:old_category_name>/item/<string:old_item_name>/edit/',methods=['GET','POST'])
def editItem(old_category_name, old_item_name):
  if 'username' not in login_session:
	flash('You must be logged in to update item.')
	return redirect('/login')
  if request.method == 'POST': 
	category = session.query(Category).filter(Category.name==old_category_name).one()
	item = session.query(Item).filter(Item.name==old_item_name, Item.category_id==category.id).one()	
	stmt = update(Item).where(Item.id==item.id).values(name = request.form['name'], 
		description = request.form['description'], 
		category_id = request.form['category_id'])
	session.execute(stmt)
	session.commit()
	flash('%s item was successfully updated' % (item.name)) 
	return redirect(url_for('showAllItems'))
  else:
	category = session.query(Category).filter(Category.name==old_category_name).one()
	item = session.query(Item).filter(Item.name==old_item_name, Item.category_id==category.id).one()
	categories = session.query(Category).order_by(asc(Category.name))
	return render_template('edititem.html', item=item, categories=categories)

#Delete item
@app.route('/category/<string:category_name>/item/<string:item_name>/delete/',methods=['GET','POST'])
def deleteItem(category_name, item_name):
	if 'username' not in login_session:
		flash('You must be logged in to delete item.')
		return redirect('/login')
  	category = session.query(Category).filter(Category.name==category_name).one()
	item = session.query(Item).filter(Item.name==item_name, Item.category_id==category.id).one()
	if request.method == 'POST':
		session.delete(item)
		session.commit()
		flash('%s item was successfully deleted.' % item.name)
		return redirect(url_for('showAllItems'))
	else:
		return render_template('deleteitem.html', item=item)	
	
if __name__ == '__main__':
  app.secret_key = 'super_secret_key'
  app.debug = True
  app.run(host = '0.0.0.0', port = 8000)