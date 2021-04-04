import flask
from flask import request, jsonify, url_for, session
from authlib.integrations.flask_client import OAuth
import os
from datetime import timedelta
import sqlite3
import base64

from auth_decorator import login_required

DATABASE = "database.db"

#dotenv setup
from dotenv import load_dotenv
load_dotenv()

#app config
app = flask.Flask(__name__)
app.config["DEBUG"] = os.getenv("DEBUG")
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)
app.secret_key = os.getenv("APP_SECRET_KEY")


# oAuth Setup
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'openid email profile'},
)

def executeQueryId(query, to_filter):
	id = -1
	with sqlite3.connect(DATABASE) as con:
		cur = con.cursor()
		cur.execute(query, to_filter)
		id = cur.lastrowid
		con.commit()
	return id

def executeQueryResult(query, to_filter):
	result = []

	with sqlite3.connect(DATABASE) as con:
		con.row_factory = dict_factory
		cur = con.cursor()
		result = cur.execute(query, to_filter).fetchall()
		con.commit()

	return result

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

@app.route('/login')
def login():
    google = oauth.create_client('google')  # create the google oauth client
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')  # create the google oauth client
    token = google.authorize_access_token()  # Access token from google (needed to get user info)
    resp = google.get('userinfo')  # userinfo contains stuff u specificed in the scrope
    user_info = resp.json()
    user = oauth.google.userinfo()  # uses openid endpoint to fetch user info
    # Here you use the profile/user data that you got and query your database find/register the user
    # and set ur own data in the session not the profile from google
    session['profile'] = user_info
    session.permanent = True  # make the session permanant so it keeps existing after broweser gets closed
    return flask.redirect('/logedin')

@app.route('/logedin')
def logedin():
	login = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
	return flask.redirect(f'edpapp:?{base64.b64encode(login.encode()).decode()}')

@app.route('/dossiers/', methods=['POST'])
@login_required
def new_dossier():
	dossier_data = request.get_json()

	treatment = dossier_data.get('b', None)
	medications = dossier_data.get('m', None)
	complaints = dossier_data.get('k', None)
	age = dossier_data.get('l', None)
	result = dossier_data.get('r', None)
	sex = dossier_data.get('g', None)

	#create the dossier record
	dossierId = executeQueryId("INSERT INTO Dossiers (Geslacht, Leeftijd, Resultaat, Behandeling) VALUES (?, ?, ?, ?);", [sex, age, result, treatment]) 

	#create the medication rows
	for medication in medications:
		executeQueryId("INSERT INTO MedicatieRegel (DossierId, Medicatie) VALUES (?, ?)", [dossierId, medication])

	#creat the complaints rows
	for complaint in complaints:
		executeQueryId("INSERT INTO KlachtRegel (DossierId, Klacht) VALUES (?, ?)", [dossierId, complaint])

	return str(dossierId)


@app.route('/dossiers/<dossierId>', methods=['GET'])
@login_required
def get_dossier(dossierId):
	#Get the dossier record, if it does not exist error out.
	try:
		dossier = executeQueryResult("SELECT * FROM dossiers WHERE dossierId=?;", [dossierId])[0]
	except IndexError:
		return jsonify({"error": "not found"})

	#Get the medication and complaints record and convert them from an array to an dictionary. 
	medications = []
	for medication in executeQueryResult("SELECT Medicatie FROM MedicatieRegel WHERE dossierId = ?;", [dossierId]):
		medications.append(medication.get("Medicatie"))

	complaints = []
	for complaint in executeQueryResult("SELECT Klacht FROM KlachtRegel WHERE dossierId = ?;", [dossierId]):
		complaints.append(complaint.get("Klacht"))

	#Add the medications and the complaints to the dossier
	dossier.update({"m": medications, "k": complaints})

	#return the dossier
	return str(dossier)

@app.route('/search')
@login_required
def search():
	behandeling = request.args.get('b')
	medicatie = request.args.get('m')
	klacht = request.args.get('k')
	geslacht = request.args.get('g')
	leeftijd = request.args.get('l')
	resultaat = request.args.get('r')

	result = set()

	if (behandeling):
		keywords = behandeling.split()

		for keyword in keywords:
			keyword = f"%{keyword}%"

			searchResults = executeQueryResult("SELECT dossierid FROM dossiers WHERE behandeling LIKE ?;", [keyword])

			for searchResult in searchResults:
				result.add(searchResult.get('DossierId'))

		# results = executeQueryResult("SELECT dossierid FROM dossiers WHERE behandeling LIKE '%?%';", [keyword])

	if (medicatie):
		keywords = medicatie.split(";")

		for keyword in keywords:
			searchResults = executeQueryResult("SELECT DossierId FROM MedicatieRegel WHERE Medicatie LIKE ?", [keyword])
			keyResultSet = set()

			for searchResult in searchResults:
				keyResultSet.add(searchResult.get('DossierId'))
			
			if result:
				result = keyResultSet.intersection(result)
			else:
				result = keyResultSet

	if (klacht):
		keywords = medicatie.split(";")

		for keyword in keywords:
			searchResults = executeQueryResult("SELECT DossierId FROM KlachtRegel WHERE Medicatie LIKE ?", [keyword])
			keyResultSet = set()

			for searchResult in searchResults:
				keyResultSet.add(searchResult.get('DossierId'))
			
			if result:
				result = keyResultSet.intersection(result)
			else:
				result = keyResultSet

	if (geslacht):
		searchResults = executeQueryResult("SELECT DossierId FROM Dossiers WHERE Geslacht = ?", [geslacht])
		searchResultSet = set()

		for searchResult in searchResults:
			searchResultSet.add(searchResult.get('DossierId'))
		
		if result:
			result = keyResultSet.intersection(result)
		else:
			result = keyResultSet

	if (geslacht):
		searchResults = executeQueryResult("SELECT DossierId FROM Dossiers WHERE Geslacht = ?", [geslacht])
		searchResultSet = set()

		for searchResult in searchResults:
			searchResultSet.add(searchResult.get('DossierId'))
		
		if result:
			result = keyResultSet.intersection(result)
		else:
			result = keyResultSet

	if (leeftijd):
		searchResults = executeQueryResult("SELECT DossierId FROM Dossiers WHERE leeftijd = ?", [leeftijd])
		searchResultSet = set()

		for searchResult in searchResults:
			searchResultSet.add(searchResult.get('DossierId'))
		
		if result:
			result = keyResultSet.intersection(result)
		else:
			result = keyResultSet

	if (resultaat):
		searchResults = executeQueryResult("SELECT DossierId FROM Dossiers WHERE Geslacht = ?", [resultaat])
		searchResultSet = set()

		for searchResult in searchResults:
			searchResultSet.add(searchResult.get('DossierId'))
		
		if result:
			result = keyResultSet.intersection(result)
		else:
			result = keyResultSet


	return jsonify(list(result))

if __name__=="__main__":
    app.run()
