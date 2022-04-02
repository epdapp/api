# Handeling all the imports

from re import I
from sqlite3.dbapi2 import IntegrityError
from types import MethodDescriptorType
from dotenv import load_dotenv
from typing import Dict
import flask
from flask import request, jsonify, url_for, session, render_template, _request_ctx_stack, Response, Blueprint
from authlib.integrations.flask_client import OAuth
import os
from datetime import timedelta
import sqlite3
import base64
from werkzeug.datastructures import CharsetAccept, Headers
import flask_cors
from flask_cors import cross_origin
import json
from six.moves.urllib.request import urlopen
from functools import wraps
from jose import jwt


# dotenv config
load_dotenv()

# app config
app = flask.Flask(__name__)
app.config["DEBUG"] = os.getenv("DEBUG")
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)
app.secret_key = os.getenv("APP_SECRET_KEY")
cors = flask_cors.CORS(app, resources={r"*": {"origins": "*"}})


# auth config
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN")
API_IDENTIFIER = os.getenv("API_IDENTIFIER")
ALGORITHMS = ["RS256"]


# Format error response and append status code.
class AuthError(Exception):
    """
    An AuthError is raised whenever the authentication failed.
    """

    def __init__(self, error: Dict[str, str], status_code: int):
        super().__init__()
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex: AuthError) -> Response:
    """
    serializes the given AuthError as json and sets the response status code accordingly.
    :param ex: an auth error
    :return: json serialized ex response
    """
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


def get_token_auth_header() -> str:
    """Obtains the access token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                         "description":
                             "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                         "description":
                         "Authorization header must start with"
                         " Bearer"}, 401)
    if len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                         "description": "Token not found"}, 401)
    if len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Authorization header must be"
                             " Bearer token"}, 401)

    token = parts[1]
    return token


def requires_scope(required_scope: str) -> bool:
    """Determines if the required scope is present in the access token
    Args:
        required_scope (str): The scope required to access the resource
    """
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("scope"):
        token_scopes = unverified_claims["scope"].split()
        for token_scope in token_scopes:
            if token_scope == required_scope:
                return True
    return False

# Kijk of de gebruiker aan de frontend is ingelogd en of er een goedgekeurde Bearer token wordt meegestuurd met de request

def requires_auth(func):
    """Determines if the access token is valid
    """

    @wraps(func)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        jsonurl = urlopen("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
        jwks = json.loads(jsonurl.read())
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.JWTError as jwt_error:
            raise AuthError({"code": "invalid_header",
                             "description":
                             "Invalid header. "
                             "Use an RS256 signed JWT Access Token"}, 401) from jwt_error
        if unverified_header["alg"] == "HS256":
            raise AuthError({"code": "invalid_header",
                             "description":
                                 "Invalid header. "
                                 "Use an RS256 signed JWT Access Token"}, 401)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_IDENTIFIER,
                    issuer="https://" + AUTH0_DOMAIN + "/"
                )
            except jwt.ExpiredSignatureError as expired_sign_error:
                raise AuthError({"code": "token_expired",
                                 "description": "token is expired"}, 401) from expired_sign_error
            except jwt.JWTClaimsError as jwt_claims_error:
                raise AuthError({"code": "invalid_claims",
                                 "description":
                                 "incorrect claims,"
                                 " please check the audience and issuer"}, 401) from jwt_claims_error
            except Exception as exc:
                raise AuthError({"code": "invalid_header",
                                 "description":
                                 "Unable to parse authentication"
                                 " token."}, 401) from exc

            _request_ctx_stack.top.current_user = payload
            return func(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                         "description": "Unable to find appropriate key"}, 401)

    return decorated

# scopes


def requires_scope(required_scope):
    """Determines if the required scope is present in the Access Token
    Args:
        required_scope (str): The scope required to access the resource
    """
    token = get_token_auth_header()
    unverified_claims = jwt.get_unverified_claims(token)
    if unverified_claims.get("scope"):
        token_scopes = unverified_claims["scope"].split()
        for token_scope in token_scopes:
            if token_scope == required_scope:
                return True
    return False

# DATABASE setup

DATABASE = "database.db"

# Query functions om sql in python te kunnen schrijven

def executeQueryId(query, to_filter):
    id = -1
    with sqlite3.connect(DATABASE) as con:
        cur = con.cursor()
        cur.execute(query, to_filter)
        id = cur.lastrowid
        con.commit()
    return id

def executeQuery(query, to_filter):
    with sqlite3.connect(DATABASE) as con:
        cur = con.cursor()
        cur.execute(query, to_filter)
        con.commit()
    return

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




# post user route

@ app.route('/users/', methods=['POST'])
@cross_origin(headers=["Content-type", "Authorization"])
@requires_auth
def post_user():

    # Get request van de gestuurde body

    user_data = request.get_json()
    
    UserId = user_data.get('userId', None)
    Naam = user_data.get('name', None)
    Email = user_data.get('email', None)
    ProfielFoto = user_data.get('profilePicture', None)

    # Post de gebruiker/dokter in de database. Als gebruiker bestaat, throw error

    try:
        newUser = executeQuery("INSERT INTO Users (UserId, Naam, Email, ProfielFoto) VALUES (?, ?, ?, ?);", [UserId, Naam, Email, ProfielFoto])
        return str(newUser)
    except(IntegrityError):
        return jsonify({"error": "gebruiker bestaat al"})

# Save dossier route om een dossier op te slaan voor ingelogde dokter

@ app.route("/saveddossiers/", methods=["PUT"])
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def saveDossier():
    # Get dossier van de gestuurde body
    dossier_data = request.get_json()

    # Get de al opgeslagen dossiers
    prestoredDossiers = dossier_data.get('dossierId', None)

    # Als prestoredDossiers een string is en er dus maar een eerdere dossier is opgeslagen, doe dan niks
    if type(prestoredDossiers) is str:
        prestoredDossiers = prestoredDossiers
    # Anders: maak van de prestoredDossiers een string (was object) en maak er een array van zodat iedere dossier los is 
    else:
        prestoredDossiers = set(map(int, str(dossier_data.get('dossierId', None)).split(', ')))
        
        # Maak er dan weer een string van zodat ie opgeslagen kan worden in de db
        prestoredDossiers = str(prestoredDossiers)[1:-1]
        
    userId = dossier_data.get('userId', None)
    print(prestoredDossiers)

    # Post het nieuwe opgeslagen dossier in de database als ie niet al bestaat

    try:
        saveNewDossier = executeQuery("UPDATE Users SET StoredDossier = ? WHERE UserId = ?", [prestoredDossiers, userId])
        return str(saveNewDossier)
    except(IntegrityError):
        return jsonify({"error": "dossier is al opgeslagen"})

# Get de savedDossiers van ingelogde gebruiker/dokter route 

@ app.route("/get-saveddossiers/<UserId>", methods=["GET"])
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def getSavedDossiers(UserId):

    # Select de dossiers uit db en return ze 
    savedDossiers = executeQueryResult("SELECT StoredDossier FROM Users WHERE UserId=?", [UserId])
    return jsonify(savedDossiers)

# Sla een dossier niet meer op 

@ app.route('/del-saved-dossier', methods=["PUT"])
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def delSavedDos():
    # Get de data van de gestuurde body

    data = request.get_json()
    userId = data.get('userId')

    # Hier was de opgeslagen dossier er al in de frontend uigehaald
    newDossierString = data.get('dosString')

    # Update de nieuwe string naar de database, anders was de dossier nooit opgeslagen. 
    try:
        newSaved = executeQueryResult("UPDATE Users SET StoredDossier =? WHERE UserId = ?", [newDossierString, userId])
        return str(newSaved)
    except(IntegrityError):
        return jsonify({"error": "Dit dossier was nooit opgeslagen"})

# Post nieuw dossier route

@ app.route('/dossiers/', methods=['POST'])
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def new_dossier():
    # Get de data die in de body is gestuurd

    dossier_data = request.get_json()

    desease = dossier_data.get('z', None)
    treatment = dossier_data.get('b', None)
    medications = dossier_data.get('m', None)
    complaints = dossier_data.get('k', None)
    age = dossier_data.get('l', None)
    result = dossier_data.get('r', None)
    sex = dossier_data.get('g', None)
    created = dossier_data.get('a', None)

    # create the dossier record
    dossierId = executeQueryId(u"INSERT INTO Dossiers (Ziekte, Geslacht, Leeftijd, Resultaat, Behandeling, Aangemaakt) VALUES (?, ?, ?, ?, ?, ?);", [
        desease, sex, age, result, treatment, created])

    # create the medication rows and link to the dossierId
    for medication in medications:
        executeQueryId(u"INSERT INTO MedicatieRegel (DossierId, Medicatie) VALUES (?, ?)", [
                       dossierId, medication])

    # create the complaints rows and link to the dossierId
    for complaint in complaints:
        executeQueryId(u"INSERT INTO KlachtRegel (DossierId, Klacht) VALUES (?, ?)", [
                       dossierId, complaint])

    return str(dossierId)

# Created in a function to re-use in a route
def get_dossier(dossierId):
    # Get the dossier record, if it does not exist error out.
    try:
        dossier = executeQueryResult(
            "SELECT * FROM dossiers WHERE dossierId=?;", [dossierId])[0]
    except IndexError:
        return jsonify({"error": "not found"})

    # Get the medication and complaints record and convert them from an array to an dictionary.
    medications = []
    for medication in executeQueryResult("SELECT Medicatie FROM MedicatieRegel WHERE dossierId = ?;", [dossierId]):
        medications.append(medication.get("Medicatie"))

    complaints = []
    for complaint in executeQueryResult("SELECT Klacht FROM KlachtRegel WHERE dossierId = ?;", [dossierId]):
        complaints.append(complaint.get("Klacht"))

    # Add the medications and the complaints to the dossier
    dossier.update({"m": medications, "k": complaints})

    # return the dossier
    return dossier

# Created in a function to re-use in a route
def del_dossier(dossierId):
    try:
        executeQueryResult(
            "DELETE FROM Dossiers WHERE dossierId = ?;", [dossierId])
        executeQueryResult(
            "DELETE FROM KlachtRegel WHERE dossierId = ?;", [dossierId])
        executeQueryResult(
            "DELETE FROM MedicatieRegel WHERE dossierId = ?;", [dossierId])
    except IndexError:
        return "Mislukt!"

# Get specifieke dossier en stuur de dossierId in de url mee
@ app.route('/dossiers/<dossierId>', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def get_dossier_str(dossierId):
    # call dossier function
    dossier = get_dossier(dossierId)

    # return the dossier
    return jsonify(dossier)

# Get alle dossiers
@ app.route('/dossiers/all', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def get_all_dosssiers():
    # Get all dossiers
    ids = executeQueryResult(
        'SELECT dossierid FROM dossiers ORDER BY DossierId desc', [])

    print(ids[0].get('DossierId'))

    results = []

    # Voor ieder id, call get_dossiers function
    for id in ids:
        results.append(get_dossier(id.get('DossierId')))
    results = jsonify(results)
    return results

# Delete specifieke dossier, id wordt in url meegestuurd
@ app.route('/dossiers/del/<dossierId>', methods=['DELETE'])
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def del_dossier_called(dossierId):
    # call de del_dossier function met de id
    del_dossier(dossierId)
    return flask.Response(status=204)

# Create full-text search
@ app.route('/dossiers/search', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def search():
    ziekte = request.args.get('z')
    behandeling = request.args.get('b')
    medicatie = request.args.get('m')
    klacht = request.args.get('k')
    geslacht = request.args.get('g')
    leeftijd = request.args.get('l')
    resultaat = request.args.get('r')
    aangemaakt = request.args.get('a')

    result = set()

    # Check waar je op wilt zoeken

    if (ziekte):
        keyword = f"%{ziekte}%"

        # Zoek voor het keyword en voor al die id's, return dossier

        ids = executeQueryResult(
            u"SELECT dossierId FROM dossiers WHERE ziekte LIKE ?;", [keyword])

        results = []

        for id in ids:
            results.append(get_dossier(id.get("DossierId")))
        results = jsonify(results)
        return results

    if (behandeling):
        keywords = behandeling.split()

        # Omdat behandeling uit meerdere woorden kan bestaan, split de behandelingen

        #  Zoek op elk keyword
        for keyword in keywords:
            keyword = f"%{keyword}%"

            ids = executeQueryResult(
                u"SELECT dossierid FROM dossiers WHERE behandeling LIKE ?;", [keyword])

            results = []

            for id in ids:
                results.append(get_dossier(id.get("DossierId")))
            results = jsonify(results)

            return results

        # results = executeQueryResult("SELECT dossierid FROM dossiers WHERE behandeling LIKE '%?%';", [keyword])

    if (medicatie):
        keywords = medicatie.split(";")

        # Zelfde verhaal als bij behandeling

        for keyword in keywords:

            ids = executeQueryResult(
                u"SELECT DossierId FROM MedicatieRegel WHERE Medicatie LIKE ?", [keyword])

            results = []

            for id in ids:
                results.append(get_dossier(id.get("DossierId")))
            results = jsonify(results)

            return results

    if (klacht):
        keywords = klacht.split(";")

        # Idemdito aan de twee hierboven

        for keyword in keywords:

            ids = executeQueryResult(
                u"SELECT DossierId FROM KlachtRegel WHERE Klacht LIKE ?", [keyword])

            results = []

            for id in ids:
                results.append(get_dossier(id.get("DossierId")))
            results = jsonify(results)

            return results

    if (geslacht):
        # Zelfde verhaal als bij ziekte
        ids = executeQueryResult(
            u"SELECT DossierId FROM Dossiers WHERE Geslacht = ?", [geslacht])

        results = []

        for id in ids:
            results.append(get_dossier(id.get("DossierId")))
        results = jsonify(results)

        return results

    if (leeftijd):
        # Zelfde verhaal als bij ziekte en geslacht
        ids = executeQueryResult(
            u"SELECT DossierId FROM Dossiers WHERE leeftijd = ?", [leeftijd])

        results = []

        for id in ids:
            results.append(get_dossier(id.get("DossierId")))
        results = jsonify(results)

        return results

    if (resultaat):
        keywords = resultaat.split()

        # Zelfde verhaal als bij behandeling

        for keyword in keywords:
            keyword = f"%{keyword}%"

        ids = executeQueryResult(
            u"SELECT DossierId FROM Dossiers WHERE Resultaat LIKE ?", [keyword])

        results = []

        for id in ids:
            results.append(get_dossier(id.get("DossierId")))
        results = jsonify(results)

        return results

    if (aangemaakt):
        keyword = f"%{aangemaakt}%"

        # zelfde verhaal als bij ziekte
        
        ids = executeQueryResult(
            u"SELECT dossierId FROM dossiers WHERE aangemaakt LIKE ?;", [keyword])

        results = []

        for id in ids:
            results.append(get_dossier(id.get("DossierId")))
        results = jsonify(results)
        return results

# Get profielFoto route met userId in de url

@ app.route('/profilepicture/<userId>', methods=['GET'])
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def getPicture(userId):
    # Vraag op van de db en return
    picture = executeQueryResult('SELECT profielFoto FROM Users WHERE UserId = ?', [userId])
    return jsonify(picture)

# Verander profielfoto route
@ app.route('/profilepicture', methods=['PUT'])
@cross_origin(headers=["Content-Type", "Authorization"])
@requires_auth
def updateProfilePicture():
    # Get de data van de gestuurde body
    data = request.get_json()
    userId = data.get('userId', None)
    newProfilePicture = data.get('picUrl', None)

    executeQueryResult("UPDATE Users SET ProfielFoto = ? WHERE UserId = ?", [newProfilePicture, userId])
    return flask.Response(status=200)

# Run de app 
if __name__ == "__main__":
    app.run(debug=True)
