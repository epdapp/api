import flask
from flask import request, jsonify
import sqlite3

DATABASE = "database.db"

app = flask.Flask(__name__)
app.config["DEBUG"] = True

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

@app.route('/dossiers/', methods=['POST'])
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
def get_dossier(dossierId):
	try:
		dossier = executeQueryResult("SELECT * FROM dossiers WHERE dossierId=?;", [dossierId])[0]
	except IndexError:
		return jsonify({"error": "not found"})


	medications = executeQueryResult("SELECT Medicatie FROM MedicatieRegel WHERE dossierId = ?;", [dossierId])
	complaints = executeQueryResult("SELECT Klacht FROM KlachtRegel WHERE dossierId = ?;", [dossierId])

	dossier.update({"m": medications, "k": complaints})

	return str(dossier)

app.run()