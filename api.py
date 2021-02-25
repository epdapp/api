import flask
from flask import request, jsonify
import sqlite3

DATABASE = "database.db"

app = flask.Flask(__name__)
app.config["DEBUG"] = True

def executeQuery(query, to_filter):
	id = -1
	with sqlite3.connect(DATABASE) as con:
		cur = con.cursor()
		cur.execute(query, to_filter)
		id = cur.lastrowid
		con.commit()
	return id


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
	dossierId = executeQuery("INSERT INTO Dossiers (Geslacht, Leeftijd, Resultaat, Behandeling) VALUES (?, ?, ?, ?);", [sex, age, result, treatment]) 

	#create the medication rows
	for medication in medications:
		executeQuery("INSERT INTO MedicatieRegel (DossierId, Medicatie) VALUES (?, ?)", [dossierId, medication])

	#creat the complaints rows
	for complaint in complaints:
		executeQuery("INSERT INTO KlachtRegel (DossierId, Klacht) VALUES (?, ?)", [dossierId, complaint])

	return str(dossierId)




app.run()