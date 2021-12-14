PRAGMA ENCODING = "UTF-16";
CREATE TABLE [Dossiers] (
	[DossierId] INTEGER PRIMARY KEY NOT NULL,
	[Ziekte] TEXT NULL,
	[Geslacht] TEXT NULL,
	[Leeftijd] INTEGER NULL,
	[Resultaat] TEXT NULL,
	[Behandeling] TEXT NULL,
	[Aangemaakt] TEXT NOT NULL
);
CREATE TABLE [KlachtRegel] (
	[KlachtRegelId] INTEGER PRIMARY KEY NOT NULL,
	[DossierId] INTEGER NULL,
	[Klacht] TEXT NULL
);
CREATE TABLE [MedicatieRegel] (
	[MedicatieRegelId] INTEGER PRIMARY KEY NOT NULL,
	[DossierId] INTEGER NULL,
	[Medicatie] TEXT NULL
);
CREATE TABLE [Users] (
	[UserId] TEXT PRIMARY KEY,
	[Naam] TEXT NOT NULL,
	[Email] TEXT NOT NULL,
	[ProfielFoto] TEXT NOT NULL,
	[StoredDossier] INTEGER NULL
);