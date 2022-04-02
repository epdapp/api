-- Main query om de database te maken

PRAGMA ENCODING = "UTF-8";
CREATE TABLE [Dossiers] (
	[DossierId] INTEGER PRIMARY KEY NOT NULL,
	[Ziekte] TEXT NULL,
	[Geslacht] TEXT NULL,
	[Leeftijd] INTEGER NULL,
	[Resultaat] TEXT NULL,
	[Behandeling] TEXT NULL,
	[Aangemaakt] TEXT NOT NULL
);

-- Aparte tables voor klachten en medicatie zodat deze opgeslagen kunnen worden in een array

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

-- Users table om gebruikers in onze eigen db op te slaan zonder auth0

CREATE TABLE [Users] (
	[UserId] TEXT PRIMARY KEY,
	[Naam] TEXT NOT NULL,
	[Email] TEXT NOT NULL,
	[ProfielFoto] TEXT NOT NULL,
	[StoredDossier] INTEGER NULL
);