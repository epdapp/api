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