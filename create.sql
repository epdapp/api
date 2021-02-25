CREATE TABLE [Dossiers] (
	[DossierId] INTEGER PRIMARY KEY NOT NULL,
	[Geslacht] INTEGER NULL,
	[Leeftijd] INTEGER NULL,
	[Resultaat] INTEGER NULL,
	[Behandeling] LONGTEXT NULL
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