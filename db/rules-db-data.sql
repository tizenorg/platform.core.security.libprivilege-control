-- !!! CAUTION !!!
-- Beware of updating!
-- Remember that you might insert things to a filled database.

.load librules-db-sql-udf.so
PRAGMA foreign_keys = ON;

BEGIN TRANSACTION;

-- PERMISSION TYPES --------------------------------------------------------------------------------
INSERT OR IGNORE INTO permission_type(type_name) VALUES("ALL_APPS"); -- Automatically added to all apps.
INSERT OR IGNORE INTO permission_type(type_name) VALUES("WRT");
INSERT OR IGNORE INTO permission_type(type_name) VALUES("OSP");
INSERT OR IGNORE INTO permission_type(type_name) VALUES("EFL");
INSERT OR IGNORE INTO permission_type(type_name) VALUES("WRT_partner");
INSERT OR IGNORE INTO permission_type(type_name) VALUES("WRT_platform");
INSERT OR IGNORE INTO permission_type(type_name) VALUES("OSP_partner");
INSERT OR IGNORE INTO permission_type(type_name) VALUES("OSP_platform");

INSERT OR IGNORE INTO permission_view(name, type_name) VALUES
		("ALL_APPS", 	"ALL_APPS"),
		("WRT", 	"WRT"),
		("WRT_partner", "WRT_partner"),
		("WRT_platform","WRT_platform"),
		("OSP", 	"OSP"),
		("OSP_partner", "OSP_partner"),
		("OSP_platform","OSP_platform"),
		("EFL", 	"EFL");

COMMIT TRANSACTION;

VACUUM;
