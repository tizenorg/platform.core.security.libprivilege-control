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

-- APP PATH TYPES ----------------------------------------------------------------------------------
INSERT OR IGNORE INTO app_path_type(name) VALUES("GROUP_PATH");
INSERT OR IGNORE INTO app_path_type(name) VALUES("PUBLIC_PATH");
INSERT OR IGNORE INTO app_path_type(name) VALUES("SETTINGS_PATH");
INSERT OR IGNORE INTO app_path_type(name) VALUES("NPRUNTIME_PATH");

INSERT OR IGNORE INTO permission_view(name, type_name) VALUES
		("ALL_APPS", 	"ALL_APPS"),
		("WRT", 	"WRT"),
		("OSP", 	"OSP"),
		("EFL", 	"EFL");

-- PUBLIC FOLDERS ----------------------------------------------------------------------------------
-- PUBLIC_PATH
INSERT OR IGNORE INTO permission_app_path_type_rule_view(permission_name,
						permission_type_name,
						app_path_type_name,
						access,
						is_reverse) VALUES
	("ALL_APPS", "ALL_APPS", "PUBLIC_PATH", "rx", 0);

COMMIT TRANSACTION;

VACUUM;
