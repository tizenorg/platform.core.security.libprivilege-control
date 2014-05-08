BEGIN EXCLUSIVE TRANSACTION;

--assume, that database is in version V3

--remove all path related tables, views, indexes, etc.

DROP TABLE IF EXISTS app_path;
DROP TABLE IF EXISTS app_path_type;
DROP TABLE IF EXISTS label_app_path_type_rule;
DROP TABLE IF EXISTS permission_app_path_type_rule;

DROP VIEW IF EXISTS permission_app_path_type_rule_view;
DROP VIEW IF EXISTS label_app_path_type_rule_view;
DROP VIEW IF EXISTS path_view;
DROP VIEW IF EXISTS path_removal_view;
DROP VIEW IF EXISTS ltl_permission_app_path_type_rule_view;
DROP VIEW IF EXISTS ltl_label_app_path_type_rule_view;
DROP VIEW IF EXISTS ltl_app_path_view;
DROP VIEW IF EXISTS ltl_app_path_reverse_view;

DROP INDEX IF EXISTS app_path_app_path_type_id_index;
DROP INDEX IF EXISTS permission_app_path_type_rule_app_path_type_id_index;

COMMIT TRANSACTION;
