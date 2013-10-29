-- !!! CAUTION !!!
-- 1. Beware of updating schema!
--    We can drop views and triggers,
--    but we should copy data from tables
--    according to the schema version!
-- 2. If you change definition of tables
--    update the schema counter at the bottom!!

-- TODO: Use "USING" in joins whenever possible

.load librules-db-sql-udf.so
PRAGMA foreign_keys = ON;
PRAGMA auto_vacuum = NONE;

BEGIN EXCLUSIVE TRANSACTION;

-- PRAGMA cache_size = 2000;

CREATE TABLE IF NOT EXISTS  app (
    app_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    label_id INTEGER NOT NULL,
    UNIQUE(label_id),

    FOREIGN KEY(label_id) REFERENCES label(label_id)
);
CREATE INDEX IF NOT EXISTS app_index ON app(app_id, label_id);


CREATE TABLE IF NOT EXISTS app_permission (
    app_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    is_volatile INTEGER NOT NULL  DEFAULT 0,
    is_enabled INTEGER NOT NULL  DEFAULT 1,

    PRIMARY KEY(app_id, permission_id),

    FOREIGN KEY(app_id) REFERENCES app(app_id),
    FOREIGN KEY(permission_id) REFERENCES permission(permission_id)
);

CREATE TABLE IF NOT EXISTS app_path (
    app_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    label_id INTEGER NOT NULL,
    access INTEGER NOT NULL,
    app_path_type_id INTEGER NOT NULL ,

    -- TODO:
    -- Desired behavior should be:
    -- allow one app to register a path only once (already implemented by the primary key)
    -- prohibit two apps registering the same path with different labels (probably cannot be done by SQL constraints)
    -- allow two apps to register the same path if label is also same

    PRIMARY KEY (app_id, path),

    FOREIGN KEY(app_id) REFERENCES app(app_id),
    FOREIGN KEY(label_id) REFERENCES label(label_id),
    FOREIGN KEY(app_path_type_id) REFERENCES app_path_type(app_path_type_id)
);

CREATE TABLE IF NOT EXISTS app_path_type (
    app_path_type_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL ,

    UNIQUE (name)
);
-- CREATE INDEX IF NOT EXISTS app_path_type_index ON app_path_type(app_path_type_id, name);


CREATE TABLE IF NOT EXISTS permission_permission_rule (
    permission_id INTEGER NOT NULL,
    target_permission_id INTEGER NOT NULL,
    access INTEGER NOT NULL DEFAULT 0,
    is_reverse INTEGER NOT NULL  DEFAULT 0,

    PRIMARY KEY (permission_id, target_permission_id, is_reverse),

    FOREIGN KEY(permission_id) REFERENCES permission(permission_id),
    FOREIGN KEY(target_permission_id) REFERENCES permission(permission_id)
);

CREATE TABLE IF NOT EXISTS permission_label_rule (
    permission_id INTEGER NOT NULL,
    label_id INTEGER NOT NULL,
    access INTEGER NOT NULL DEFAULT 0,
    is_reverse INTEGER NOT NULL  DEFAULT 0,

    PRIMARY KEY (permission_id,label_id, is_reverse),

    FOREIGN KEY(permission_id) REFERENCES permission(permission_id),
    FOREIGN KEY(label_id) REFERENCES label(label_id)
);

CREATE TABLE IF NOT EXISTS permission_app_path_type_rule (
    permission_id INTEGER NOT NULL,
    app_path_type_id INTEGER NOT NULL,
    access INTEGER NOT NULL DEFAULT 0,
    is_reverse INTEGER NOT NULL  DEFAULT 0,

    PRIMARY KEY (permission_id, app_path_type_id, is_reverse),

    FOREIGN KEY(permission_id) REFERENCES permission(permission_id),
    FOREIGN KEY(app_path_type_id) REFERENCES app_path_type(app_path_type_id)
);


CREATE TABLE IF NOT EXISTS label (
    label_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,

    UNIQUE(name)
);

CREATE TABLE IF NOT EXISTS permission_type (
    permission_type_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    type_name TEXT NOT NULL,

    UNIQUE(type_name)
);

CREATE TABLE IF NOT EXISTS permission (
    permission_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT ,
    permission_type_id INTEGER NOT NULL,
    name TEXT NOT NULL,

    UNIQUE (name, permission_type_id),

    FOREIGN KEY(permission_type_id) REFERENCES permission_type(permission_type_id)
);


CREATE TABLE IF NOT EXISTS all_smack_binary_rules(
    subject TEXT NOT NULL,
    object  TEXT NOT NULL,
    access  INTEGER NOT NULL,
    is_volatile INTEGER NOT NULL
);

-- TEMPORARY TABLES ------------------------------------------------------------
-- Definitions are repeated in code.

CREATE TEMPORARY TABLE history_smack_rule(
    subject TEXT NOT NULL,
    object  TEXT NOT NULL,
    access  INTEGER NOT NULL
);


CREATE TEMPORARY TABLE modified_label(
   name TEXT NOT NULL,
   UNIQUE (name)
);


CREATE TEMPORARY TABLE all_smack_binary_rules_modified(
    subject TEXT NOT NULL,
    object  TEXT NOT NULL,
    access  INTEGER NOT NULL
);


CREATE TEMPORARY TABLE history_smack_rule_modified(
    subject TEXT NOT NULL,
    object  TEXT NOT NULL,
    access  INTEGER NOT NULL
);


-- PERMISSION VIEW -------------------------------------------------------------
DROP VIEW IF EXISTS permission_view;
CREATE VIEW permission_view AS
SELECT      permission.permission_id, permission.name, permission_type.type_name
FROM        permission
INNER JOIN  permission_type USING(permission_type_id);

DROP TRIGGER IF EXISTS permission_view_insert_trigger;
CREATE TRIGGER permission_view_insert_trigger
INSTEAD OF INSERT ON permission_view
BEGIN
    -- Add the permission
    INSERT OR IGNORE INTO permission(name,permission_type_id)
    SELECT      NEW.name, permission_type.permission_type_id
    FROM        permission_type
    WHERE       permission_type.type_name = NEW.type_name;


    -- Delete the previous definition of the permission
    DELETE FROM permission_label_rule_view
    WHERE       permission_label_rule_view.permission_name = NEW.name AND
                permission_label_rule_view.permission_type_name = NEW.type_name;
END;

-- PERMISSION TO LABEL RULE VIEW -----------------------------------------------
DROP VIEW IF EXISTS permission_label_rule_view;
CREATE VIEW permission_label_rule_view AS
SELECT
        permission_view.permission_id       AS permission_id,
        permission_view.name                AS permission_name,
        permission_view.type_name           AS permission_type_name,
        label.name                              AS label_name,
        permission_label_rule.access            AS access,
        permission_label_rule.is_reverse        AS is_reverse
FROM    permission_label_rule
LEFT JOIN permission_view USING(permission_id)
LEFT JOIN label USING(label_id);


-- Preferred way of adding permission rules would be to use these ONE, multi-row
-- insert statement, with one check of a condition
-- that there is such permission id. It's impossible to make those inserts in C,
-- so the programmer has to secure, that there is a permission with a given id.
-- (Check it and insert in the same transaction)
-- In runtime we accept ONLY inserts with label.
-- All other kinds of permissions are filled during the database creation.
DROP TRIGGER IF EXISTS permission_label_rule_view_insert_trigger;
CREATE TRIGGER permission_label_rule_view_insert_trigger
INSTEAD OF INSERT ON permission_label_rule_view
BEGIN
    -- Adding api features adds a label it it's not present.
    INSERT OR IGNORE INTO label(name) VALUES (NEW.label_name);

    INSERT OR REPLACE INTO permission_label_rule(permission_id,
                                                 label_id,
                                                 access,
                                                 is_reverse)
    SELECT      NEW.permission_id,
                label.label_id,
                str_to_access(NEW.access),
                NEW.is_reverse
    FROM        label
    WHERE       label.name = NEW.label_name;
END;


-- TODO: Potential problem - undeleted labels.
DROP TRIGGER IF EXISTS permission_label_rule_view_delete_trigger;
CREATE TRIGGER permission_label_rule_view_delete_trigger
INSTEAD OF DELETE ON permission_label_rule_view
BEGIN
        DELETE FROM permission_label_rule
        WHERE   permission_label_rule.permission_id
                IN (SELECT permission_view.permission_id
                    FROM   permission_view
                    WHERE  permission_view.name = OLD.permission_name AND
                           permission_view.type_name = OLD.permission_type_name);
END;


-- PERMISSION TO APP PATH TYPE RULE VIEW ---------------------------------------
DROP VIEW IF EXISTS permission_app_path_type_rule_view;
CREATE VIEW permission_app_path_type_rule_view AS
SELECT
        permission_view.permission_id       AS permission_id,
        permission_view.name                AS permission_name,
        permission_view.type_name           AS permission_type_name,
        app_path_type.name                      AS app_path_type_name,
        permission_app_path_type_rule.access       AS access,
        permission_app_path_type_rule.is_reverse   AS is_reverse
FROM    permission_app_path_type_rule
LEFT JOIN permission_view USING(permission_id)
LEFT JOIN app_path_type USING(app_path_type_id);


DROP TRIGGER IF EXISTS permission_app_path_type_rule_view_insert_trigger;
CREATE TRIGGER permission_app_path_type_rule_view_insert_trigger
INSTEAD OF INSERT
ON permission_app_path_type_rule_view
WHEN NEW.permission_id IS NULL
BEGIN
    INSERT INTO permission_app_path_type_rule(permission_id,
                                              app_path_type_id,
                                              access,
                                              is_reverse)
    SELECT      permission_view.permission_id,
                app_path_type.app_path_type_id,
                str_to_access(NEW.access),
                NEW.is_reverse
    FROM        permission_view, app_path_type
    WHERE       permission_view.name = NEW.permission_name AND
                permission_view.type_name = NEW.permission_type_name AND
                app_path_type.name = NEW.app_path_type_name;
END;

DROP TRIGGER IF EXISTS permission_app_path_type_rule_view_delete_trigger;
CREATE TRIGGER permission_app_path_type_rule_view_delete_trigger
INSTEAD OF DELETE
ON permission_app_path_type_rule_view
BEGIN
    -- Delete the rule
    DELETE FROM permission_app_path_type_rule
    WHERE       permission_app_path_type_rule.permission_id
                IN (SELECT permission_view.permission_id
                    FROM   permission_view
                    WHERE  permission_view.name = OLD.permission_name AND
                           permission_view.type_name = OLD.permission_type_name);
END;


CREATE TRIGGER permission_app_path_type_id_rule_view_insert_trigger
INSTEAD OF INSERT
ON permission_app_path_type_rule_view
WHEN NEW.permission_id IS NOT NULL
BEGIN
    INSERT OR REPLACE INTO permission_app_path_type_rule(permission_id,
                                                         app_path_type_id,
                                                         access,
                                                         is_reverse)
    SELECT      NEW.permission_id,
                app_path_type.app_path_type_id,
                str_to_access(NEW.access),
                NEW.is_reverse
    FROM        app_path_type
    WHERE       app_path_type.name = NEW.app_path_type_name;
END;


-- PERMISSION TO PERMISSION RULE VIEW ------------------------------------------
DROP VIEW IF EXISTS permission_permission_rule_view;
CREATE VIEW permission_permission_rule_view AS
SELECT
        tmp_permission_view.permission_id       AS permission_id,
        tmp_permission_view.name                AS permission_name,
        tmp_permission_view.type_name           AS permission_type_name,
        tmp_target_permission_view.name         AS target_permission_name,
        tmp_target_permission_view.type_name    AS target_permission_type_name,
        permission_permission_rule.access       AS access,
        permission_permission_rule.is_reverse   AS is_reverse
FROM    permission_permission_rule
LEFT JOIN permission_view AS tmp_permission_view USING(permission_id)
LEFT JOIN permission_view AS tmp_target_permission_view
ON permission_permission_rule.target_permission_id = tmp_target_permission_view.permission_id;


-- Trigger for manual addition of rules.
DROP TRIGGER IF EXISTS permission_permission_rule_view_insert_trigger;
CREATE TRIGGER  permission_permission_rule_view_insert_trigger
INSTEAD OF INSERT ON  permission_permission_rule_view
BEGIN

    INSERT OR REPLACE INTO permission_permission_rule(permission_id,
                                                      target_permission_id,
                                                      access,
                                                      is_reverse)
    SELECT  tmp_permission_view.permission_id,
            tmp_target_permission_view.permission_id,
            str_to_access(NEW.access),
            NEW.is_reverse
    FROM    permission_view AS tmp_permission_view,
            permission_view AS tmp_target_permission_view
    WHERE   tmp_permission_view.name = NEW.permission_name AND
            tmp_permission_view.type_name = NEW.permission_type_name AND
            tmp_target_permission_view.name = NEW.target_permission_name AND
            tmp_target_permission_view.type_name = NEW.target_permission_type_name;
END;


DROP TRIGGER IF EXISTS permission_permission_rule_view_delete_trigger;
CREATE TRIGGER  permission_permission_rule_view_delete_trigger
INSTEAD OF DELETE ON  permission_permission_rule_view
BEGIN
    -- Delete the rule
    DELETE FROM permission_permission_rule_view
    WHERE       permission_permission_rule_view.permission_id
                IN (SELECT permission_view.permission_id
                    FROM   permission_view
                    WHERE  permission_view.name = OLD.permission_name AND
                           permission_view.type_name = OLD.permission_type_name);
END;



-- LABEL VIEW ------------------------------------------------------------------
-- There are no INSTEAD OF triggers on regular tables.
-- We use a view to delete unreferenced labels:
DROP VIEW IF EXISTS label_view;
CREATE VIEW label_view AS SELECT * FROM label;

DROP TRIGGER IF EXISTS label_view_delete_trigger;
CREATE TRIGGER label_view_delete_trigger
INSTEAD OF DELETE ON label_view
WHEN    OLD.label_id NOT IN (SELECT app.label_id
                             FROM app) AND
        OLD.label_id NOT IN (SELECT permission_label_rule.label_id
                             FROM permission_label_rule) AND
        OLD.label_id NOT IN (SELECT app_path.label_id
                             FROM app_path)
BEGIN
        DELETE FROM label WHERE label.name = OLD.name;
END;


-- APPLICATION VIEW ------------------------------------------------------------
DROP VIEW IF EXISTS application_view;
CREATE VIEW application_view AS
SELECT      app.app_id, label.name
FROM        label
INNER JOIN  app USING(label_id);

DROP TRIGGER IF EXISTS application_view_insert_trigger;
CREATE TRIGGER application_view_insert_trigger
INSTEAD OF INSERT ON application_view
BEGIN
    -- The app's label could have been added by the permission.
    INSERT OR IGNORE INTO label(name) VALUES (NEW.name);

    -- Add application:
    INSERT INTO app(label_id)
    SELECT label_id
    FROM   label
    WHERE  label.name = NEW.name;

    -- Add the permission granted to all applications
    INSERT INTO app_permission_view(app_id, name, type_name, is_volatile, is_enabled)
    VALUES (last_insert_rowid(), "ALL_APPS", "ALL_APPS", 0, 1);

END;


DROP TRIGGER IF EXISTS application_view_delete_trigger;
CREATE TRIGGER application_view_delete_trigger
INSTEAD OF DELETE ON application_view
BEGIN
        -- Delete rules that correspond to app's paths:
        DELETE FROM permission_label_rule
        WHERE       permission_label_rule.label_id IN
                   (SELECT     app_path.label_id
                    FROM       app_path
                    INNER JOIN application_view USING(app_id)
                    WHERE      application_view.name = OLD.name);

        -- Delete path
        DELETE FROM path_view
        WHERE path_view.owner_app_label_name=OLD.name;

        -- Delete apps permissions:
        DELETE FROM app_permission
        WHERE       app_permission.app_id
                    IN (SELECT application_view.app_id
                        FROM   application_view
                        WHERE  application_view.name = OLD.name
                        LIMIT  1);

        -- Delete application
        DELETE FROM app
        WHERE app.app_id IN (SELECT application_view.app_id
                             FROM   application_view
                             WHERE  application_view.name = OLD.name
                             LIMIT  1);

        -- Delete label
        DELETE FROM label_view
        WHERE label_view.name = OLD.name;
END;


-- PATH VIEW -------------------------------------------------------------------
DROP VIEW IF EXISTS path_view;
CREATE VIEW path_view AS
SELECT  application_view.name   AS owner_app_label_name,
        app_path.path           AS path,
        label.name              AS path_label_name,
        app_path.access         AS access,
        app_path_type.name      AS path_type_name

FROM    app_path
LEFT JOIN app_path_type     USING (app_path_type_id)
LEFT JOIN application_view  USING (app_id)
LEFT JOIN label             USING (label_id);


-- For an existing application we add a path.
DROP TRIGGER IF EXISTS path_view_insert_trigger;
CREATE TRIGGER path_view_insert_trigger
INSTEAD OF INSERT ON path_view
WHEN NEW.owner_app_label_name IN (SELECT application_view.name
                                  FROM application_view)
BEGIN
    -- The path's label could have been added by the permission.
    INSERT OR IGNORE INTO label(name) VALUES (NEW.path_label_name);

    -- Add the path
    INSERT INTO app_path(app_id, path, label_id, access, app_path_type_id)
    SELECT  application_view.app_id,
            NEW.path,
            label.label_id,
            str_to_access(NEW.access),
            app_path_type.app_path_type_id
    FROM    application_view, app_path_type, label
    WHERE   application_view.name = NEW.owner_app_label_name AND
            app_path_type.name = NEW.path_type_name AND
            label.name = NEW.path_label_name;
END;

DROP TRIGGER IF EXISTS path_view_delete_trigger;
CREATE TRIGGER path_view_delete_trigger
INSTEAD OF DELETE ON path_view
BEGIN
        -- Delete the path
        DELETE FROM app_path
        WHERE app_path.app_id IN (SELECT  app.app_id
                                  FROM    app, label
                                  WHERE   label.name = OLD.owner_app_label_name AND
                                          app.label_id = label.label_id);

        -- Delete the path's label if it's not used any more
        DELETE FROM label_view WHERE label_view.name = OLD.path_label_name;
END;

-- APP PERMISSION LIST VIEW ----------------------------------------------------
-- Used in check_app_permission_internal to check if permissions are present
-- TODO: Check if SQLite optimizer doesn't change app_permission_view to the same code.
DROP VIEW IF EXISTS app_permission_list_view;
CREATE VIEW app_permission_list_view AS
SELECT      app_permission.app_id AS app_id,
            app_permission.permission_id AS permission_id,
            permission_view.name AS permission_name,
            permission_view.type_name AS permission_type_name,
            app_permission.is_volatile AS is_volatile,
            app_permission.is_enabled AS is_enabled
FROM        app_permission
INNER JOIN  permission_view USING(permission_id);




-- APP PERMISSION VIEW ---------------------------------------------------------
DROP VIEW IF EXISTS app_permission_view;
CREATE VIEW app_permission_view AS
SELECT      application_view.app_id,
            application_view.name  AS app_name,
            permission_view.permission_id,
            permission_view.name,
            permission_view.type_name,
            app_permission.is_volatile,
            app_permission.is_enabled
FROM        app_permission
INNER JOIN  application_view USING(app_id)
INNER JOIN  permission_view USING(permission_id);


DROP TRIGGER IF EXISTS app_permission_view_insert_trigger;
CREATE TRIGGER app_permission_view_insert_trigger
INSTEAD OF INSERT ON app_permission_view
BEGIN
    INSERT INTO app_permission(app_id, permission_id, is_volatile, is_enabled)
    SELECT      NEW.app_id,
                permission_view.permission_id,
                NEW.is_volatile,
                NEW.is_enabled
    FROM        permission_view
    WHERE       permission_view.name = NEW.name AND
                permission_view.type_name = NEW.type_name;
END;




-- It's forbidden do change permission from not volatile to volatile.
-- We have to check it before inserting anything.
-- Used in updating permissions
DROP TRIGGER IF EXISTS app_permission_view_update_trigger;
CREATE TRIGGER app_permission_view_update_trigger
INSTEAD OF UPDATE ON app_permission_view
BEGIN
    UPDATE OR IGNORE app_permission
    SET              is_enabled = NEW.is_enabled
    WHERE            app_permission.app_id = OLD.app_id AND
                     app_permission.permission_id
                     IN (SELECT  permission_view.permission_id
                         FROM    permission_view
                         WHERE   permission_view.name = OLD.name AND
                                 permission_view.type_name = OLD.type_name
                         LIMIT 1);
END;


DROP TRIGGER IF EXISTS app_permission_view_delete_trigger;
CREATE TRIGGER app_permission_view_delete_trigger
INSTEAD OF DELETE ON app_permission_view
BEGIN
    DELETE FROM app_permission
    WHERE       app_permission.app_id
                IN (SELECT application_view.app_id
                    FROM   application_view
                    WHERE  application_view.name = OLD.app_name
                    LIMIT  1)
                AND
                app_permission.permission_id NOT IN (SELECT permission_view.permission_id
                                                     FROM   permission_view
                                                     WHERE  permission_view.name = "ALL_APPS" AND
                                                            permission_view.type_name = "ALL_APPS");
    -- Delete paths
    DELETE FROM path_view
    WHERE path_view.owner_app_label_name=OLD.app_name;

END;

-- APP PERMISSION VOLATILE VIEW ------------------------------------------------
DROP VIEW IF EXISTS app_permission_volatile_view;
CREATE VIEW app_permission_volatile_view AS
SELECT      *
FROM        app_permission_view
WHERE       app_permission_view.is_volatile = 1;


DROP TRIGGER IF EXISTS app_permission_volatile_view_delete_trigger;
CREATE TRIGGER app_permission_volatile_view_delete_trigger
INSTEAD OF DELETE ON app_permission_volatile_view
BEGIN
    DELETE FROM app_permission
    WHERE       app_permission.is_volatile = 1 AND
                app_permission.app_id
                IN (SELECT application_view.app_id
                    FROM   application_view
                    WHERE  application_view.name = OLD.app_name
                    LIMIT  1);
END;


-- APPLICATIONS PERMISSIONS ID -------------------------------------------------
-- All applications and their permissions
DROP VIEW IF EXISTS app_label_with_permission_view;
CREATE VIEW app_label_with_permission_view AS
SELECT      app_permission.permission_id,
            application_view.name,
            application_view.app_id,
            app_permission.is_volatile
FROM        app_permission
INNER JOIN  application_view USING(app_id)
WHERE       app_permission.is_enabled = 1;



-- PERMISSION TO PERMISSION RULE VIEW ------------------------------------------
-- ltl = label to label
DROP VIEW IF EXISTS ltl_permission_permission_rule_view;
CREATE VIEW ltl_permission_permission_rule_view AS
SELECT      (CASE WHEN is_reverse = 0 THEN app1.name ELSE app2.name END) AS subject,
            (CASE WHEN is_reverse = 1 THEN app1.name ELSE app2.name END) AS object,
            p.access,
            app1.is_volatile OR app2.is_volatile AS is_volatile
FROM        permission_permission_rule AS p
INNER JOIN  app_label_with_permission_view AS app1 USING(permission_id)
INNER JOIN  app_label_with_permission_view AS app2
            ON app2.permission_id = p.target_permission_id
WHERE       app1.app_id != app2.app_id;

-- PERMISSION TO LABEL RULE VIEW -----------------------------------------------
-- ltl = label to label
DROP VIEW IF EXISTS ltl_permission_label_rule_view;
CREATE VIEW ltl_permission_label_rule_view AS
SELECT      (CASE WHEN is_reverse = 0 THEN app.name ELSE label.name END) AS subject,
            (CASE WHEN is_reverse = 1 THEN app.name ELSE label.name END) AS object,
            p.access,
            app.is_volatile
FROM        permission_label_rule AS p
INNER JOIN  app_label_with_permission_view AS app USING(permission_id)
INNER JOIN  label USING(label_id)
WHERE       app.name != label.name;



-- PERMISSION TO PATH TYPE RULE VIEW -------------------------------------------
-- ltl = label to label
DROP VIEW IF EXISTS ltl_permission_app_path_type_rule_view;
CREATE VIEW ltl_permission_app_path_type_rule_view AS
SELECT      (CASE WHEN is_reverse = 0 THEN app.name ELSE label.name END) AS subject,
            (CASE WHEN is_reverse = 1 THEN app.name ELSE label.name END) AS object,
            p.access,
            app.is_volatile
FROM        permission_app_path_type_rule AS p
INNER JOIN  app_label_with_permission_view AS app USING(permission_id)
INNER JOIN  app_path USING(app_path_type_id)
INNER JOIN  label USING(label_id)
WHERE       app.name != label.name;


-- PERMISSION TO APPLICATION'S OWN PATHS ---------------------------------------
-- ltl = label to label
DROP VIEW IF EXISTS ltl_app_path_view;
CREATE VIEW ltl_app_path_view AS
SELECT      application_view.name   AS subject,
            label.name              AS object,
            app_path.access         AS access
FROM        app_path
INNER JOIN  application_view USING(app_id)
INNER JOIN  label USING(label_id);


-- SMACK RULES VIEWS -----------------------------------------------------------
DROP VIEW IF EXISTS all_smack_binary_rules_view;
CREATE VIEW all_smack_binary_rules_view AS
SELECT  subject,
        object,
        bitwise_or(access) AS access,
        MIN(is_volatile) AS is_volatile
FROM   (SELECT subject, object, access, is_volatile
        FROM   ltl_permission_permission_rule_view
        UNION ALL
        SELECT subject, object, access, is_volatile
        FROM   ltl_permission_label_rule_view
        UNION ALL
        SELECT subject, object, access, is_volatile
        FROM   ltl_permission_app_path_type_rule_view
        UNION ALL
        SELECT subject, object, access, 0
        FROM   ltl_app_path_view
       )
GROUP BY subject, object
ORDER BY subject, object ASC;

-- ALL INSERTED DATA VIEW ------------------------------------------------------
-- This view is used to clear the database from inserted rules.
-- We loose all information about installed applications
-- and folders.
DROP VIEW IF EXISTS all_inserted_data;
CREATE VIEW all_inserted_data AS
SELECT      *
FROM        label;

DROP TRIGGER IF EXISTS all_inserted_data_delete_trigger;
CREATE TRIGGER all_inserted_data_delete_trigger INSTEAD OF
DELETE ON all_inserted_data
BEGIN
    DELETE FROM permission_label_rule;
    DELETE FROM permission_permission_rule;
    DELETE FROM permission_app_path_type_rule;

    DELETE FROM app_permission;

    DELETE FROM permission;
    DELETE FROM permission_type;

    DELETE FROM app_path;
    DELETE FROM app_path_type;
    DELETE FROM app;

    DELETE FROM label;
END;



-- SMACK RULES MODIFICATIONS VIEW ----------------------------------------------
-- This definition is repeated during opening a connection with the database.
-- Used to get all smack rules, even volatile.
-- Ensure it's the same!
CREATE TEMPORARY VIEW modified_smack_rules AS
SELECT  subject, object,
        access_to_str(access_add) AS access_add,
        access_to_str(access_del) AS access_del
FROM    (
        SELECT     subject, object,
                   s1.access & ~s2.access AS access_add,
                   s2.access & ~s1.access AS access_del
        FROM       all_smack_binary_rules AS s1
        INNER JOIN history_smack_rule AS s2
                   USING (subject, object)
        WHERE      s1.access != s2.access

        UNION

        SELECT     subject, object,
                   s1.access AS access_add,
                   0 AS access_del
        FROM       all_smack_binary_rules AS s1
        LEFT JOIN  history_smack_rule s2
                   USING (subject, object)
        WHERE      s2.subject IS NULL AND
                   s2.object  IS NULL

        UNION

        SELECT     subject, object,
                   0 AS access_add,
                   s1.access AS access_del
        FROM       history_smack_rule s1
        LEFT JOIN  all_smack_binary_rules AS s2
                   USING (subject, object)
        WHERE      s2.subject IS NULL AND
                   s2.object  IS NULL
        )
ORDER BY subject, object ASC;


-- Update here!
PRAGMA schema_version = 1;

COMMIT TRANSACTION;
