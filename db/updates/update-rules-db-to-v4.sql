
BEGIN EXCLUSIVE TRANSACTION;

--assume, that database is in version V3
PRAGMA user_version = 4;

COMMIT TRANSACTION;
