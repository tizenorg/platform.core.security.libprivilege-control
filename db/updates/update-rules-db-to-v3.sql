--smaple file for future work
BEGIN EXCLUSIVE TRANSACTION;

--assume, that database is in version V2
--place your queries to update the database schema to V3 here



PRAGMA user_version = 3;

COMMIT TRANSACTION;
