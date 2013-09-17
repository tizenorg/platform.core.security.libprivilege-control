/*
 * libprivilege control, rules database
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Jan Olszak <j.olszak@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
* @file        rules-db-internals.c
* @author      Jan Olszak (j.olszak@samsung.com)
* @version     1.0
* @brief       Definition of internal functions of the rules-db API.
*/

#include <errno.h>      // For error logging
#include <stdarg.h>     // For handling multiple arguments
#include <stdlib.h>     // For free
#include <stdio.h>      // For file manipulation
#include "common.h"     // For smack_label_is_valid
#include <unistd.h>     // For sleep

#include "rules-db-internals.h"
#include "rules-db.h"

#define RDB_MAX_QUERY_ATTEMPTS    50
#define RDB_TIME_BETWEEN_ATTEMPTS 1 // sec




/**
 * Helper function. Use on INSERT or DELETE or UPDATE, when not interested in returned value
 *
 * @ingroup RDB: internal functions
 *
 * @param  p_stmt SQLite3 statement
 * @return        PC_OPERATION_SUCCESS on success, error code otherwise
 */
static int step_and_convert_returned_value(sqlite3_stmt *p_stmt)
{
	if(sqlite3_step(p_stmt) == SQLITE_DONE) {
		return PC_OPERATION_SUCCESS;
	} else {
		C_LOGE("RDB: Error during stepping: %s",
		       sqlite3_errmsg(sqlite3_db_handle(p_stmt)));
		return PC_ERR_DB_QUERY_STEP;
	}
}

int add_modified_label_internal(sqlite3 *p_db, const char *const s_label_name)
{
	int ret = PC_OPERATION_SUCCESS;
	sqlite3_stmt *p_stmt = NULL;
	ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT OR IGNORE INTO modified_label(name) VALUES(%Q)",
			   s_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int add_modified_permission_internal(sqlite3 *p_db, sqlite3_int64 i_permission_id)
{
	int ret = PC_OPERATION_SUCCESS;
	sqlite3_stmt *p_stmt = NULL;
	ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT OR IGNORE INTO modified_label(name) \
			    SELECT app_permission_view.app_name        \
			    FROM   app_permission_view                 \
			    WHERE  app_permission_view.permission_id = %d",
			   i_permission_id);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int add_modified_apps_path_internal(sqlite3 *p_db,
				    const char *const s_app_label_name)
{
	int ret = PC_OPERATION_SUCCESS;
	sqlite3_stmt *p_stmt = NULL;
	ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT OR IGNORE INTO modified_label(name) \
			    SELECT path_view.path_label_name           \
			    FROM   path_view                           \
			    WHERE  path_view.owner_app_label_name = %Q",
			   s_app_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}

/**
 * Function called when the target database is busy.
 * We attempt to access the database every
 * RDB_TIME_BETWEEN_ATTEMPTS seconds
 *
 * @param  not_used  not used
 * @param  i_attempt number of the attempt
 * @return           0 when stops waiting
 *                   1 when waiting
 */
static int database_busy_handler(void *not_used UNUSED,
				 int i_attempt)
{
	if(i_attempt > RDB_MAX_QUERY_ATTEMPTS) {
		// I ain't gonna wait for you forever!
		C_LOGE("RDB: Database busy for too long.");
		return 0;
	}
	C_LOGW("RDB: Database busy, waiting");
	sleep(RDB_TIME_BETWEEN_ATTEMPTS);
	return 1;
}


int open_rdb_connection(sqlite3 **p_db)
{
	RDB_LOG_ENTRY;

	char *p_err_msg;

	// Open connection:
	int ret = sqlite3_open_v2(RDB_PATH,
				  p_db,
				  RDB_READWRITE_FLAG,
				  NULL);
	if(*p_db == NULL) {
		C_LOGE("RDB: Error opening the database: Unable to allocate memory.");
		return PC_ERR_DB_CONNECTION;
	}
	if(ret != SQLITE_OK) {
		C_LOGE("RDB: Error opening the database: %s", sqlite3_errmsg(*p_db));
		return PC_ERR_DB_CONNECTION;
	}

	//Register busy handler:
	if(sqlite3_busy_handler(*p_db, database_busy_handler, NULL) != SQLITE_OK) {
		C_LOGE("RDB: Error opening the database: %s", sqlite3_errmsg(*p_db));
		return PC_ERR_DB_CONNECTION;
	}

	// Load extensions:
	if(sqlite3_enable_load_extension(*p_db, 1)) {
		C_LOGE("RDB: Error enabling extensions: %s", sqlite3_errmsg(*p_db));
		return PC_ERR_DB_CONNECTION;
	}

	if(sqlite3_load_extension(*p_db,
				  "/usr/lib/librules-db-sql-udf.so", 0,
				  &p_err_msg) != SQLITE_OK) {

		C_LOGE("RDB: Error during loading librules-db-sql-udf.so: %s",
		       p_err_msg);
		sqlite3_free(p_err_msg);
		return PC_ERR_DB_CONNECTION;
	}
	sqlite3_free(p_err_msg);


	// Create the temporary tables:
	if(sqlite3_exec(*p_db,
			"PRAGMA foreign_keys = ON;                                 \
			CREATE TEMPORARY TABLE history_smack_rule(                 \
			        subject VARCHAR NOT NULL,                          \
			        object  VARCHAR NOT NULL,                          \
			        access  INTEGER NOT NULL);                         \
			                                                           \
			CREATE TEMPORARY TABLE modified_label(                     \
			        name VARCHAR NOT NULL,                             \
			        UNIQUE(name));                                     \
			                                                           \
			CREATE TEMPORARY TABLE all_smack_binary_rule_modified(     \
			        subject VARCHAR NOT NULL,                          \
				object  VARCHAR NOT NULL,                          \
				access  INTEGER NOT NULL);                         \
			                                                           \
			CREATE TEMPORARY TABLE history_smack_rule_modified(        \
			        subject VARCHAR NOT NULL,                          \
			        object  VARCHAR NOT NULL,                          \
			        access  INTEGER NOT NULL);                         \
			                                                           \
                        CREATE TEMPORARY VIEW modified_smack_rules AS              \
			SELECT 	subject, object,                                   \
				access_to_str(access_add) AS access_add,           \
				access_to_str(access_del) AS access_del            \
			FROM 	(                                                  \
				SELECT 	   subject, object,                        \
				           s1.access & ~s2.access AS access_add,   \
				           s2.access & ~s1.access AS access_del    \
				FROM       all_smack_binary_rule_modified AS s1    \
				INNER JOIN history_smack_rule_modified AS s2       \
				           USING (subject, object)                 \
				WHERE      s1.access != s2.access                  \
				UNION                                              \
				SELECT     subject, object,                        \
				           s1.access AS access_add,                \
				           0 AS access_del                         \
				FROM       all_smack_binary_rule_modified s1       \
				LEFT JOIN  history_smack_rule_modified s2          \
				           USING (subject, object)                 \
				WHERE      s2.subject IS NULL AND                  \
				           s2.object  IS NULL                      \
				UNION                                              \
				SELECT     subject, object,                        \
				           0 AS access_add,                        \
				           s1.access AS access_del                 \
				FROM       history_smack_rule_modified s1          \
				LEFT JOIN  all_smack_binary_rule_modified s2       \
				           USING (subject, object)                 \
				WHERE      s2.subject IS NULL AND                  \
				           s2.object  IS NULL                      \
				)                                                  \
			ORDER BY subject, object ASC;                              \
			ANALYZE;",
			0, 0, 0) != SQLITE_OK) {
		C_LOGE("RDB: Error during preparing script: %s", sqlite3_errmsg(*p_db));
		return PC_ERR_DB_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}


int prepare_stmt(sqlite3 *p_db,
		 sqlite3_stmt **pp_stmt,
		 const char *const s_sql,
		 ...)
{
	int ret = PC_ERR_DB_QUERY_PREP;
	char *s_query = NULL;
	va_list args;
	va_start(args, s_sql);

	s_query = sqlite3_vmprintf(s_sql, args);

	if(s_query == NULL) {
		C_LOGE("RDB: Error during preparing statement: Unable to allocate enough memory.");
		ret = PC_ERR_DB_QUERY_PREP;
		goto finish;
	}

	if(sqlite3_prepare_v2(p_db,
			      s_query,
			      strlen(s_query) + 1,
			      pp_stmt,
			      NULL)) {
		C_LOGE("RDB: Error during preparing statement: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_PREP;
		goto finish;
	}

	if(*pp_stmt == NULL) {
		C_LOGE("RDB: Error during preparing statement: SQL statement is probably empty.");
		ret = PC_ERR_DB_QUERY_PREP;
		goto finish;
	}

	ret = PC_OPERATION_SUCCESS;

finish:
	va_end(args);
	sqlite3_free(s_query);
	return ret;
}


int check_app_label_internal(sqlite3 *p_db,
			     const char *const s_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT COUNT(application_view.name) \
			   FROM application_view                \
			   WHERE application_view.name=%Q       \
			   LIMIT 1",
			   s_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = sqlite3_step(p_stmt);
	if(ret == SQLITE_ROW) {
		switch(sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN)) {
		case 0: ret = PC_OPERATION_SUCCESS; break;
		case 1: ret = PC_ERR_DB_LABEL_TAKEN; break;
		}

	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int check_label_internal(sqlite3 *p_db,
			 const char *const s_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT COUNT(label.name) \
			   FROM label WHERE name=%Q LIMIT 1",
			   s_label_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = sqlite3_step(p_stmt);
	if(ret == SQLITE_ROW) {
		switch(sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN)) {
		case 0: ret = PC_OPERATION_SUCCESS; break;
		case 1: ret = PC_ERR_DB_LABEL_TAKEN; break;
		}

	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int add_app_internal(sqlite3 *p_db,
		     const char *const s_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT into application_view(name) VALUES(%Q)",
			   s_label_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int remove_app_internal(sqlite3 *p_db,
			const char *const s_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "DELETE FROM application_view \
			     WHERE application_view.name=%Q",
			   s_label_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int add_path_internal(sqlite3 *p_db,
		      const char *const s_owner_label_name,
		      const char *const s_path_label_name,
		      const char *const s_path,
		      const char *const s_access,
		      const char *const s_type)
{
	RDB_LOG_ENTRY_PARAM("%s %s %s %s %s",
			    s_owner_label_name, s_path_label_name,
			    s_path, s_access, s_type);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT INTO path_view(owner_app_label_name, \
			    			  path,                 \
			    			  path_label_name,      \
			    			  access,               \
			    			  path_type_name)       \
			     VALUES(%Q, %Q, %Q,  %Q, %Q);",
			   s_owner_label_name, s_path,
			   s_path_label_name, s_access, s_type);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int check_permission_internal(sqlite3 *p_db,
			      const char *const s_permission_name,
			      const char *const s_permission_type_name)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_permission_name, s_permission_type_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT COUNT(SELECT permission_view.permission_id \
			                 FROM   permission_view               \
			                 WHERE  name=%Q AND                   \
			                        type_name=%Q                  \
			                 LIMIT 1)",
			   s_permission_name, s_permission_type_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = sqlite3_step(p_stmt);
	if(ret == SQLITE_ROW) {
		switch(sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN)) {
		case 0: ret = PC_OPERATION_SUCCESS; break;  // No such permission
		case 1: ret = PC_PERMISSION_EXISTS; break;  // Permission exists
		}

	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int add_permission_internal(sqlite3 *p_db,
			    const char *const s_permission_name,
			    const char *const s_permission_type_name)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_permission_name, s_permission_type_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT INTO permission_view(name, type_name) \
			   VALUES (%Q,%Q)",
			   s_permission_name, s_permission_type_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int get_permission_id_internal(sqlite3 *p_db,
			       const char *const s_permission_name,
			       const char *const s_permission_type_name,
			       sqlite3_int64 *p_permission_id)
{
	RDB_LOG_ENTRY_PARAM("%s %s", s_permission_name, s_permission_type_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT permission_view.permission_id  \
			    FROM   permission_view                \
			    WHERE  permission_view.name = %Q AND  \
				   permission_view.type_name = %Q \
			    LIMIT  1",
			   s_permission_name, s_permission_type_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = sqlite3_step(p_stmt);
	if(ret == SQLITE_ROW) {
		ret = PC_OPERATION_SUCCESS;
		*p_permission_id = sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN);
	} else if(ret == SQLITE_DONE) {
		C_LOGW("RDB: There is no permission_id for %s %s", s_permission_name, s_permission_type_name);
		ret = PC_ERR_DB_OPERATION;

	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));

	return ret;
}


int parse_rule(const char *const s_rule,
	       char s_subject[],
	       char s_object[],
	       char s_access[])
{
	int ret = PC_OPERATION_SUCCESS;
	char *tmp_s_rule = NULL;
	const char *tmp_s_subject = NULL;
	const char *tmp_s_object = NULL;
	const char *tmp_s_access = NULL;
	char *saveptr = NULL;

	// Parse subject, object and access:
	tmp_s_rule = strdup(s_rule);
	tmp_s_subject = strtok_r(tmp_s_rule, " \t\n", &saveptr);
	tmp_s_object = strtok_r(NULL, " \t\n", &saveptr);
	tmp_s_access = strtok_r(NULL, " \t\n", &saveptr);

	// Check rule validity:
	if(tmp_s_subject == NULL ||
	    tmp_s_object == NULL ||
	    tmp_s_access == NULL ||
	    strtok_r(NULL, " \t\n", &saveptr) != NULL) {
		C_LOGE("RDB: Incorrect rule format: %s", s_rule);
		ret = PC_ERR_INVALID_PARAM;
		goto finish;
	}

	// Copy rules
	strcpy(s_subject, tmp_s_subject);
	strcpy(s_object, tmp_s_object);
	strcpy(s_access, tmp_s_access);
finish:
	if(tmp_s_rule) free(tmp_s_rule);
	return ret;
}


int add_permission_rules_internal(sqlite3 *p_db,
				  sqlite3_int64 permission_id,
				  const char *const *const pp_smack_rules)
{
	RDB_LOG_ENTRY;

	int i;
	int ret = PC_OPERATION_SUCCESS;
	sqlite3_stmt *p_stmt = NULL;
	char s_subject[SMACK_LABEL_LEN + 1];
	char s_object[SMACK_LABEL_LEN + 1];
	char s_access[ACC_LEN + 1];

	// Prepare statement.
	const char *s_query = "INSERT INTO \
		permission_label_rule_view(permission_id,access,label_name,is_reverse) \
		VALUES(?,?,?,?)";
	if(sqlite3_prepare_v2(p_db,
			      s_query,
			      strlen(s_query) + 1,
			      &p_stmt,
			      NULL)) {
		C_LOGE("RDB: Error during preparing statement: %s",
		       sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_PREP;
		goto finish;
	}

	for(i = 0; pp_smack_rules[i] != NULL ; ++i) {
		C_LOGD("RDB: Granting permission: %s", pp_smack_rules[i]);

		// Ignore empty lines
		if(strspn(pp_smack_rules[i], " \t\n") == strlen(pp_smack_rules[i]))
			continue;

		ret = parse_rule(pp_smack_rules[i], s_subject, s_object, s_access);
		if(ret != PC_OPERATION_SUCCESS) goto finish;

		// Bind values to the statement and run it:
		sqlite3_bind_int(p_stmt, 1, permission_id);
		sqlite3_bind_text(p_stmt, 2, s_access, RDB_AUTO_DETERM_SIZE, 0);
		if(!strcmp(s_subject, SMACK_APP_LABEL_TEMPLATE)) {
			// Not reversed
			sqlite3_bind_text(p_stmt, 3, s_object, RDB_AUTO_DETERM_SIZE, 0);
			sqlite3_bind_int(p_stmt, 4, 0);

		} else if(!strcmp(s_object, SMACK_APP_LABEL_TEMPLATE)) {
			sqlite3_bind_text(p_stmt, 3, s_subject, RDB_AUTO_DETERM_SIZE, 0);
			sqlite3_bind_int(p_stmt, 4, 1);

		} else {
			C_LOGE("RDB: Incorrect rule format: %s", pp_smack_rules[i]);
			ret = PC_ERR_INVALID_PARAM;
			goto finish;
		}

		// Perform the insert
		ret = step_and_convert_returned_value(p_stmt);
		if(ret != PC_OPERATION_SUCCESS) goto finish;

		// Reset and unbind statement:
		if(sqlite3_reset(p_stmt) != SQLITE_OK) {
			C_LOGE("RDB: Error reseting statement: %s",
			       sqlite3_errmsg(p_db));
			ret = PC_ERR_DB_QUERY_STEP;
			goto finish;
		}
		if(sqlite3_clear_bindings(p_stmt) != SQLITE_OK) {
			C_LOGE("RDB: Error reseting statement: %s",
			       sqlite3_errmsg(p_db));
			ret = PC_ERR_DB_QUERY_STEP;
			goto finish;
		}
	}

finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int get_app_id_internal(sqlite3 *p_db,
			int *pi_app_id,
			const char *const s_app_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_app_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT application_view.app_id \
			     FROM application_view \
			     WHERE application_view.name = %Q",
			   s_app_label_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = sqlite3_step(p_stmt);
	if(ret == SQLITE_ROW) {
		ret = PC_OPERATION_SUCCESS;
		*pi_app_id = sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN);

	} else if(ret == SQLITE_DONE) {
		C_LOGW("RDB: There is no app_id for %s", s_app_label_name);
		ret = PC_ERR_DB_OPERATION;

	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int add_app_permission_internal(sqlite3 *p_db,
				int i_app_id,
				const char *const s_permission_name,
				const char *const s_permission_type_name,
				const bool b_is_volatile_new,
				const bool b_is_enabled_new)
{
	RDB_LOG_ENTRY_PARAM("%d %s %s %d %d", i_app_id,
			    s_permission_name, s_permission_type_name,
			    b_is_volatile_new, b_is_enabled_new);


	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "INSERT INTO                                  \
			    app_permission_view(app_id, name, type_name, \
			    is_volatile, is_enabled)                     \
			    VALUES(%d,%Q,%Q,%d,%d)",
			   i_app_id, s_permission_name, s_permission_type_name,
			   (int)b_is_volatile_new, (int)b_is_enabled_new);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int switch_app_permission_internal(sqlite3 *p_db,
				   const int i_app_id,
				   const char *const s_permission_name,
				   const char *const s_permission_type_name,
				   const bool b_is_enabled_new)
{
	RDB_LOG_ENTRY_PARAM("%d %s %s %d", i_app_id,
			    s_permission_name, s_permission_type_name,
			    b_is_enabled_new);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "UPDATE app_permission_view \
			    SET    is_enabled=%d       \
			    WHERE  app_id = %d  AND    \
			           name =%Q AND        \
			           type_name=%Q",
			   b_is_enabled_new, i_app_id,
			   s_permission_name, s_permission_type_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;
	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int update_app_permission_internal(sqlite3 *p_db,
				   const int i_app_id,
				   const int i_permission_id,
				   const bool b_is_volatile_new,
				   const bool b_is_enabled_new)
{
	RDB_LOG_ENTRY_PARAM("%d %d %d %d",
			    i_app_id, i_permission_id,
			    b_is_volatile_new, b_is_enabled_new);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "UPDATE app_permission \
			     SET is_volatile = %d, is_enabled=%d \
			     WHERE app_id = %d AND permission_id = %d",
			   b_is_volatile_new, b_is_enabled_new,
			   i_app_id, i_permission_id);

	if(ret != PC_OPERATION_SUCCESS) goto finish;
	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int change_app_permission_internal(sqlite3 *p_db,
				   int i_app_id,
				   const char *const s_permission_name,
				   const char *const s_permission_type_name,
				   int i_is_volatile_new,
				   int i_is_enabled_new)
{
	RDB_LOG_ENTRY_PARAM("%d %d %d %d %d", i_app_id,
			    s_permission_name, s_permission_type_name,
			    i_is_volatile_new, i_is_enabled_new);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;
	int i_is_volatile_old, i_is_enabled_old, i_permission_id;

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT is_volatile, is_enabled, permission_id      \
			     FROM    app_permission_list_view                   \
			     WHERE   app_id = %d AND                            \
			     permission_name=%Q AND                             \
			     permission_type_name=%Q LIMIT 1",
			   i_app_id, s_permission_name, s_permission_type_name);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = sqlite3_step(p_stmt);
	if(ret == SQLITE_ROW) {
		// Phi, I already have this permission...
		i_is_volatile_old = sqlite3_column_int(p_stmt, RDB_FIRST_COLUMN);
		i_is_enabled_old = sqlite3_column_int(p_stmt, RDB_SECOND_COLUMN);

		if(i_is_volatile_old == 1 && i_is_volatile_new == 0) {
			// Confucius say, No man can down-cast volatility.
			C_LOGE("RDB: Down-casting volatility is forbidden.");
			ret = PC_ERR_DB_PERM_FORBIDDEN;
			goto finish;
		}

		if(i_is_volatile_old == i_is_volatile_new &&
		    i_is_enabled_old == i_is_enabled_new) {
			// There is no change. Nice.
			C_LOGD("RDB: Permission %s %s already exists.", s_permission_name, s_permission_type_name);
			ret = PC_OPERATION_SUCCESS;
			goto finish;
		}

		i_permission_id = sqlite3_column_int(p_stmt, RDB_THIRD_COLUMN);

		// Finalize statement
		if(sqlite3_finalize(p_stmt) < 0)
			C_LOGE("RDB: Error during finalizing statement: %s",
			       sqlite3_errmsg(p_db));
		p_stmt = NULL;

		C_LOGD("RDB: Updating permission %s %s to application.", s_permission_name, s_permission_type_name);
		ret = update_app_permission_internal(p_db,
						     i_app_id,
						     i_permission_id,
						     i_is_volatile_new,
						     i_is_enabled_new);

	} else if(ret == SQLITE_DONE) {
		// Wow! A brand new permission! Omnomnom...

		if(sqlite3_finalize(p_stmt) < 0)
			C_LOGE("RDB: Error during finalizing statement: %s",
			       sqlite3_errmsg(p_db));
		p_stmt = NULL;

		C_LOGD("RDB: Adding permission %s %s to application.", s_permission_name, s_permission_type_name);
		ret = add_app_permission_internal(p_db,
						  i_app_id,
						  s_permission_name,
						  s_permission_type_name,
						  i_is_volatile_new,
						  i_is_enabled_new);
	} else {
		C_LOGE("RDB: Error during stepping: %s", sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_QUERY_STEP;
	}

finish:
	if(p_stmt && sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int revoke_app_permissions_internal(sqlite3 *p_db,
				    const char *const s_app_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_app_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "DELETE FROM app_permission_view \
			    WHERE app_permission_view.app_name=%Q;",
			   s_app_label_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int reset_app_permissions_internal(sqlite3 *p_db,
				   const char *const s_app_label_name)
{
	RDB_LOG_ENTRY_PARAM("%s", s_app_label_name);

	int ret = PC_ERR_DB_OPERATION;
	sqlite3_stmt *p_stmt = NULL;

	ret = prepare_stmt(p_db, &p_stmt,
			   "DELETE FROM app_permission_volatile_view \
			     WHERE app_permission_volatile_view.app_name=%Q;",
			   s_app_label_name);

	if(ret != PC_OPERATION_SUCCESS) goto finish;

	ret = step_and_convert_returned_value(p_stmt);
finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));
	return ret;
}


int save_smack_rules(sqlite3 *p_db)
{
	RDB_LOG_ENTRY;

	if(sqlite3_exec(p_db,
			"DELETE FROM history_smack_rule;                     \
			                                                     \
			INSERT INTO history_smack_rule 			     \
			SELECT subject, object, access                       \
			FROM all_smack_binary_rules;                         \
			                                                     \
			CREATE INDEX history_smack_rule_subject_object_index \
			ON history_smack_rule(subject, object);",
			0, 0, 0) != SQLITE_OK) {
		C_LOGE("RDB: Error during saving history table: %s",
		       sqlite3_errmsg(p_db));
		return PC_ERR_DB_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}


static int update_rules_in_db(sqlite3 *p_db)
{
	RDB_LOG_ENTRY;

	// All rules generated by the present state of the database
	if(sqlite3_exec(p_db,
			"DELETE FROM all_smack_binary_rules; 	    \
			                                            \
			INSERT INTO all_smack_binary_rules          \
			SELECT subject, object, access, is_volatile \
			FROM all_smack_binary_rules_view;           \
			                                            \
			DELETE FROM all_smack_binary_rule_modified; \
			                                            \
			INSERT INTO all_smack_binary_rule_modified  \
			SELECT subject, object, access              \
			FROM   all_smack_binary_rules,              \
			       modified_label                       \
			WHERE  subject IN modified_label OR         \
			       object IN modified_label;            \
			                                            \
			DELETE FROM history_smack_rule_modified;    \
			                                            \
			INSERT INTO history_smack_rule_modified     \
			SELECT subject, object, access              \
			FROM   history_smack_rule,                  \
			       modified_label                       \
			WHERE  subject IN modified_label OR         \
			       object IN modified_label;            \
			",
			0, 0, 0) != SQLITE_OK) {
		C_LOGE("RDB: Error during updating rules: %s",
		       sqlite3_errmsg(p_db));
		return PC_ERR_DB_OPERATION;
	}
	return PC_OPERATION_SUCCESS;
}

int update_smack_rules(sqlite3 *p_db)
{
	RDB_LOG_ENTRY;

	int ret = PC_OPERATION_SUCCESS;
	sqlite3_stmt *p_stmt = NULL;
	const unsigned char *s_subject    = NULL;
	const unsigned char *s_object     = NULL;
	const unsigned char *s_access_add = NULL;
	const unsigned char *s_access_del = NULL;
	struct smack_accesses *smack = NULL;

	ret = update_rules_in_db(p_db);
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	if(smack_accesses_new(&smack)) {
		C_LOGE("RDB: Error during updating smack rules: smack_accesses_new failed.");
		ret = PC_ERR_MEM_OPERATION;
		goto finish;
	}

	ret = prepare_stmt(p_db, &p_stmt,
			   "SELECT * from modified_smack_rules;");
	if(ret != PC_OPERATION_SUCCESS) goto finish;

	while((ret = sqlite3_step(p_stmt)) == SQLITE_ROW) {
		s_subject    = sqlite3_column_text(p_stmt, RDB_FIRST_COLUMN);
		s_object     = sqlite3_column_text(p_stmt, RDB_SECOND_COLUMN);
		s_access_add = sqlite3_column_text(p_stmt, RDB_THIRD_COLUMN);
		s_access_del = sqlite3_column_text(p_stmt, RDB_FOURTH_COLUMN);

		C_LOGD("RDB: Added rule to smack:: %s %s %s %s",
		       s_subject, s_object, s_access_add, s_access_del);

		if(smack_accesses_add_modify(smack,
					     (const char *) s_subject,
					     (const char *) s_object,
					     (const char *) s_access_add,
					     (const char *) s_access_del)) {
			C_LOGE("RDB: Error during updating smack rules: %s",
			       sqlite3_errmsg(p_db));
			ret = PC_ERR_INVALID_OPERATION;
			goto finish;
		}
	}
	if(ret == SQLITE_DONE) {
		ret = PC_OPERATION_SUCCESS;
	} else {
		C_LOGE("RDB: Error during updating smack rules [%d]: %s",
		       ret, sqlite3_errmsg(p_db));
		ret = PC_ERR_DB_OPERATION;
	}

	if(smack_accesses_apply(smack)) {
		C_LOGE("RDB: Error in smack_accesses_apply");
		ret = PC_ERR_INVALID_OPERATION;
	}

finish:
	if(sqlite3_finalize(p_stmt) < 0)
		C_LOGE("RDB: Error during finalizing statement: %s",
		       sqlite3_errmsg(p_db));

	smack_accesses_free(smack);
	return ret;
}