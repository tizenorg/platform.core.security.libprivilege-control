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
 * @file        rules-db-internals.h
 * @author      Jan Olszak (j.olszak@samsung.com)
 * @version     1.0
 * @brief       This file contains definition of rules database API.
 */

#include <sqlite3.h>
#include "rules-db.h"

#ifndef _RULES_DB_INTERNALS_H_
#define _RULES_DB_INTERNALS_H_

#define ACC_LEN 6

// Templates:
#define SMACK_APP_LABEL_TEMPLATE "~APP~"

// Open database flags:
#define RDB_READWRITE_FLAG SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_PRIVATECACHE
#define RDB_READONLY_FLAG SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_PRIVATECACHE

// Bind function defines:
#define RDB_FIRST_PARAM  1 /// Bind to the first parameter
#define RDB_SECOND_PARAM 2 /// Bind to the second parameter

#define RDB_AUTO_DETERM_SIZE -1 // Determine the size of the

// Getting values
#define RDB_FIRST_COLUMN  0
#define RDB_SECOND_COLUMN 1
#define RDB_THIRD_COLUMN  2
#define RDB_FOURTH_COLUMN 3

#define RDB_DISABLE 0
#define RDB_ENABLE  1

#define RDB_LOG_ENTRY_PARAM(format, ...) C_LOGD("RDB: Entering function %s. Args: " format, __func__, ##__VA_ARGS__)
#define RDB_LOG_ENTRY C_LOGD("RDB: Entering function %s", __func__)


/**
 * Add the label to the temporary table with modified labels.
 * We use this table to speed up generating modified smack rules.
 *
 * If label is not in this table, but rule changed
 * Smack will not get the rule in runtime.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db         pointer to a SQLite3 database object
 * @param  s_label_name label name
 * @return              PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_modified_label_internal(sqlite3 *p_db, const char *const s_label_name);


/**
 * Adds label names of applications with the permission to modified labels.
 * Used when permission is going to change and we're going to change some
 * accesses granted by this permission.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db            pointer to a SQLite3 database object
 * @param  i_permission_id id of the permission
 * @return                 PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_modified_permission_internal(sqlite3 *p_db, sqlite3_int64 i_permission_id);

/**
 * Adds label names of the application's folders to the modified labels.
 * Used during removing application.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db             pointer to a SQLite3 database object
 * @param  s_app_label_name label of the application
 * @return                  PC_OPERATION_SUCCESS on success,
 *                          error code otherwise
 */
int add_modified_apps_path_internal(sqlite3 *p_db, const char *const s_app_label_name);
/**
 * Open a connection with the database and perform an initialization.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db pointer to a SQLite3 database object
 * @return      PC_OPERATION_SUCCESS on success, error code otherwise
 */
int open_rdb_connection(sqlite3 **pp_db);


/**
 * Write variables into the query and create a SQLite statement.
 * One should use the SQLite3 format strings like '%Q'.
 *
 * For a lot of generic queries use binding.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db    pointer to a SQLite3 database object
 * @param  pp_stmt buffer for a pointer to the constructed statement
 * @return         PC_OPERATION_SUCCESS on success, error code otherwise
 */
int prepare_stmt(sqlite3 *p_db,
		 sqlite3_stmt **pp_stmt,
		 const char   *const s_sql,
		 ...);


/**
 * Check if the label is present in the database.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db         pointer to a SQLite3 database object
 * @param  s_label_name label's name
 * @return              PC_OPERATION_SUCCESS on success, error code otherwise
 */
int check_label_internal(sqlite3 *p_db,
			 const char  *const s_label_name);


/**
 * Check if the label is available for an application.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db         pointer to a SQLite3 database object
 * @param  s_label_name application's label name
 * @return              PC_OPERATION_SUCCESS when label free
 *                      PC_ERR_DB_LABEL_TAKEN when label taken
 *                      error code otherwise
 */
int check_app_label_internal(sqlite3 *p_db,
			     const char  *const s_label_name);


/**
 * Check if permission with a given name and type is available
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  s_permission_name      permission name
 * @param  s_permission_type_name permission type name
 * @return                        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int check_permission_internal(sqlite3 *p_db,
			      const char *const s_permission_name,
			      const char *const s_permission_type_name);


/**
 * Adds the application to the database.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db         pointer to a SQLite3 database object
 * @param  s_label_name application's label name
 * @return              PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_app_internal(sqlite3 *p_db,
		     const char  *const s_label_name);


/**
 * Removes the application from the database together with its permissions and paths.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db         pointer to a SQLite3 database object
 * @param  s_label_name application's label name
 * @return              PC_OPERATION_SUCCESS on success, error code otherwise
 */
int remove_app_internal(sqlite3 *p_db,
			const char   *const s_label_name);


/**
 * Add a path to the database
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db               pointer to a SQLite3 database object
 * @param  s_owner_label_name label name of the paths owner
 * @param  s_path_label_name  path's label name
 * @param  s_path             the path
 * @param  access             access rights
 * @param  s_type             path's type name
 * @return                    PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_path_internal(sqlite3 *p_db,
		      const char *const s_owner_label_name,
		      const char *const s_path_label_name,
		      const char *const s_path,
		      const char *const s_access,
		      const char *const s_type);


/**
 * Add a permission with a given name and of a give type
 * and return its internal permission id.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  s_permission_name      permission name
 * @param  s_permission_type_name permission type name
 * @return                        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_permission_internal(sqlite3 *p_db,
			    const char *const s_permission_name,
			    const char *const s_permission_type_name);

/**
 * Gets the id of the permission
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  s_permission_name      permission name
 * @param  s_permission_type_name permission type name
 * @param  p_permission_id        buffer for the id of the new permission
 * @return                        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int get_permission_id_internal(sqlite3 *p_db,
			       const char *const s_permission_name,
			       const char *const s_permission_type_name,
			       sqlite3_int64 *p_permission_id);

/**
 * Adds a list of smack permissions to the database.
 * s_permision_name has to appear either in the subject or the object of the rule.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db            pointer to a SQLite3 database object
 * @param  i_permission_id permission id for which we ad permission rules
 * @param  pp_smack_rules  a list of smack rules, that we want to apply. Not empty!
 * @return                 PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_permission_rules_internal(sqlite3 *p_db,
				  sqlite3_int64 i_permission_id,
				  const char  *const *const pp_smack_rules);



/**
 * Gets the internal app id of an application with a given name.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db             pointer to a SQLite3 database object
 * @param  pi_app_id        pointer to where the app is should be returned
 * @param  s_app_label_name label name of the application
 * @return                  PC_OPERATION_SUCCESS on success, error code otherwise
 */
int get_app_id_internal(sqlite3 *p_db,
			int *pi_app_id,
			const char *const s_app_label_name);


/**
 * Divides the rule into subject, object and access strings.
 *
 * @ingroup RDB internal functions
 *
 * @param  s_rule    the string that we parse
 * @param  s_subject buffer for the subject
 * @param  s_object  buffer for the object
 * @param  s_access  buffer for the access
 * @return           PC_OPERATION_SUCCESS on success, error code otherwise
 */
int parse_rule(const char *const s_rule,
	       char s_subject[],
	       char s_object[],
	       char s_access[]);


/**
 * Add a new permission to an application.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  i_app_id               application id
 * @param  s_permission_name      permission name
 * @param  s_permission_type_name permission type name
 * @param  b_is_volatile_new      is the permission volatile
 * @param  b_is_enabled_new       is the permission enabled
 * @return                        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int add_app_permission_internal(sqlite3 *p_db,
				int i_app_id,
				const char *const s_permission_name,
				const char *const s_permission_type_name,
				const bool b_is_volatile_new,
				const bool b_is_enabled_new);


/**
 * Enable or disable a permission for a given application.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  i_app_id               application id
 * @param  s_permission_name      permission name
 * @param  s_permission_type_name permission type name
 * @param  b_is_enabled_new       is the permission enabled
 * @return                        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int switch_app_permission_internal(sqlite3 *p_db,
				   const int i_app_id,
				   const char *const s_permission_name,
				   const char *const s_permission_type_name,
				   const bool b_is_enabled_new);


/**
 * Update an existing permission of an application.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db              pointer to a SQLite3 database object
 * @param  i_app_id          application id
 * @param  i_permission_id   id of the permission
 * @param  b_is_volatile_new is the permission volatile
 * @param  b_is_enabled_new  is the permission enabled
 * @return                   PC_OPERATION_SUCCESS on success, error code otherwise
 */
int update_app_permission_internal(sqlite3 *p_db,
				   const int i_app_id,
				   const int i_permission_id,
				   const bool b_is_volatile_new,
				   const bool b_is_enabled_new);


/**
 * Change a permission for an application.
 * Function modifies or adds a permission.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db                   pointer to a SQLite3 database object
 * @param  i_app_id               application id
 * @param  s_permission_name      permission name
 * @param  s_permission_type_name permission type name
 * @param  i_is_volatile_new      is the permission volatile
 * @param  i_is_enabled_new       is the permission enabled
 * @return                        PC_OPERATION_SUCCESS on success, error code otherwise
 */
int change_app_permission_internal(sqlite3 *p_db,
				   int i_app_id,
				   const char *const s_permission_name,
				   const char *const s_permission_type_name,
				   int i_is_volatile_new,
				   int i_is_enabled_new);


/**
 * Delete all permissions of the application.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db             pointer to a SQLite3 database object
 * @param  s_app_label_name applications label name
 * @return                  PC_OPERATION_SUCCESS on success, error code otherwise
 */
int revoke_app_permissions_internal(sqlite3 *p_db,
				    const char *const s_app_label_name);


/**
 * Delete all volatile permissions of the application.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db             pointer to a SQLite3 database object
 * @param  s_app_label_name applications label name
 * @return                  PC_OPERATION_SUCCESS on success, error code otherwise
 */
int reset_app_permissions_internal(sqlite3 *p_db,
				   const char *const s_app_label_name);


/**
 * Saves present smack rules in a temporary table: history_smack_rule
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db pointer to a SQLite3 database object
 * @return      PC_OPERATION_SUCCESS on success, error code otherwise
 */
int save_smack_rules(sqlite3 *p_db);


/**
 * Updates smack rules. Only rules that change are refreshed.
 *
 * @ingroup RDB internal functions
 *
 * @param  p_db pointer to a SQLite3 database object
 * @return      PC_OPERATION_SUCCESS on success, error code otherwise
 */
int update_smack_rules(sqlite3 *p_db);


#endif // _RULES_DB_INTERNALS_H_