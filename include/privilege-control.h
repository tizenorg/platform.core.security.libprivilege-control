/*
 * libprivilege control
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Kidong Kim <kd0228.kim@samsung.com>
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

#include <stdbool.h>
#include <sys/types.h>

#ifndef _PRIVILEGE_CONTROL_H_
#define _PRIVILEGE_CONTROL_H_

/* Macros for converting preprocessor token to string */
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

#ifndef API
#define API __attribute__((visibility("default")))
#endif // API

#define DEPRECATED __attribute__((deprecated))
#define UNUSED __attribute__((unused))

/* error codes */
#define	PC_OPERATION_SUCCESS		((int)0)
#define PC_ERR_FILE_OPERATION		-1
#define PC_ERR_MEM_OPERATION		-2
#define PC_ERR_NOT_PERMITTED		-3
#define PC_ERR_INVALID_PARAM		-4
#define PC_ERR_INVALID_OPERATION	-5
#define PC_ERR_DB_OPERATION		-6

/// Label is taken by another application
#define PC_ERR_DB_LABEL_TAKEN           -7

/// Query fails during preparing a SQL statement
#define PC_ERR_DB_QUERY_PREP            -8

/// Query fails during binding to a SQL statement
#define PC_ERR_DB_QUERY_BIND            -9

/// Query fails during stepping a SQL statement
#define PC_ERR_DB_QUERY_STEP            -10

/// Unable to establish a connection with the database
#define PC_ERR_DB_CONNECTION            -11

/// There is no application with such app_id
#define PC_ERR_DB_NO_SUCH_APP           -12

/// There already exists a permission with this name and type
#define PC_ERR_DB_PERM_FORBIDDEN        -13


typedef enum {
       APP_TYPE_WGT,
       APP_TYPE_OSP,
       APP_TYPE_EFL,
       APP_TYPE_OTHER,
} app_type_t;

typedef enum {
        APP_PATH_PRIVATE,
        APP_PATH_GROUP_RW,
        APP_PATH_PUBLIC_RO,
        APP_PATH_SETTINGS_RW,
        APP_PATH_ANY_LABEL,
} app_path_type_t;

/* APIs - used by applications */

/**
 * Set DAC and SMACK privileges for application.
 * This function is meant to be call by the application launcher just before
 * it launches an application. It will setup DAC and SMACK privileges based
 * on app type and accesses.
 * It must be called with root privileges, which will be dropped in the function.
 *
 * @param name package name
 * @param type application type (currently distinguished types:
 *             "wgt",
 *             "tpk", "osp",
 *             "rpm", "efl")
 *
 * @param path file system path to the binary
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_set_privilege(const char* name, const char* type, const char* path);

/**
 * For a UNIX socket endpoint determine the other side's pkg_id. Caller is
 * responsible for freeing the return widget id.
 *
 * @param  sockfd  socket file descriptor
 * @return         id of the connecting widget on success, NULL on failure.
 */
char* perm_app_id_from_socket(int sockfd);

/**
 * Adds an application to the database if it doesn't already exist. It is needed
 * for tracking lifetime of an application. It must be called by privileged
 * user, before using any other perm_app_* function regarding that application.
 * It must be called within database transaction started with perm_begin() and
 * finished with perm_end(). It may be called more than once during installation.
 *
 * @param  pkg_id  application identifier
 * @return         PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_install(const char* pkg_id);

/**
 * Removes an application from the database with it's permissions, rules and
 * directories, enabling future installation of the application with the same
 * pkg_id. It is needed for tracking lifetime of an application. It must be
 * called by privileged user and within database transaction started with
 * perm_begin() and finished with perm_end().
 *
 * @param  pkg_id  application identifier
 * @return         PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_uninstall(const char* pkg_id);

/**
 * Grant SMACK permissions based on permissions list.
 * It is intended to be called during app installation.
 * It will construct SMACK rules based on permissions list, grant them
 * and store it in a database, so they will be automatically granted on
 * system boot, when persistent mode is enabled.
 * It must be called by privileged user.
 *
 * @param  pkg_id      application identifier
 * @param  app_type    application type
 * @param  perm_list   array of permission names, last element must be NULL
 * @param  persistent  boolean for choosing between persistent and temporary rules
 * @return             PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_enable_permissions(const char* pkg_id, app_type_t app_type, const char** perm_list, bool persistent);

/**
 * Removes previously granted SMACK permissions based on permissions list.
 * It will remove given permissions from an application, leaving other granted
 * permissions untouched. Results will be persistent.
 * It must be called by privileged user.
 *
 * @param  pkg_id     application identifier
 * @param  app_type   application type
 * @param  perm_list  array of permission names, last element must be NULL
 * @return            PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_disable_permissions(const char* pkg_id, app_type_t app_type, const char** perm_list);

/**
 * Removes all application's permissions, rules and directories registered in
 * the database. It must be called by privileged user.
 *
 * @param  pkg_id  application identifier
 * @return         PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_revoke_permissions(const char* pkg_id);

/**
 * Removes all application's permissions which are not persistent. It must be
 * called by privileged user.
 *
 * @param  pkg_id  application identifier
 * @return         PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_reset_permissions(const char* pkg_id);

/**
 * Sets SMACK labels for an application directory (recursively) or for an executable/symlink
 * file. The exact behavior depends on app_path_type argument:
 * 	- APP_PATH_PRIVATE: label with app's label, set access label on everything
 *    and execute label on executable files and symlinks to executable files
 *
 * 	- APP_PATH_GROUP_RW: label with given shared_label, set access label on
 * 	  everything and enable transmute on directories. Also give pkg_id full access
 * 	  to the shared label.
 *
 * 	- APP_PATH_PUBLIC_RO: label with autogenerated label, set access label on
 * 	  everything and enable transmute on directories. Give full access to the label to
 * 	  pkg_id and RX access to all other apps.
 *
 * 	- APP_PATH_SETTINGS_RW: label with autogenerated label, set access label on
 * 	  everything and enable transmute on directories. Give full access to the label to
 * 	  pkg_id and RWX access to all appsetting apps.
 *
 * This function should be called during app installation.
 * Results will be persistent on the file system.
 * It must be called by privileged user.
 *
 * @param  pkg_id         application identifier
 * @param  path           file or directory path
 * @param  app_path_type  application path type
 * @param  shared_label   optional argument for APP_PATH_GROUP_RW and
 *                        APP_PATH_ANY_LABEL path type; type is const char*
 * @return                PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_app_setup_path(const char* pkg_id, const char* path, app_path_type_t app_path_type, ...);

/**
 * Adds new feature to the database. It must be called by privileged user and
 * within database transaction started with perm_begin() and finished with
 * perm_end().
 *
 * @param  app_type          application type
 * @param  api_feature_name  name of newly added feature
 * @param  smack_rule_set    set of rules required by the feature - NULL terminated
 *                           list of NULL terminated rules.
 * @param  list_of_db_gids   list of gids required to access databases controlled
 *                           by the feature
 * @return                   PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_add_api_feature(app_type_t app_type,
			 const char* api_feature_name,
			 const char** set_smack_rule_set,
			 const gid_t* list_of_db_gids,
			 size_t list_size);

/**
 * Starts exclusive database transaction. Run before functions modifying
 * database.
 *
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_begin(void);

/**
 * Ends exclusive database transaction. Run after functions modifying database.
 * If an error occurred during the transaction then all modifications will be
 * rolled back.
 *
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int perm_end(void);

/**
* Run to rollback any privilege modification.
*
* @return PC_OPERATION_SUCCESS on success,
*         PC_ERR_* on error
*/
int perm_rollback(void);

/**
 * Get message connected to error code.
 *
 * @param errnum error code
 * @return string describing the error code
 */
const char* perm_strerror(int errnum);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _PRIVILEGE_CONTROL_H_
