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

/* error codes */
#define	PC_OPERATION_SUCCESS		((int)0)
#define PC_ERR_FILE_OPERATION		-1
#define PC_ERR_MEM_OPERATION		-2
#define PC_ERR_NOT_PERMITTED		-3
#define PC_ERR_INVALID_PARAM		-4
#define PC_ERR_INVALID_OPERATION	-5

typedef enum {
       APP_TYPE_WGT,
       APP_TYPE_OSP,
       APP_TYPE_OTHER,
} app_type_t;

/* APIs - used by applications */
int control_privilege(void) __attribute__((deprecated));

int set_privilege(const char* pkg_name) __attribute__((deprecated));

/**
 * Set DAC and SMACK privileges for application.
 * This function is meant to be call by the application launcher just before
 * it launches an application. It will setup DAC and SMACK privileges based
 * on app type and accesses.
 * It must be called with root privileges, which will be dropped in the function.
 *
 * @param name package name
 * @param type application type (currently distinguished types: "wgt" and other)
 * @param path file system path to the binary
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int set_app_privilege(const char* name, const char* type, const char* path);

/**
 * For a UNIX socket endpoint determine the other side's app_id.
 *
 * @param sockfd socket file descriptor
 * @return id of the connecting widget on success, NULL on failure.
 * Caller is responsible for freeing the return widget id.
 */
char* app_id_from_socket(int sockfd);

/**
 * Inform about installation of a new app.
 * It is intended to be called during app installation.
 * It will create an empty SMACK rules file used by other functions operating
 * on permissions. It is needed for tracking lifetime of an app.
 * It must be called by privileged user, befor using any other app_* function.
 *
 *
 * @param app_id application identifier
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int app_install(const char* app_id);

/**
 * Inform about deinstallation of an app.
 * It will remove the SMACK rules file, enabling future installation of app
 * with the same identifier. It is needed for tracking lifetime of an app.
 * You should call app_revoke_permissions() before this function.
 * It must be called by privileged user.
 *
 *
 * @param app_id application identifier
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int app_uninstall(const char* app_id);

/**
 * Grant SMACK permissions based on permissions list.
 * It is intended to be called during app installation.
 * It will construct SMACK rules based on permissions list, grant them
 * and store it in a file, so they will be automatically granted on
 * system boot.
 * It must be called by privileged user.
 * THIS FUNCTION IS NOW DEPRECATED. app_enable_permissions() SHOULD BE USED INSTEAD.
 *
 *
 * @param app_id application identifier
 * @param perm_list array of permission names, last element must be NULL
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int app_add_permissions(const char* app_id, const char** perm_list)  __attribute__((deprecated));

/**
 * Grant temporary SMACK permissions based on permissions list.
 * It will construct SMACK rules based on permissions list, grant them,
 * but not store it anywhere, so they won't be granted again on system boot.
 * It must be called by privileged user.
 * THIS FUNCTION IS NOW DEPRECATED. app_enable_permissions() SHOULD BE USED INSTEAD.
 *
 *
 * @param app_id application identifier
 * @param perm_list array of permission names, last element must be NULL
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int app_add_volatile_permissions(const char* app_id, const char** perm_list)  __attribute__((deprecated));

/**
 * Grant SMACK permissions based on permissions list.
 * It is intended to be called during app installation.
 * It will construct SMACK rules based on permissions list, grant them
 * and store it in a file, so they will be automatically granted on
 * system boot, when persistent mode is enabled.
 * It must be called by privileged user.
 *
 *
 * @param app_id application identifier
 * @param app_type application type
 * @param perm_list array of permission names, last element must be NULL
 * @param persistent boolean for choosing between persistent and temporary rules
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int app_enable_permissions(const char* app_id, app_type_t app_type, const char** perm_list, bool persistent);

/**
 * Revoke SMACK permissions from an application.
 * This function should be called during app deinstallation.
 * It will revoke all SMACK rules previously granted by app_add_permissions().
 * It will also remove a rules file from disk.
 * It must be called by privileged user.
 *
 * @param app_id application identifier
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int app_revoke_permissions(const char* app_id);

/**
 * Reset SMACK permissions for an application by revoking all previously
 * granted rules and enabling them again from a rules file from disk.
 * It must be called by privileged user.
 *
 * @param app_id application identifier
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int app_reset_permissions(const char* app_id);

/**
 * Recursively set SMACK access labels for an application directory
 * and execute labels for executable files.
 * This function should be called once during app installation.
 * Results will be persistent on the file system.
 * It must be called by privileged user.
 *
 * @param app_label label name
 * @param path directory path
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int app_label_dir(const char* app_label, const char* path);

/**
 * Recursively set SMACK access and transmute labels for an application
 * directory and adds SMACK rule for application.
 * This function should be called once during app installation.
 * Results will be persistent on the file system.
 * It must be called by privileged user.
 *
 * @param app_label label name, used as subject for SMACK rule
 * @param shared_label, used as object for SMACK rule
 * @param path directory path
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int app_label_shared_dir(const char* app_label, const char* shared_label,
						 const char* path);



/**
 * Add SMACK rx rules for application identifiers to shared_label.
 * This function should be called during app installation.
 * It must be called by privileged user.
 *
 * @param shared_label label of the shared resource
 * @param app_list list of application SMACK identifiers
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int add_shared_dir_readers(const char* shared_label, const char** app_list);

/**
 * Make two applications "friends", by giving them both full permissions on
 * each other.
 * Results will be persistent on the file system. Must be called after
 * app_add_permissions() has been called for each application.
 * It must be called by privileged user.
 *
 * @param app_id1 first application identifier
 * @param app_id2 second application identifier
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int app_add_friend(const char* app_id1, const char* app_id2);

/**
 * Modify SMACK rules to give access from (subject)customer_label to (object)
 * provider_label.
 * Note: This function will do nothing if subject has already rwxat access to
 * object. You can revoke this modyfication by calling app_rovoke_access.
 *
 * @param subject - label of client application
 * @param object  - label of provider application
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int app_give_access(const char* subject, const char* object, const char* permission);

/**
 * Revoke access granted by app_give_access. This function will not remove
 * accesses that were granted before app_give_access call.
 *
 * @param subject - label of client application
 * @param object  - label of provider application
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int app_revoke_access(const char* subject, const char* object);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _PRIVILEGE_CONTROL_H_
