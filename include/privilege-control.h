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

/* APIs for WRT */

/**
* Set DAC and SMACK privileges for web application.
* This is a specialized version of set_app_privilege() to be called by WRT
* when it is being launched from the console instead of AUL.
*
* @param widget_id widget identificator
* @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
*/
int wrt_set_privilege(const char* widget_id);

/**
 * Reset all SMACK permissions for a widget.
 * This function should be called when previously granted permissions
 * for a widget are no longer needed (e.g. after its termination or
 * deinstallation).
 * It must be called by privileged user.
 *
 * @param widget_id widget identifier from WRT
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int wrt_permissions_reset(const char* widget_id);

/**
 * Grant SMACK permissions required to use selected devcaps.
 * This function should be called during preparation for widget run
 * (after wrt_permissions_reset()) and whenever widget is supposed to
 * gain any new devcap permissions.
 * It must be called by privileged user.
 *
 * @param widget_id widget identifier from WRT
 * @param devcap_list array of devcap names, last element must be NULL
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int wrt_permissions_add(const char* widget_id, const char** devcap_list);

/**
 * Recursively set SMACK labels for a widget source directory.
 * This function should be called once during widget installation, after
 * widget's source is unpacked in it's destination directory.
 * Results will be persistent on the file system.
 * It must be called by privileged user.
 *
 * @param widget_id widget identifier from WRT
 * @param path parent directory path with widget's source
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int wrt_set_src_dir(const char* widget_id, const char *path);

/**
 * Recursively set SMACK labels for a widget data directory.
 * This function should be called once during widget installation, after
 * widget's initial data is unpacked in it's destination directory.
 * Results will be persistent on the file system.
 * It must be called by privileged user.
 *
 * @param widget_id widget identifier from WRT
 * @param path parent directory path with widget's data
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int wrt_set_data_dir(const char* widget_id, const char *path);

/**
 * For a UNIX socket endpoint determine if the other side is a widget
 * and return its widget id.
 * This function is deprecated due to unification of app labels.
 * Use app_id_from_socket() instead.
 *
 * @param sockfd socket file descriptor
 * @return id of the connecting widget on success, NULL on failure.
 * Caller is responsible for freeing the return widget id.
 */
char* wrt_widget_id_from_socket(int sockfd) __attribute__((deprecated));

/**
 * For a UNIX socket endpoint determine the other side's app_id.
 *
 * @param sockfd socket file descriptor
 * @return id of the connecting widget on success, NULL on failure.
 * Caller is responsible for freeing the return widget id.
 */
char* app_id_from_socket(int sockfd);

/**
 * Grant SMACK permissions based on permissions list.
 * It is intended to be called during app installation.
 * It will construct SMACK rules based on permissions list, grant them
 * and store it in a file, so they will be automatically granted on
 * system boot.
 * It must be called by privileged user.
 *
 *
 * @param app_id application identifier
 * @param perm_list array of permission names, last element must be NULL
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int app_add_permissions(const char* app_id, const char** perm_list);

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

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _PRIVILEGE_CONTROL_H_
