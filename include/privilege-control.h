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
int control_privilege(void);

int set_privilege(const char* pkg_name);

/**
 * Set process SMACK label from EXEC label of a file.
 * This function is emulating EXEC label behaviour of SMACK for programs
 * run by dlopen/dlsym instead of execv.
 *
 * @param path file path to take label from
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int set_exec_label(const char* path);

/* APIs for WRT */

/**
 * Reset all SMACK permissions for a widget.
 * This function should be called during preparation for widget run.
 * It would be a good idea to also call it after widget has terminated.
 * It must be called by privileged user.
 *
 * @param widget_id widget identifier from WRT
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int wrt_permissions_reset(unsigned long long widget_id);

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
int wrt_permissions_add(unsigned long long widget_id, const char** devcap_list);

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
int wrt_set_src_dir(unsigned long long widget_id, const char *path);

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
int wrt_set_data_dir(unsigned long long widget_id, const char *path);

/**
 * Assign SMACK label to a process and drop root permissions.
 * Also grant default SMACK permissions (not related to any devcaps).
 * This function should be called by before executing widget code.
 * It must be called by privileged user. After the function returns,
 * privileges will be dropped.
 *
 * @param widget_id widget identifier from WRT
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
int wrt_set_privilege(unsigned long long widget_id);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _PRIVILEGE_CONTROL_H_
