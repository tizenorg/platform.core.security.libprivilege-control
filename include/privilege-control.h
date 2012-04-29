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

/* added APIs - add & delete user and group for 3rd party applications */
int add_user_and_group(const char* pkg_name, const char* permissions);

int delete_user_and_group(const char* pkg_name);

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // _PRIVILEGE_CONTROL_H_
