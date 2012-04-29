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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>

#include <math.h>
#include <sys/time.h>

#include "privilege-control.h"

#define APP_GID	5000
#define APP_UID	5000
#define ADMIN_GROUP	6504
#define DEVELOPER_GID	5100
#define DEVELOPER_UID	5100

#define APP_USER_NAME	"app"
#define DEV_USER_NAME	"developer"

#define APP_HOME_DIR	"/opt/home/app"
#define DEV_HOME_DIR	"/opt/home/developer"

#define APP_GROUP_PATH	"/usr/share/privilege-control/app_group_list"
#define DEV_GROUP_PATH	"/usr/share/privilege-control/dev_group_list"

#ifdef USE_PRIVILEGE_CONTROL

typedef struct {
	char user_name[10];
	int uid;
	int gid;
	char home_dir[64];
	char group_list[64];
} new_user;

API int control_privilege(void)
{
	if(getuid() == APP_UID)	// current user is 'app'
		return PC_OPERATION_SUCCESS;

	if(set_privilege("org.tizen.") == PC_OPERATION_SUCCESS)
		return PC_OPERATION_SUCCESS;
	else
		return PC_ERR_NOT_PERMITTED;
}

API int set_privilege(const char* pkg_name)
{
	FILE* fp_group = NULL;	// /etc/group
	uid_t t_uid = -1;		// uid of current process
	gid_t *glist = NULL;	// group list
	gid_t temp_gid = -1;	// for group list
	char buf[10] = {0, };		// contents in group_list file
	int glist_cnt = 0;		// for group list
	int result;
	new_user usr;

	/*
	 * initialize user structure
	 */
	memset(usr.user_name, 0x00, 10);
	memset(usr.home_dir, 0x00, 64);
	memset(usr.group_list, 0x00, 64);
	usr.uid = -1;
	usr.gid = -1;

	t_uid = getuid();

	if(t_uid == 0)	// current user is 'root'
	{
		if(!strncmp(pkg_name, "developer", 9))
		{
			strncpy(usr.user_name, DEV_USER_NAME, strlen(DEV_USER_NAME));
			usr.uid = DEVELOPER_UID;
			usr.gid = DEVELOPER_GID;
			strncpy(usr.home_dir, DEV_HOME_DIR, strlen(DEV_HOME_DIR));
			strncpy(usr.group_list, DEV_GROUP_PATH, strlen(DEV_GROUP_PATH));
		}
		else
		{
			strncpy(usr.user_name, APP_USER_NAME, strlen(APP_USER_NAME));
			usr.uid = APP_UID;
			usr.gid = APP_GID;
			strncpy(usr.home_dir, APP_HOME_DIR, strlen(APP_HOME_DIR));
			strncpy(usr.group_list, APP_GROUP_PATH, strlen(APP_GROUP_PATH));
		}

		/*
		 * get group information
		 */
		if(!(fp_group = fopen(usr.group_list, "r")))
		{
			fprintf(stderr, "[ERR] file open error: [%s]\n", usr.group_list);
			result = PC_ERR_FILE_OPERATION;	// return -1
			goto error;
		}

		while(fgets(buf, 10, fp_group) != NULL)
		{
			if(buf == NULL)
			{
				fprintf(stderr, "[ERR] Fail to get gid\n");
				result = PC_ERR_INVALID_OPERATION;
				goto error;
			}

			errno = 0;
			temp_gid = strtoul(buf, 0, 10);
			if(errno != 0)	// error occured during strtoul()
			{
				fprintf(stderr, "[ERR] cannot change string to integer: [%s]\n", buf);
				result = PC_ERR_INVALID_OPERATION;
				goto error;
			}

			glist = (gid_t*)realloc(glist, sizeof(gid_t) * (glist_cnt + 1));
			if(!glist)
			{
				result = PC_ERR_MEM_OPERATION;	// return -2
				goto error;
			}
			glist[glist_cnt] = temp_gid;
			glist_cnt++;
		}
		fclose(fp_group);
		fp_group = NULL;

		/*
		 * in case of dialer, add admin to glist
		 */
		if(!strncmp(pkg_name, "org.tizen.phone", 15))
		{
			glist = (gid_t*)realloc(glist, sizeof(gid_t) * (glist_cnt + 1));
			glist[glist_cnt] = ADMIN_GROUP;	// 6504
			glist_cnt++;
		}

		/*
		 * setgroups()
		 */
		if(setgroups(glist_cnt, glist) != 0)
		{
			fprintf(stderr, "[ERR] setgrouops fail\n");
			result = PC_ERR_NOT_PERMITTED;	// return -3
			goto error;
		}
		if(glist != NULL)
		{
			free(glist);
			glist = NULL;
		}

		/*
		 * setgid() & setgid()
		 */
		if(setgid(usr.gid) != 0)	// fail
		{
			fprintf(stderr, "[ERR] fail to execute setgid().\n");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}
		if(setuid(usr.uid) != 0)	// fail
		{
			fprintf(stderr, "[ERR] fail to execute setuid().\n");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}

		if(setenv("USER", usr.user_name, 1) != 0)	//fail
		{
			fprintf(stderr, "[ERR] fail to execute setenv().\n");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}
		if(setenv("HOME", usr.home_dir, 1) != 0)	// fail
		{
			fprintf(stderr, "[ERR] fail to execute setenv().\n");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}
	}
	else	// current user is not only 'root' but 'app'
	{
		fprintf(stderr, "[ERR] current user is NOT root\n");
		result = PC_ERR_NOT_PERMITTED;	// return -3
		goto error;
	}

	result = PC_OPERATION_SUCCESS;

error:
	if(glist != NULL)
		free(glist);

	return result;
}

#else // USE_PRIVILEGE_CONTROL

API int control_privilege(void)
{
	return 0;
}

API int set_privilege(const char* pkg_name)
{
	return 0;
}

#endif // USE_PRIVILEGE_CONTROL
