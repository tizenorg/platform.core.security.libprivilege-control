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

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <fts.h>
#include <errno.h>
#include <math.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/smack.h>
#include <linux/capability.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <search.h>
#include <iri.h>

#include "privilege-control.h"
#include "access-db.h"
#include "common.h"

#define APP_GID	5000
#define APP_UID	5000
#define DEVELOPER_GID	5100
#define DEVELOPER_UID	5100

#define APP_USER_NAME	"app"
#define DEV_USER_NAME	"developer"

#define APP_HOME_DIR	TOSTRING(HOMEDIR) "/app"
#define DEV_HOME_DIR	TOSTRING(HOMEDIR) "/developer"

#define APP_GROUP_PATH	TOSTRING(SHAREDIR) "/app_group_list"
#define DEV_GROUP_PATH	TOSTRING(SHAREDIR) "/dev_group_list"

#define SMACK_SRC_FILE_SUFFIX   "_src_file"
#define SMACK_SRC_DIR_SUFFIX    "_src_dir"
#define SMACK_DATA_SUFFIX       "_data"
#define WRT_BASE_DEVCAP         "WRT"
#define WRT_CLIENT_PATH         "/usr/bin/wrt-client"
#define ACC_LEN                 6
#define TIZEN_PRIVILEGE_ANTIVIRUS  "http://tizen.org/privilege/antivirus"
#define TIZEN_PRIVILEGE_APPSETTING "http://tizen.org/privilege/appsetting"
#define PATH_RULES_PUBLIC_RO       "PATH_RULES_PUBLIC_RO.smack"
#define PATH_RULES_GROUP_RW        "PATH_RULES_GROUP_RW.smack"

typedef struct {
	char user_name[10];
	int uid;
	int gid;
	char home_dir[64];
	char group_list[64];
} new_user;

/**
 * Return values
 * <0 - error
 * 0 - skip
 * 1 - label
 */
typedef int (*label_decision_fn)(const FTSENT*);
enum {
	DECISION_SKIP = 0,
	DECISION_LABEL = 1
};

API int control_privilege(void)//deprecated
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	if(getuid() == APP_UID)	// current user is 'app'
		return PC_OPERATION_SUCCESS;

	if(perm_app_set_privilege("org.tizen.", NULL, NULL) == PC_OPERATION_SUCCESS)
		return PC_OPERATION_SUCCESS;
	else {
		C_LOGE("perm_app_set_privilege failed (not permitted).");
		return PC_ERR_NOT_PERMITTED;
	}
}

/**
 * TODO: this function should be moved to libsmack in open-source.
 */
API int get_smack_label_from_process(pid_t pid, char *smack_label)
{
	SECURE_C_LOGD("Entering function: %s. Params: pid=%i", __func__, pid);

	int ret;
	int fd AUTO_CLOSE;
	int PATH_MAX_LEN = 64;
	char path[PATH_MAX_LEN + 1];

	if (pid < 0) {
		C_LOGE("invalid param pid.");
		ret = PC_ERR_INVALID_PARAM;
		goto out;
	}

	if(smack_label == NULL) {
		C_LOGE("Invalid param smack_label (NULL).");
		ret = PC_ERR_INVALID_PARAM;
		goto out;
	}

	bzero(smack_label, SMACK_LABEL_LEN + 1);
	if (!have_smack()) { // If no smack just return success with empty label
		C_LOGD("No SMACK. Returning empty label");
		ret = PC_OPERATION_SUCCESS;
		goto out;
	}

	bzero(path, PATH_MAX_LEN + 1);
	snprintf(path, PATH_MAX_LEN, "/proc/%d/attr/current", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		SECURE_C_LOGE("Cannot open file %s (errno: %s)", path, strerror(errno));
		ret = PC_ERR_FILE_OPERATION;
		goto out;
	}

	ret = read(fd, smack_label, SMACK_LABEL_LEN);
	if (ret < 0) {
		SECURE_C_LOGE("Cannot read from file %s", path);
		ret = PC_ERR_FILE_OPERATION;
		goto out;
	}

	SECURE_C_LOGD("smack_label=%s", smack_label);

	ret = PC_OPERATION_SUCCESS;

out:
	return ret;
}

API int smack_pid_have_access(pid_t pid,
								const char* object,
								const char *access_type)
{
	SECURE_C_LOGD("Entering function: %s. Params: pid=%i, object=%s, access_type=%s",
				__func__, pid, object, access_type);

	int ret;
	char pid_subject_label[SMACK_LABEL_LEN + 1];
	cap_t cap;
	cap_flag_value_t cap_v;

	if (!have_smack()) {
		C_LOGD("No SMACK. Return access granted");
		return 1;
	}

	if (pid < 0) {
		C_LOGE("Invalid pid.");
		return -1;
	}

	if(object == NULL) {
		C_LOGE("Invalid object param.");
		return -1;
	}

	if(access_type == NULL) {
		C_LOGE("Invalid access_type param");
		return -1;
	}

	//get SMACK label of process
	ret = get_smack_label_from_process(pid, pid_subject_label);
	if (PC_OPERATION_SUCCESS != ret) {
		SECURE_C_LOGE("get_smack_label_from_process %d failed: %d", pid, ret);
		return -1;
	}
	SECURE_C_LOGD("pid %d has label: %s", pid, pid_subject_label);

	// do not call smack_have_access() if label is empty
	if (pid_subject_label[0] != '\0') {
		ret = smack_have_access(pid_subject_label, object, access_type);
		if ( -1 == ret) {
			C_LOGE("smack_have_access failed.");
			return -1;
		}
		if ( 1 == ret ) { // smack_have_access return 1 (access granted)
			C_LOGD("smack_have_access returned 1 (access granted)");
			return 1;
		}
	}

	// smack_have_access returned 0 (access denied). Now CAP_MAC_OVERRIDE should be checked
	C_LOGD("smack_have_access returned 0 (access denied)");
	cap = cap_get_pid(pid);
	if (cap == NULL) {
		C_LOGE("cap_get_pid failed");
		return -1;
	}
	ret = cap_get_flag(cap, CAP_MAC_OVERRIDE, CAP_EFFECTIVE, &cap_v);
	if (0 != ret) {
		C_LOGE("cap_get_flag failed");
		return -1;
	}

	if (cap_v == CAP_SET) {
		C_LOGD("pid %d has CAP_MAC_OVERRIDE", pid);
		return 1;

	} else {
		C_LOGD("pid %d doesn't have CAP_MAC_OVERRIDE", pid);
		return 0;
	}
}

static int set_dac(const char *smack_label, const char *pkg_name)
{
	SECURE_C_LOGD("Entering function: %s. Params: smack_label=%s, pkg_name=%s",
				__func__, smack_label, pkg_name);

	FILE* fp_group = NULL;	// /etc/group
	uid_t t_uid = -1;		// uid of current process
	gid_t *glist = NULL;	// group list
	gid_t temp_gid = -1;	// for group list
	char buf[10] = {0, };		// contents in group_list file
	int glist_cnt = 0;		// for group list
	int result;
	int i;
	new_user usr;
	unsigned *additional_gids = NULL;

	/*
	 * initialize user structure
	 */
	C_LOGD("Initialize user structure");
	memset(usr.user_name, 0x00, 10);
	memset(usr.home_dir, 0x00, 64);
	memset(usr.group_list, 0x00, 64);
	usr.uid = -1;
	usr.gid = -1;

	t_uid = getuid();
	C_LOGD("Current uid is %d", t_uid);

	if(t_uid == 0)	// current user is 'root'
	{
		if(!strncmp(pkg_name, "developer", 9))
		{
			strncpy(usr.user_name, DEV_USER_NAME, sizeof(usr.user_name));
			usr.uid = DEVELOPER_UID;
			usr.gid = DEVELOPER_GID;
			strncpy(usr.home_dir, DEV_HOME_DIR, sizeof(usr.home_dir));
			strncpy(usr.group_list, DEV_GROUP_PATH, sizeof(usr.group_list));
		}
		else
		{
			strncpy(usr.user_name, APP_USER_NAME, sizeof(usr.user_name));
			usr.uid = APP_UID;
			usr.gid = APP_GID;
			strncpy(usr.home_dir, APP_HOME_DIR, sizeof(usr.home_dir));
			strncpy(usr.group_list, APP_GROUP_PATH, sizeof(usr.group_list));
		}

		/*
		 * get group information
		 */
		C_LOGD("Get group information");
		SECURE_C_LOGD("Opening file %s.", usr.group_list);
		if(!(fp_group = fopen(usr.group_list, "r")))
		{
			C_LOGE("fopen failed.");
			result = PC_ERR_FILE_OPERATION;	// return -1
			goto error;
		}

		while(fgets(buf, 10, fp_group) != NULL)
		{
			errno = 0;
			temp_gid = strtoul(buf, 0, 10);
			if(errno != 0)	// error occured during strtoul()
			{
				C_LOGE("Cannot change string to integer: %s", buf);
				result = PC_ERR_INVALID_OPERATION;
				goto error;
			}

			glist = (gid_t*)realloc(glist, sizeof(gid_t) * (glist_cnt + 1));
			if(!glist)
			{
				result = PC_ERR_MEM_OPERATION;	// return -2
				C_LOGE("Cannot allocate memory");
				goto error;
			}
			glist[glist_cnt] = temp_gid;
			glist_cnt++;
		}
		fclose(fp_group);
		fp_group = NULL;

		if(NULL != smack_label)
		{
			gid_t *glist_new;
			int i, cnt;

			result = get_app_gids(smack_label, &additional_gids, &cnt);
			if (result != PC_OPERATION_SUCCESS)
				goto error;

			if (cnt > 0) {
				glist_new = (gid_t*)realloc(glist, sizeof(gid_t) * (glist_cnt + cnt));
				if (glist_new == NULL) {
					result = PC_ERR_MEM_OPERATION;	// return -2
					C_LOGE("Memory allocation failed");
					goto error;
				}
				glist = glist_new;
				for (i = 0; i < cnt; ++i) {
					C_LOGD("Additional GID based on enabled permissions: %u", additional_gids[i]);
					glist[glist_cnt++] = additional_gids[i];
				}
			}
		}

		/*
		 * setgroups()
		 */
		C_LOGD("Adding process to the following groups:");
		for(i=0; i<glist_cnt; ++i) {
			SECURE_C_LOGD("glist [ %d ] = %d", i, glist[i]);
		}
		C_LOGD("Calling setgroups()");
		if(setgroups(glist_cnt, glist) != 0)
		{
			C_LOGE("setgroups failed");
			result = PC_ERR_NOT_PERMITTED;	// return -3
			goto error;
		}
		if(glist != NULL)
		{
			free(glist);
			glist = NULL;
		}

		/*
		 * setuid() & setgid()
		 */
		C_LOGD("setgid( %d ) & setuid( %d )", usr.gid, usr.uid);
		if(setgid(usr.gid) != 0)	// fail
		{
			C_LOGE("Failed to execute setgid().");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}
		if(setuid(usr.uid) != 0)	// fail
		{
			C_LOGE("Failed to execute setuid().");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}

		SECURE_C_LOGD("setenv(): USER = %s, HOME = %s", usr.user_name, usr.home_dir);
		if(setenv("USER", usr.user_name, 1) != 0)	//fail
		{
			C_LOGE("Failed to execute setenv() [USER].");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}
		if(setenv("HOME", usr.home_dir, 1) != 0)	// fail
		{
			C_LOGE("Failed to execute setenv() [HOME].");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}
	}
	else	// current user is not only 'root' but 'app'
	{
		C_LOGE("Current user is NOT root");
		result = PC_ERR_NOT_PERMITTED;	// return -3
		goto error;
	}

	result = PC_OPERATION_SUCCESS;

error:
	if(fp_group != NULL)
		fclose(fp_group);
	if(glist != NULL)
		free(glist);
	free(additional_gids);

	return result;
}

/**
 * Get SMACK label from EXEC label of a file.
 * SMACK label should be freed by caller
 *
 * @param path file path to take label from
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
static int get_smack_from_binary(char **smack_label, const char* path, app_type_t type)
{
	SECURE_C_LOGD("Entering function: %s. Params: path=%s, type=%d",
				__func__, path, type);
	int ret;

	*smack_label = NULL;
	if (type == APP_TYPE_WGT
	|| type == APP_TYPE_WGT_PARTNER
	|| type == APP_TYPE_WGT_PLATFORM) {
		ret = smack_lgetlabel(path, smack_label, SMACK_LABEL_EXEC);
	} else {
		ret = smack_getlabel(path, smack_label, SMACK_LABEL_EXEC);
	}
	if (ret != 0) {
		C_LOGE("Getting exec label from file %s failed", path);
		return PC_ERR_INVALID_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

/**
 * Set process SMACK label.
 * This function is emulating EXEC label behavior of SMACK for programs
 * run by dlopen/dlsym instead of execv.
 *
 * @param smack label
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
static int set_smack_for_self (char *smack_label)
{
	SECURE_C_LOGD("Entering function: %s. Params: smack_label=%s",
				__func__, smack_label);
	int ret;

	if (smack_label == NULL) {
		/* No label to set, just return with success */
		C_LOGD("No label to set, just return with success.");
		ret = PC_OPERATION_SUCCESS;
	}
	else {
		SECURE_C_LOGD("smack_label=%s", smack_label);
		if (have_smack()) {
			ret = smack_set_label_for_self(smack_label);
			C_LOGD("smack_set_label_for_self returned %d", ret);
		} else
			ret = PC_OPERATION_SUCCESS;
	}

	return ret;
}

static int is_widget(const char* path)
{
	SECURE_C_LOGD("Entering function: %s. Params: path=%s",
				__func__, path);
	char buf[sizeof(WRT_CLIENT_PATH)];
	int ret;

	ret = readlink(path, buf, sizeof(WRT_CLIENT_PATH));
	if (ret == -1)
		C_LOGD("readlink(%s) returned error: %s. Assuming that app is not a widget", path, strerror(errno));
	else if (ret == sizeof(WRT_CLIENT_PATH))
		C_LOGD("%s is not a widget", path);
	if (ret == -1 || ret == sizeof(WRT_CLIENT_PATH))
		return 0;
	buf[ret] = '\0';
	C_LOGD("buf=%s", buf);

	ret = !strcmp(WRT_CLIENT_PATH, buf);
	C_LOGD("%s is %s widget", path, ret ? "a" : "not a");
	return (ret);
}

/**
 * Partially verify, that the type given for app is correct.
 * This function will use some heuristics to check whether the app type is right.
 * It is intended for security hardening to catch privilege setting for the
 * app type not corresponding to the actual binary.
 * Beware - when it detects an anomaly, the whole process will be terminated.
 *
 * @param type claimed application type
 * @param path file path to executable
 * @return return void on success, terminate the process on error
 */
static app_type_t verify_app_type(const char* type, const char* path)
{
	SECURE_C_LOGD("Entering function: %s. Params: type=%s, path=%s",
				__func__, type, path);

	/* TODO: this should actually be treated as error, but until the old
	 * set_privilege API is removed, it must be ignored */
	if (path == NULL) {
		C_LOGD("PKG_TYPE_OTHER");
		return APP_TYPE_OTHER; /* good */
	}

	if (is_widget(path)) {
		if (!strcmp(type, "wgt")) {
			C_LOGD("PKG_TYPE_WGT");
			return APP_TYPE_WGT; /* good */
		} else if (!strcmp(type, "wgt_partner")) {
			C_LOGD("PKG_TYPE_WGT_PARTNER");
			return APP_TYPE_WGT_PARTNER; /* good */
		} else if (!strcmp(type, "wgt_platform")) {
			C_LOGD("PKG_TYPE_WGT_PLATFORM");
			return APP_TYPE_WGT_PLATFORM; /* good */
		}

	} else {
		if (type == NULL || (strcmp(type, "wgt")
				&& strcmp(type, "wgt_partner")
				&& strcmp(type, "wgt_platform"))){
			C_LOGD("PKG_TYPE_OTHER");
			return APP_TYPE_OTHER; /* good */
		}
	}

	/* bad */
	C_LOGE("EXIT_FAILURE");
	exit(EXIT_FAILURE);
}

API int set_app_privilege(const char* name, const char* type, const char* path)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: name=%s, type=%s, path=%s",
				__func__, name, type, path);

	return perm_app_set_privilege(name, type, path);
}

API int perm_app_set_privilege(const char* name, const char* type, const char* path)
{
	SECURE_C_LOGD("Entering function: %s. Params: name=%s, type=%s, path=%s",
				__func__, name, type, path);

	//SECURE_C_LOGD("Function params: name = %s, type = %s, path = %s", name, type, path);
	int ret = PC_OPERATION_SUCCESS;
	int were_rules_loaded = 0;
	char *smack_label AUTO_FREE;

	if (name == NULL) {
		C_LOGE("Error invalid parameter");
		return PC_ERR_INVALID_PARAM;
	}

	if (path != NULL && have_smack()) {
		ret = get_smack_from_binary(&smack_label, path, verify_app_type(type, path));
		if (ret != PC_OPERATION_SUCCESS)
			return ret;
		were_rules_loaded = check_if_rules_were_loaded(smack_label);
		if (were_rules_loaded < 0) {
			C_LOGE("check_if_rules_was_loaded failed.");
			return PC_ERR_INVALID_OPERATION;
		}
		if (!were_rules_loaded) { // first run of application
			C_LOGD("This is first run of this application. Adding SMACK rules.");
			ret = add_app_first_run_rules(smack_label);
			if (ret != PC_OPERATION_SUCCESS ) {
				C_LOGW("add_app_first_run_rules failed");
				// should we return here with error code?
			}
			mark_rules_as_loaded(smack_label);
		}

		ret = set_smack_for_self(smack_label);
		if (ret != PC_OPERATION_SUCCESS)
			return ret;
	}

	if (path != NULL && !have_smack()) {
		ret = get_smack_from_binary(&smack_label, path, verify_app_type(type, path));
		if (ret != PC_OPERATION_SUCCESS)
			return ret;
	}

	return set_dac(smack_label, name);
}

API int set_privilege(const char* pkg_name)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_name=%s",
				__func__, pkg_name);

	return perm_app_set_privilege(pkg_name, NULL, NULL);
}

static inline const char* app_type_name(app_type_t app_type)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d",
				__func__, app_type);

	switch (app_type) {
	case APP_TYPE_WGT:
		C_LOGD("App type = APP_TYPE_WGT");
		return "WRT";
	case APP_TYPE_OSP:
		C_LOGD("App type = APP_TYPE_OSP");
		return "OSP";
	case APP_TYPE_WGT_PARTNER:
		C_LOGD("App type = APP_TYPE_WGT_PARTNER");
		return "WRT_partner";
	case APP_TYPE_WGT_PLATFORM:
		C_LOGD("App type = APP_TYPE_WGT_PLATFORM");
		return "WRT_platform";
	case APP_TYPE_OSP_PARTNER:
		C_LOGD("App type = APP_TYPE_OSP_PARTNER");
		return "OSP_partner";
	case APP_TYPE_OSP_PLATFORM:
		C_LOGD("App type = APP_TYPE_OSP_PLATFORM");
		return "OSP_platform";
	case APP_TYPE_EFL:
		return "EFL";
	default:
		C_LOGD("App type = other");
		return NULL;
	}
}

static inline const char* app_type_group_name(app_type_t app_type)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d",
				__func__, app_type);

	switch (app_type) {
	case APP_TYPE_WGT:
	case APP_TYPE_WGT_PARTNER:
	case APP_TYPE_WGT_PLATFORM:
		C_LOGD("App type group name = WRT");
		return "WRT";
	case APP_TYPE_OSP:
	case APP_TYPE_OSP_PARTNER:
	case APP_TYPE_OSP_PLATFORM:
		C_LOGD("App type group name = OST");
		return "OSP";
	case APP_TYPE_EFL:
		return "EFL";
	default:
		return NULL;
	}
}

/**
 * This function changes permission URI to basename for file name.
 * For e.g. from http://tizen.org/privilege/contact.read will be
 * created basename : org.tizen.privilege.contact.read
 */

static int base_name_from_perm(const char *perm, char **name)
{
	SECURE_C_LOGD("Entering function: %s. Params: perm=%s",
				__func__, perm);

	iri_t *ip = NULL;
	char *host_dot = NULL;
	char *rest_slash = NULL;
	int ret;

	ip = iri_parse(perm);
	if (ip == NULL || ip->host == NULL) {
		SECURE_C_LOGE("Bad permission format : %s", perm);
		iri_destroy(ip);
		return PC_ERR_INVALID_PARAM;
	}

	if (ip->path == NULL) {
		ip->path = ip->host;
		ip->host = NULL;
	}

	if (ip->host) {
		host_dot = strrchr(ip->host, '.');
		if (host_dot) {
			*host_dot = '\0';
			++host_dot;
		}
	}

	while ((rest_slash = strchr(ip->path, '/'))) {
		*rest_slash = '.';
	}

	ret = asprintf(name, "%s%s%s%s",
			host_dot ? host_dot : "", host_dot ? "." : "",
			ip->host ? ip->host : "", ip->path);
	if (ret == -1) {
		C_LOGE("asprintf failed");
		iri_destroy(ip);
		return PC_ERR_MEM_OPERATION;
	}

	iri_destroy(ip);
	return PC_OPERATION_SUCCESS;
}

static int perm_file_path(char** path, app_type_t app_type, const char* perm, const char *suffix, bool is_early)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d, perm=%s, suffix=%s, is_early=%d",
				__func__, app_type, perm, suffix, is_early);

	const char* app_type_prefix = NULL;
	char* perm_basename = NULL;
	int ret = 0;

	if (perm == NULL || strlen(perm) == 0) {
		C_LOGE("Empty permission name.");
		return PC_ERR_INVALID_PARAM;
	}

	app_type_prefix = app_type_group_name(app_type);

	ret = base_name_from_perm(perm, &perm_basename);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Couldn't get permission basename.");
		return ret;
	}

	if (is_early) {
		ret = asprintf(path, TOSTRING(SHAREDIR) "/%s%s%s%s%s",
		app_type_prefix ? app_type_prefix : "", app_type_prefix ? "_" : "",
		perm_basename, "_early", suffix);
	}
	else {
		ret = asprintf(path, TOSTRING(SHAREDIR) "/%s%s%s%s",
		app_type_prefix ? app_type_prefix : "", app_type_prefix ? "_" : "",
		perm_basename, suffix);
	}
	if (ret == -1) {
		C_LOGE("asprintf failed.");
		return PC_ERR_MEM_OPERATION;
	}

	C_LOGD("Path=%s", *path);

	return PC_OPERATION_SUCCESS;
}

static int perm_to_smack_from_file(struct smack_accesses* smack,
		                           const char* app_label,
		                           const char* app_label_template,
		                           const char* rules_file_path)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_label=%s, app_label_template=%s, rules_file_path=%s",
				__func__, app_label, app_label_template, rules_file_path);

	char smack_subject[SMACK_LABEL_LEN + 1];
	char smack_object[SMACK_LABEL_LEN + 1];
	char smack_accesses[ACC_LEN + 1];
	FILE* file AUTO_FCLOSE;

	SECURE_C_LOGD("Opening file %s.", rules_file_path);
	file = fopen(rules_file_path, "r");
	if (file == NULL) {
		SECURE_C_LOGW("fopen failed [%s] %s", rules_file_path, strerror(errno));
		return PC_OPERATION_SUCCESS;
	}

	while (fscanf(file,
			"%" TOSTRING(SMACK_LABEL_LEN) "s "
			"%" TOSTRING(SMACK_LABEL_LEN) "s "
			"%" TOSTRING(ACC_LEN) "s\n",
			smack_subject, smack_object, smack_accesses) == 3) {
		if (!strcmp(smack_subject, app_label_template))
			strcpy(smack_subject, app_label);

		if (!strcmp(smack_object, app_label_template))
			strcpy(smack_object, app_label);

		C_LOGD("smack_accesses_add_modify (subject: %s, object: %s, access: %s)", smack_subject, smack_object, smack_accesses);
		if (smack_accesses_add_modify(smack, smack_subject, smack_object, smack_accesses, "") != 0) {
			C_LOGE("smack_accesses_add_modify failed.");
			return PC_ERR_INVALID_OPERATION;
		}
	}

	return PC_OPERATION_SUCCESS;
}

static int perm_to_smack_generic(struct smack_accesses* smack, const char* app_label, app_type_t app_type, const char* perm, bool is_early)
{
	C_LOGD("Enter function: %s", __func__);

	int ret;
	char* path AUTO_FREE;

	// get file name for permission (devcap)
	ret = perm_file_path(&path, app_type, perm, ".smack", is_early);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGD("No smack config file for permission %s", perm);
		return ret;
	}

	ret = perm_to_smack_from_file(smack, app_label, SMACK_APP_LABEL_TEMPLATE, path);
	if (ret != PC_OPERATION_SUCCESS) {
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

static int perm_to_smack_early(struct smack_accesses* smack, const char* app_label, app_type_t app_type, const char* perm)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_label=%s, app_type=%d, perm=%s",
				__func__, app_label, app_type, perm);

	return perm_to_smack_generic(smack, app_label, app_type, perm, 1);
}

static int perm_to_smack(struct smack_accesses* smack, const char* app_label, app_type_t app_type, const char* perm)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_label=%s, app_type=%d, perm=%s",
				__func__, app_label, app_type, perm);

	return perm_to_smack_generic(smack, app_label, app_type, perm, 0);
}

static int perm_to_dac(const char* app_label, app_type_t app_type, const char* perm)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_label=%s, app_type=%d, perm=%s",
				__func__, app_label, app_type, perm);

	int ret;
	char* path AUTO_FREE;
	FILE* file AUTO_FCLOSE;
	int gid;

	ret = perm_file_path(&path, app_type, perm, ".dac", 0);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGD("No dac config file for permission %s", perm);
		return ret;
	}

	SECURE_C_LOGD("Opening file %s.", path);
	file = fopen(path, "r");
	if (file == NULL) {
		C_LOGW("fopen failed.");
		return PC_OPERATION_SUCCESS;
	}

	while (fscanf(file, "%d\n", &gid) == 1) {
		SECURE_C_LOGD("Adding app_id %s to group %d", app_label, gid);
		ret = add_app_gid(app_label, gid);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("add_app_gid failed");
			return ret;
		}
	}

	return PC_OPERATION_SUCCESS;
}

static int label_all(const FTSENT* ftsent)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	return DECISION_LABEL;
}

static int label_execs(const FTSENT* ftsent)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	C_LOGD("Mode = %d", ftsent->fts_statp->st_mode);
	// label only regular executable files
	if (S_ISREG(ftsent->fts_statp->st_mode) && (ftsent->fts_statp->st_mode & S_IXUSR))
		return DECISION_LABEL;
	return DECISION_SKIP;
}

static int label_dirs(const FTSENT* ftsent)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	// label only directories
	if (S_ISDIR(ftsent->fts_statp->st_mode))
		return DECISION_LABEL;
	return DECISION_SKIP;
}

static int label_links_to_execs(const FTSENT* ftsent)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	struct stat buf;
	char* target AUTO_FREE;

	// check if it's a link
	if ( !S_ISLNK(ftsent->fts_statp->st_mode))
		return DECISION_SKIP;

	target = realpath(ftsent->fts_path, NULL);
	if (!target) {
		SECURE_C_LOGE("Getting link target for %s failed (Error = %s)", ftsent->fts_path, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}
	if (-1 == stat(target, &buf)) {
		SECURE_C_LOGE("stat failed for %s (Error = %s", target, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}
	// skip if link target is not a regular executable file
	if (buf.st_mode != (buf.st_mode | S_IXUSR | S_IFREG)) {
		SECURE_C_LOGD("%s is not a regular executable file. Skipping.", target);
		return DECISION_SKIP;
	}

	return DECISION_LABEL;
}

static int dir_set_smack_r(const char *path, const char* label,
		enum smack_label_type type, label_decision_fn fn)
{
	SECURE_C_LOGD("Entering function: %s. Params: path=%s, label=%s, type=%d",
				__func__, path, label, type);

	const char* path_argv[] = {path, NULL};
	FTS *fts AUTO_FTS_CLOSE;
	FTSENT *ftsent;
	int ret;

	fts = fts_open((char * const *) path_argv, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL) {
		C_LOGE("fts_open failed.");
		return PC_ERR_FILE_OPERATION;
	}

	while ((ftsent = fts_read(fts)) != NULL) {
		/* Check for error (FTS_ERR) or failed stat(2) (FTS_NS) */
		if (ftsent->fts_info == FTS_ERR || ftsent->fts_info == FTS_NS) {
			C_LOGE("FTS_ERR error or failed stat(2) (FTS_NS)");
			return PC_ERR_FILE_OPERATION;
		}

		ret = fn(ftsent);
		if (ret < 0) {
			C_LOGE("fn(ftsent) failed.");
			return ret;
		}

		if (ret == DECISION_LABEL) {
			C_LOGD("smack_lsetlabel (label: %s (type: %d), path: %s)", label, type, ftsent->fts_path);
			if (smack_lsetlabel(ftsent->fts_path, label, type) != 0) {
				C_LOGE("smack_lsetlabel failed.");
				return PC_ERR_FILE_OPERATION;
			}
		}
	}

	/* If last call to fts_read() set errno, we need to return error. */
	if (errno != 0) {
		C_LOGE("Last errno from fts_read: %s", strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}
	return PC_OPERATION_SUCCESS;
}

API char* app_id_from_socket(int sockfd)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: sockfd=%d",
				__func__, sockfd);

    return perm_app_id_from_socket(sockfd);
}

API char* perm_app_id_from_socket(int sockfd)
{
	SECURE_C_LOGD("Entering function: %s. Params: sockfd=%d",
				__func__, sockfd);

	if (!have_smack()) {
		C_LOGD("No SMACK. Returning NULL.");
		return NULL;
	}

	char* app_id;
	int ret;

	ret = smack_new_label_from_socket(sockfd, &app_id);
	if (ret < 0) {
		C_LOGE("smack_new_label_from_socket failed");
		return NULL;
	}

	SECURE_C_LOGD("app_id = %s", app_id);

	return app_id;
}

static int app_add_rule(const char *app_id, const char *object, const char *perm)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s, object=%s, perm=%s",
				__func__, app_id, object, perm);

	int ret;
	int fd AUTO_CLOSE;
	char *smack_path AUTO_FREE;
	struct smack_accesses* smack AUTO_SMACK_FREE;

	ret = load_smack_from_file(app_id, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed.");
		return ret;
	}

	ret = smack_accesses_add_modify(smack, app_id, object, perm, "");
	if (ret == -1) {
		C_LOGE("smack_accesses_add_modify failed.");
		return PC_ERR_INVALID_OPERATION;
	}

	if (have_smack() && smack_accesses_apply(smack)) {
		C_LOGE("smack_accesses_apply failed.");
		return PC_ERR_INVALID_OPERATION;
	}

	if (smack_accesses_save(smack, fd)) {
		C_LOGE("smack_accesses_save failed.");
		return PC_ERR_INVALID_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}


static int
app_register_appsetting(const char *app_id, struct smack_accesses *smack)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
				__func__, app_id);

	int ret;
	int i;

	char **label_app_list AUTO_FREE;
	char **label_dir_list AUTO_FREE;
	int app_list_len = 0;
	int dir_list_len = 0;

	if (!smack_label_is_valid(app_id)) {
		C_LOGE("Invalid param app_id.");
		return PC_ERR_INVALID_PARAM;
	}

	/* writing appsetting_id (app_id) to "database"*/
	ret = add_appsetting_id_to_databse(app_id);
	if (ret != PC_OPERATION_SUCCESS)
		goto out;


	/* Reading labels of all installed apps from "database"*/
	ret = get_all_apps_ids(&label_app_list, &app_list_len);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while getting data from database");
		goto out;
	}

	/*Add smack rules with rx access to each app*/
	for (i = 0; i < app_list_len; ++i) {
		C_LOGD("Appsetting: applying rx rule for %s", label_app_list[i]);
		if (smack_accesses_add_modify(smack, app_id,
				label_app_list[i], "rx", "") == -1) {
			C_LOGE("smack_accesses_add_modify failed.");
			ret = PC_ERR_INVALID_OPERATION;
			goto out;
		}
	}

	/* Reading labels of all registered settings dirs from "database"*/
	ret = get_all_settings_dir_ids(
			&label_dir_list, &dir_list_len);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while getting data from database");
		goto out;
	}
	/*Add smack rules with rwx access to each app*/
	for (i = 0; i < dir_list_len; ++i) {
		C_LOGD("Appsetting: applying rwx rule for %s", label_dir_list[i]);
		if (smack_accesses_add_modify(smack, app_id,
				label_dir_list[i], "rwx", "") == -1) {
			C_LOGE("smack_accesses_add_modify failed.");
			ret = PC_ERR_INVALID_OPERATION;
			goto out;
			/* Should we abort adding rules if
			 * smack_accesses_add_modify fails once?*/
		}
	}

	out:
	for (i = 0; i < app_list_len; ++i) {
		free(label_app_list[i]);
	}
	for (i = 0; i < dir_list_len; ++i) {
		free(label_dir_list[i]);
	}

	return ret;
}

static int give_anti_virus_access_to_all_folders(const char *app_av_id, struct smack_accesses* smack, int folder_type)
{
	int ret;
	int i;

	char** smack_label_list AUTO_FREE;
	int smack_label_list_len = 0;

	switch (folder_type) {
		case APP_PATH_PUBLIC_RO:
			ret = db_get_public_dirs(&smack_label_list, &smack_label_list_len);
			break;
		case APP_PATH_GROUP_RW:
			ret = db_get_groups_dirs(&smack_label_list, &smack_label_list_len);
			break;
		case APP_PATH_SETTINGS_RW:
			ret = get_all_settings_dir_ids(&smack_label_list, &smack_label_list_len);
			break;
		default:
			return PC_OPERATION_SUCCESS;
	}
	if (ret != PC_OPERATION_SUCCESS ) {
		C_LOGE("Error while getting public RO folders from database.");
		goto out;
	}

	for (i = 0; i < smack_label_list_len; ++i) {
		SECURE_C_LOGD("Applying rwx rule for %s", smack_label_list[i]);
		if (smack_accesses_add_modify(smack, app_av_id, smack_label_list[i], "wrx", "") == -1) {
			C_LOGE("smack_accesses_add_modify failed.");
			ret = PC_ERR_INVALID_OPERATION;
			goto out;
		}
	}

out:

	for (i = 0; i < smack_label_list_len; ++i) {
		free(smack_label_list[i]);
	}

	return ret;
}

static int app_register_av_internal(const char *app_av_id, struct smack_accesses* smack)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_av_id=%s.",
				__func__, app_av_id);

	int ret;
	int i;

	char** smack_label_app_list AUTO_FREE;
	int smack_label_app_list_len = 0;

	if (!smack_label_is_valid(app_av_id)) {
		C_LOGE("Invalid param app_av_id.");
		return PC_ERR_INVALID_PARAM;
	}

	if(smack == NULL) {
		C_LOGE("Invalid param smack (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	// writing anti_virus_id (app_av_id) to "database"
	ret = add_av_id_to_databse(app_av_id);
	if (ret != PC_OPERATION_SUCCESS )
		goto out;

	// Reading labels of all installed apps from "database"
	ret = get_all_apps_ids(&smack_label_app_list, &smack_label_app_list_len);
	if (ret != PC_OPERATION_SUCCESS ) {
		C_LOGE("Error while getting installed apps from database.");
		goto out;
	}
	for (i = 0; i < smack_label_app_list_len; ++i) {
		SECURE_C_LOGD("Applying rwx rule for %s", smack_label_app_list[i]);
		if (smack_accesses_add_modify(smack, app_av_id, smack_label_app_list[i], "wrx", "") == -1) {
			C_LOGE("smack_accesses_add_modify failed.");
			ret = PC_ERR_INVALID_OPERATION;
			goto out;
			// Should we abort adding rules once smack_accesses_add_modify will fail?
		}
	}

	// Giving anti virus RWX access to public RO folders
	ret = give_anti_virus_access_to_all_folders(app_av_id, smack, APP_PATH_PUBLIC_RO);
	if (ret != PC_OPERATION_SUCCESS ) {
		C_LOGE("Error while getting public RO folders from database.");
		goto out;
	}

	// Giving anti virus RWX access to groups RW folders
	ret = give_anti_virus_access_to_all_folders(app_av_id, smack, APP_PATH_GROUP_RW);
	if (ret != PC_OPERATION_SUCCESS ) {
		C_LOGE("Error while getting groups RW folders from database.");
		goto out;
	}

	// Giving anti virus RWX access to settings RW folders
	ret = give_anti_virus_access_to_all_folders(app_av_id, smack, APP_PATH_SETTINGS_RW);
	if (ret != PC_OPERATION_SUCCESS ) {
		C_LOGE("Error while getting settings RW folders from database.");
		goto out;
	}

out:
	for (i = 0; i < smack_label_app_list_len; ++i) {
		free(smack_label_app_list[i]);
	}

	return ret;
}

/**
 *  This function will find labels of all anti viruses in database
 *  and for all of them will add a rule "anti_virus_label app_id rwx".
 *  This should be called in app_install function.
 */
static int register_app_for_av(const char * app_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s.",
				__func__, app_id);

	int ret, i;
	char** smack_label_av_list AUTO_FREE;
	int smack_label_av_list_len = 0;

	// Reading labels of all installed anti viruses from "database"
	ret = get_all_avs_ids(&smack_label_av_list, &smack_label_av_list_len);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while geting data from database.");
		return ret;
	}

	// for each anti-virus label put rule: "anti_virus_label app_id rwx"
	for (i = 0; i < smack_label_av_list_len; ++i) {
		SECURE_C_LOGD("Antivirus: app_add_rule (%s, %s rx)", smack_label_av_list[i], app_id);
		if (strcmp(app_id, smack_label_av_list[i])==0) {
			SECURE_C_LOGW("Trying to add antivirus rule for self. Skipping");
			continue;
		}
		ret = app_add_rule(smack_label_av_list[i], app_id, "wrx");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("app_add_rule failed.");
			goto out;
		}

		free(smack_label_av_list[i]);
	}

	ret = PC_OPERATION_SUCCESS;

out:
	// If something failed, then no entry of smack_label_av_list[i]
	// was deallocated. They all must be freed.
	for(; i<smack_label_av_list_len; ++i) {
		free(smack_label_av_list[i]);
	}

	return ret;
}

/**
 *  This function will find labels of all setting applications in database
 *  and for all of them will add a rule "appsetting_id app_id rwx".
 *  This should be called in app_install function.
 */
static int register_app_for_appsetting(const char *app_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
				__func__, app_id);

	int ret, i;
	char **smack_label_list AUTO_FREE;
	int smack_label_list_len = 0;

	/* Reading labels of all installed setting managers from "database"*/
	ret = get_all_appsetting_ids(&smack_label_list, &smack_label_list_len);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while geting data from database.");
		return ret;
	}

	/* for each appsetting put rule: "appsetting_id app_id rx"*/
	for (i = 0; i < smack_label_list_len; ++i) {
		SECURE_C_LOGD("Appsetting: app_add_rule (%s, %s rx)", smack_label_list[i], app_id);
		if (strcmp(app_id, smack_label_list[i])==0) {
			SECURE_C_LOGW("Trying to add setting rule for self. Skipping");
			continue;
		}

		ret = app_add_rule(smack_label_list[i], app_id, "rx");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("app_add_rule failed");
			goto out;
		}

		free(smack_label_list[i]);
	}

	ret = PC_OPERATION_SUCCESS;

out:
	/* If something failed, then no entry of smack_label_list[i]
	 was deallocated. They all must be freed.*/
	for (; i < smack_label_list_len; ++i) {
		free(smack_label_list[i]);
	}

	return ret;
}


/**
 *  This function will grant app_id rx access to all public directories and
 *  files previously designated by app_setup_path(APP_PATH_PUBLIC_RO)
 *  This should be called in app_install function.
 */
static int register_app_for_public_dirs(const char *app_id, struct smack_accesses *smack)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
				__func__, app_id);
	int ret, i;
	char **public_dirs AUTO_FREE;
	int public_dirs_cnt = 0;

	ret = db_get_public_dirs(&public_dirs, &public_dirs_cnt);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while getting data from database");
		return ret;
	}

	for (i = 0; i < public_dirs_cnt; ++i) {
		SECURE_C_LOGD("Allowing app %s to access public path %s", app_id, public_dirs[i]);
		if (smack_accesses_add_modify(smack, app_id, public_dirs[i], "rx", "")) {
			C_LOGE("app_add_rule_modify failed");
			while (i < public_dirs_cnt)
				free(public_dirs[i++]);
			return PC_ERR_INVALID_OPERATION;
		}
		free(public_dirs[i]);
	}

	return PC_OPERATION_SUCCESS;
}

static int app_add_permissions_internal(const char* app_id, app_type_t app_type, const char** perm_list, int permanent)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s, app_type=%d, permanent=%d",
				__func__, app_id, app_type, permanent);

	int i, ret;
	char* smack_path AUTO_FREE;
	char* smack_path_early AUTO_FREE;
	int fd AUTO_CLOSE;
	int fd_early AUTO_CLOSE;
	struct smack_accesses *smack AUTO_SMACK_FREE;
	struct smack_accesses *smack_early AUTO_SMACK_FREE;
	const char* base_perm = NULL;

	if (!smack_label_is_valid(app_id)) {
		C_LOGE("Invalid param app_id.");
		return PC_ERR_INVALID_PARAM;
	}

	if(perm_list == NULL) {
		C_LOGE("Invalid perm_list (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	ret = load_smack_from_file(app_id, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		return ret;
	}

	ret = load_smack_from_file_early(app_id, &smack_early, &fd_early, &smack_path_early);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		return ret;
	}

	/* Implicitly enable base permission for an app_type */
	base_perm = app_type_name(app_type);
	if (base_perm) {
		SECURE_C_LOGD("perm_to_smack params: app_id: %s, %s", app_id, base_perm);
		ret = perm_to_smack(smack, app_id, APP_TYPE_OTHER, base_perm);
		if (ret != PC_OPERATION_SUCCESS){
			C_LOGE("perm_to_smack failed");
			return ret;
		}

		// Add early permission - such permissions should be enabled right after system boot
		SECURE_C_LOGD("perm_to_smack params: app_id: %s, %s", app_id, base_perm);
		ret = perm_to_smack_early(smack_early, app_id, APP_TYPE_OTHER, base_perm);
		if (ret != PC_OPERATION_SUCCESS){
			C_LOGE("perm_to_smack failed");
			return ret;
		}

	}
	for (i = 0; perm_list[i] != NULL; ++i) {
		SECURE_C_LOGD("perm_to_smack params: app_id: %s, perm_list[%d]: %s", app_id, i, perm_list[i]);
		if (strcmp(perm_list[i], TIZEN_PRIVILEGE_ANTIVIRUS) == 0) {
			ret = app_register_av_internal(app_id, smack);
			if (ret != PC_OPERATION_SUCCESS) {
				C_LOGE("app_register_av_internal failed");
				return ret;
			}
		}
		if (strcmp(perm_list[i], TIZEN_PRIVILEGE_APPSETTING) == 0) {
			ret = app_register_appsetting(app_id, smack);
			if (ret != PC_OPERATION_SUCCESS) {
				C_LOGE("app_register_appsetting failed");
				return ret;
			}
		}

		ret = perm_to_smack(smack, app_id, app_type, perm_list[i]);
		if (ret != PC_OPERATION_SUCCESS){
			C_LOGE("perm_to_smack failed");
			return ret;
		}

		ret = perm_to_smack_early(smack_early, app_id, app_type, perm_list[i]);
		if (ret != PC_OPERATION_SUCCESS){
			C_LOGE("perm_to_smack_early failed");
			return ret;
		}

		ret = perm_to_dac(app_id, app_type, perm_list[i]);
		if (ret != PC_OPERATION_SUCCESS){
			C_LOGE("perm_to_dac failed");
			return ret;
		}
	}

	if (have_smack() && smack_accesses_apply(smack)) {
		C_LOGE("smack_accesses_apply failed");
		return PC_ERR_INVALID_OPERATION;
	}

	if (have_smack() && smack_accesses_apply(smack_early)) {
		C_LOGE("smack_accesses_apply (early) failed");
		return PC_ERR_INVALID_OPERATION;
	}

	if (permanent && smack_accesses_save(smack, fd)) {
		C_LOGE("smack_accesses_save failed");
		return PC_ERR_INVALID_OPERATION;
	}

	if (permanent && smack_accesses_save(smack_early, fd_early)) {
		C_LOGE("smack_accesses_save (early) failed");
		return PC_ERR_INVALID_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_add_permissions(const char* app_id, const char** perm_list)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
				__func__, app_id);

	return app_add_permissions_internal(app_id, APP_TYPE_OTHER, perm_list, 1);
}

API int app_add_volatile_permissions(const char* app_id, const char** perm_list)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
				__func__, app_id);

	return app_add_permissions_internal(app_id, APP_TYPE_OTHER, perm_list, 0);
}

API int app_enable_permissions(const char* pkg_id, app_type_t app_type, const char** perm_list, bool persistent)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d, persistent=%d",
				__func__, pkg_id, app_type, persistent);

	return app_add_permissions_internal(pkg_id, app_type, perm_list, persistent);
}

API int perm_app_enable_permissions(const char* pkg_id, app_type_t app_type, const char** perm_list, bool persistent)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d, persistent=%d",
				__func__, pkg_id, app_type, persistent);

	return app_add_permissions_internal(pkg_id, app_type, perm_list, persistent);
}

API int app_disable_permissions(const char* pkg_id, app_type_t app_type, const char** perm_list)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d",
				__func__, pkg_id, app_type);

	return perm_app_disable_permissions(pkg_id, app_type, perm_list);
}

/* FIXME: this function is only a stub */
API int perm_app_disable_permissions(const char* pkg_id, app_type_t app_type, const char** perm_list)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, app_type=%d",
				__func__, pkg_id, app_type);

	return PC_OPERATION_SUCCESS;
}

static int app_revoke_permissions_internal(const char* app_id, bool persistent)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s, persistent=%d",
				__func__, app_id, persistent);

	char* smack_path AUTO_FREE;
	int ret;
	int fd AUTO_CLOSE;
	struct smack_accesses *smack AUTO_SMACK_FREE;

	if (!smack_label_is_valid(app_id)) {
		C_LOGE("Invalid param app_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = load_smack_from_file(app_id, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed.");
		return ret;
	}

	if (have_smack() && smack_accesses_clear(smack)) {
		ret = PC_ERR_INVALID_OPERATION;
		C_LOGE("smack_accesses_clear failed.");
		return ret;
	}

	if (have_smack() && smack_revoke_subject(app_id)) {
		ret = PC_ERR_INVALID_OPERATION;
		C_LOGE("smack_revoke_subject failed.");
		return ret;
	}

	if (persistent && ftruncate(fd, 0) == -1)
		C_LOGW("file truncation failed");

	return PC_OPERATION_SUCCESS;
}

API int app_revoke_permissions(const char* pkg_id)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s", __func__, pkg_id);
	return perm_app_revoke_permissions(pkg_id);
}

API int perm_app_revoke_permissions(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s", __func__, pkg_id);
	int ret;

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid param app_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = app_revoke_permissions_internal(pkg_id, true);
	if (ret) {
		C_LOGE("Revoking permissions failed.");
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_reset_permissions(const char* pkg_id)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s",
				__func__, pkg_id);

	return perm_app_reset_permissions(pkg_id);
}

API int perm_app_reset_permissions(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s",
				__func__, pkg_id);

	int ret;

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid param pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = app_revoke_permissions_internal(pkg_id, false);
	if (ret) {
		C_LOGE("Revoking permissions failed.");
		return ret;
	}

	/* Add empty permissions set to trigger re-read of rules */
	return perm_app_enable_permissions(pkg_id, APP_TYPE_OTHER, (const char*[]){NULL}, 0);
}

API int app_label_dir(const char* label, const char* path)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: label=%s, path=%s",
				__func__, label, path);

	int ret = PC_OPERATION_SUCCESS;

	if(path == NULL) {
		C_LOGE("Invalid argument path (NULL).");
		return PC_ERR_INVALID_PARAM;
	}

	if (!smack_label_is_valid(label)) {
		C_LOGE("Invalid param label.");
		return PC_ERR_INVALID_PARAM;
	}

	//setting access label on everything in given directory and below
	ret = dir_set_smack_r(path, label, SMACK_LABEL_ACCESS, &label_all);
	if (PC_OPERATION_SUCCESS != ret)
	{
		C_LOGE("dir_set_smack_r failed.");
		return ret;
	}

	//setting execute label for everything with permission to execute
	ret = dir_set_smack_r(path, label, SMACK_LABEL_EXEC, &label_execs);
	if (PC_OPERATION_SUCCESS != ret)
	{
		C_LOGE("dir_set_smack_r failed.");
		return ret;
	}

	//setting execute label for everything with permission to execute
	ret = dir_set_smack_r(path, label, SMACK_LABEL_EXEC, &label_links_to_execs);
	return ret;
}

static int app_uninstall_remove_early_rules(const char *app_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
				__func__, app_id);

	int ret;
	int fd AUTO_CLOSE;
	int size;
	char tmp;
	char *data, *data_end;
	char *line_begin, *line_end, *write_pos;
	char subject[SMACK_LABEL_LEN + 1];
	char object[SMACK_LABEL_LEN + 1];

	SECURE_C_LOGD("Opening file %s.", SMACK_STARTUP_RULES_FILE);
	fd = open(SMACK_STARTUP_RULES_FILE, O_RDWR);
	if (fd < 0) {
		SECURE_C_LOGE("Unable to open file %s: %s", SMACK_STARTUP_RULES_FILE, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	if (flock(fd, LOCK_EX)) {
		SECURE_C_LOGE("flock failed, error %s", strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	size = lseek(fd, 0, SEEK_END);
	if (size < 0) {
		SECURE_C_LOGE("Unable to read file %s: %s", SMACK_STARTUP_RULES_FILE, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	if (size == 0)
		return PC_OPERATION_SUCCESS;

	data = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (data == MAP_FAILED) {
		SECURE_C_LOGE("Unable to read file %s: %s", SMACK_STARTUP_RULES_FILE, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}
	data_end = data + size;

	line_begin = write_pos = data;
	while (line_begin < data_end) {
		line_end = memchr(line_begin, '\n', data_end - line_begin);
		if (line_end == NULL)
			line_end = data_end - 1;

		tmp = *line_end;
		*line_end = '\0';
		SECURE_C_LOGD("Considering early rule: %s", line_begin);

		ret = sscanf(line_begin, "%" TOSTRING(SMACK_LABEL_LEN) "s %" TOSTRING(SMACK_LABEL_LEN) "s", subject, object);
		if (ret != 2) {
			C_LOGD("Rule format is invalid, skipping it.");
			goto loop_next;
		}

		if (!strcmp(subject, app_id) || !strcmp(object, app_id)) {
			C_LOGD("Rule belongs to an app being removed, skipping it.");
			goto loop_next;
		}

		C_LOGD("Rule still needed, keeping it.");
		*line_end = tmp;
		if (write_pos != line_begin)
			memcpy(write_pos, line_begin, line_end - line_begin + 1);
		write_pos += (line_end - line_begin + 1);

	loop_next:
		*line_end = tmp;
		line_begin = line_end + 1;
	}

	munmap(data, size);
	ret = ftruncate(fd, write_pos - data);
	if (ret < 0) {
		SECURE_C_LOGE("Unable to truncate file %s to %d bytes: %s", SMACK_STARTUP_RULES_FILE, write_pos, strerror(errno));

		return PC_ERR_FILE_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_label_shared_dir(const char* app_label, const char* shared_label, const char* path)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: app_label=%s, shared_label=%s, path=%s",
				__func__, app_label, shared_label, path);
	int ret;

	if(path == NULL) {
		C_LOGE("Invalid param path.");
		return PC_ERR_INVALID_PARAM;
	}

	if(!smack_label_is_valid(app_label)) {
		C_LOGE("Invalid param app_label");
		return PC_ERR_INVALID_PARAM;
	}

	if(!smack_label_is_valid(shared_label)) {
		C_LOGE("Invalid param shared_label");
		return PC_ERR_INVALID_PARAM;
	}

	if (strcmp(app_label, shared_label) == 0) {
		C_LOGE("app_label equals shared_label");
		return PC_ERR_INVALID_PARAM;
	}

	//setting label on everything in given directory and below
	ret = dir_set_smack_r(path, shared_label, SMACK_LABEL_ACCESS, label_all);
	if(ret != PC_OPERATION_SUCCESS){
		C_LOGE("dir_set_smack_r failed.");
		return ret;
	}

	//setting transmute on dir
	ret = dir_set_smack_r(path, "1", SMACK_LABEL_TRANSMUTE, label_dirs);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("dir_set_smack_r failed");
		return ret;
	}

	ret = app_add_rule(app_label, shared_label, "rwxat");
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("app_add_rule failed");
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int add_shared_dir_readers(const char* shared_label, const char** app_list)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: shared_label=%s",
				__func__, shared_label);
	int ret;
	int i;

	if(app_list == NULL) {
		C_LOGE("Invalid param app_list.");
		return PC_ERR_INVALID_PARAM;
	}

	if (!smack_label_is_valid(shared_label)) {
		C_LOGE("Invalid param shared_label.");
		return PC_ERR_INVALID_PARAM;
	}

	for (i = 0; app_list[i] != NULL; i++) {
		if (!smack_label_is_valid(app_list[i])) {
			C_LOGE("Invalid %d element from param app_list.", i);
			return PC_ERR_INVALID_PARAM;
		}

		ret = app_add_rule(app_list[i], shared_label, "rx");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("app_add_rule failed.");
			return ret;
		}
	}

	return PC_OPERATION_SUCCESS;
}

static char* smack_label_for_path(const char *app_id, const char *path)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s, path=%s",
				__func__, app_id, path);

	char *salt AUTO_FREE;
	char *label;
	char *x;

	/* Prefix $1$ causes crypt() to use MD5 function */
	if (-1 == asprintf(&salt, "$1$%s", app_id)) {
		C_LOGE("asprintf failed");
		return NULL;
	}

	label = crypt(path, salt);
	if (label == NULL) {
		C_LOGE("crypt failed");
		return NULL;
	}

	/* crypt() output may contain slash character,
	 * which is not legal in Smack labels */
	for (x = label; *x; ++x) {
		if (*x == '/')
			*x = '%';
	}

	return label;
}
/*
 * This function should be called in perm_app_setup_path_internal().
 * After installation of new application (pkg_id) and labeling its shared directory (RW or RO),
 * all others apps installed on system should get rules to this shared directory.
 * This function will add and store those rules in rule-file of new installed app (pkg_id)
 */
static int add_other_apps_rules_for_shared_dir(const char *pkg_id, const char *type_of_shared_dir, const char *shared_dir_label)
{
	C_LOGD("Enter function: %s", __func__);

	int ret;
	int fd AUTO_CLOSE;
	char *smack_path AUTO_FREE;
	char *smack_rules_file_path AUTO_FREE;
	struct smack_accesses* smack AUTO_SMACK_FREE;

	ret = load_smack_from_file(pkg_id, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS ) {
		C_LOGE("load_smack_from_file failed: %d", ret);
		return ret;
	}

	ret = asprintf(&smack_rules_file_path, TOSTRING(SHAREDIR)"/%s", type_of_shared_dir);
	if (ret < 0) {
		C_LOGE("asprintf failed");
		return PC_ERR_MEM_OPERATION;
	}

	ret = perm_to_smack_from_file(smack, shared_dir_label, SMACK_SHARED_DIR_LABEL_TEMPLATE, smack_rules_file_path);
	if (ret != PC_OPERATION_SUCCESS ) {
		C_LOGE("perm_to_smack_from_file failed: %d", ret);
	}

	if (have_smack() && smack_accesses_apply(smack)) {
		C_LOGE("smack_accesses_apply failed");
		return PC_ERR_INVALID_OPERATION;
	}

	if (smack_accesses_save(smack, fd)) {
		C_LOGE("smack_accesses_save failed");
		return PC_ERR_INVALID_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

/* Add all anti-viruses RWX access to specific label.
 * This function should be used grant anti-viruses access to
 * public RO/group RW shared folder
 * const char *path param is used only for logs.
 */
static int add_all_anti_viruses_access_to_label(const char *label, const char *path)
{
	int i;
	int ret;
	int avs_ids_cnt = 0;
	char **avs_ids AUTO_FREE;

	/* Add all anti-viruses RWX access to public RO shared folder */
	ret = get_all_avs_ids(&avs_ids, &avs_ids_cnt);
	if (ret != PC_OPERATION_SUCCESS ) {
		C_LOGE("get_all_avs_ids failed.");
		return ret;
	}
	for (i = 0; i < avs_ids_cnt; ++i) {
		SECURE_C_LOGD("Allowing anti-virus %s to RWX access public path %s", avs_ids[i], path);
		ret = app_add_rule(avs_ids[i], label, "rwx");
		if (ret != PC_OPERATION_SUCCESS ) {
			C_LOGE("app_add_rule failed");
			while (i < avs_ids_cnt)
				free(avs_ids[i++]);
			return ret;
		}
		free(avs_ids[i]);
	}

	return PC_OPERATION_SUCCESS;
}

/* FIXME: remove this pragma once deprecated API is deleted */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static int perm_app_setup_path_internal(const char* pkg_id, const char* path, app_path_type_t app_path_type, va_list ap)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, path=%s, app_path_type=%d",
				__func__, pkg_id, path, app_path_type);

	if(path == NULL) {
		C_LOGE("Invalid argument path.");
		return PC_ERR_INVALID_PARAM;
	}

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid pkg_id.");
		SECURE_C_LOGE("Invalid pkg_id %s", pkg_id);
		return PC_ERR_INVALID_PARAM;
	}

	switch (app_path_type) {
	case APP_PATH_PRIVATE:
		C_LOGD("app_path_type is APP_PATH_PRIVATE.");
		return app_label_dir(pkg_id, path);

	case APP_PATH_GROUP_RW: {
		C_LOGD("app_path_type is APP_PATH_GROUP_RW.");
		int ret;
		const char *shared_label;

		shared_label = va_arg(ap, const char *);

		if (!smack_label_is_valid(shared_label)) {
			C_LOGE("Invalid shared_label.");
			return PC_ERR_INVALID_PARAM;
		}

		if (strcmp(pkg_id, shared_label) == 0) {
			C_LOGE("pkg_id equals shared_label.");
			return PC_ERR_INVALID_PARAM;
		}

		ret = app_label_shared_dir(pkg_id, shared_label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("app_label_shared_dir failed: %d", ret);
			return ret;
		}

		/* FIXME: This should be in some kind of transaction/lock */
		ret = db_add_groups_dir(shared_label);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("db_add_groups_dir failed.");
			return ret;
		}

		/* Add all anti-viruses RWX access to groups RW shared folder */
		ret = add_all_anti_viruses_access_to_label(shared_label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("add_all_anti_viruses_access_to_label failed");
			return ret;
		}

		return add_other_apps_rules_for_shared_dir(pkg_id, PATH_RULES_GROUP_RW, shared_label);
	}

	case APP_PATH_PUBLIC_RO: {
		C_LOGD("app_path_type is APP_PATH_PUBLIC_RO.");
		char **app_ids AUTO_FREE;
		int app_ids_cnt = 0;
		const char *label;
		int i, ret;

		C_LOGD("New public RO path %s", path);
		label = smack_label_for_path(pkg_id, path);
		if (label == NULL) {
			C_LOGE("smack_label_for_path failed.");
			return PC_ERR_INVALID_OPERATION;
		}

		C_LOGD("Generated label '%s' for public RO path %s", label, path);
		ret = app_label_shared_dir(pkg_id, label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("app_label_shared_dir failed.");
			return ret;
		}

		/* FIXME: This should be in some kind of transaction/lock */
		ret = db_add_public_dir(label);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("db_add_public_dir failed.");
			return ret;
		}

		ret = get_all_apps_ids(&app_ids, &app_ids_cnt);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("get_all_aps_ids failed.");
			return ret;
		}

		for (i = 0; i < app_ids_cnt; ++i) {
			SECURE_C_LOGD("Allowing app %s to access public path %s", app_ids[i], path);
			ret = app_add_rule(app_ids[i], label, "rx");
			if (ret != PC_OPERATION_SUCCESS) {
				C_LOGE("app_add_rule failed");
				while (i < app_ids_cnt)
					free(app_ids[i++]);
				return ret;
			}
			free(app_ids[i]);
		}

		/* Add all anti-viruses RWX access to public RO shared folder */
		ret = add_all_anti_viruses_access_to_label(label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("add_all_anti_viruses_access_to_label failed");
			return ret;
		}

		return add_other_apps_rules_for_shared_dir(pkg_id, PATH_RULES_PUBLIC_RO, label);
	}

	case APP_PATH_SETTINGS_RW:
	{
		C_LOGD("app_path_type is APP_PATH_SETTINGS_RW.");
		char **app_ids AUTO_FREE;
		int app_ids_cnt = 0;
		const char *label;
		int i;
		int ret;

		/*get path id*/
		label = smack_label_for_path(pkg_id, path);
		if (label == NULL) {
			C_LOGE("smack_label_for_path failed.");
			return PC_ERR_INVALID_OPERATION;
		}

		/*set id for path and all subfolders*/
		C_LOGD("Appsetting: generated label '%s' for setting path %s", label, path);
		ret = app_label_shared_dir(pkg_id, label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("Appsetting: app_label_shared_dir failed (%d)", ret);
			return ret;
		}

		/* add path to database */
		/* FIXME: This should be in some kind of transaction/lock */
		ret = add_setting_dir_id_to_databse(label);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("Appsetting: add_setting_dir_id_to_databse failed");
			return ret;
		}

		/*read all apps with appsetting privilege*/
		ret = get_all_appsetting_ids(&app_ids, &app_ids_cnt);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("Appsetting: get_all_appsetting_ids failed");
			return ret;
		}
		C_LOGD("Appsetting: %d appsetting privileged apps registered",
				app_ids_cnt);

		/*give RWX rights to all apps that have appsetting privilege*/
		for (i = 0; i < app_ids_cnt; ++i) {
			C_LOGD("Appsetting: allowing app %s to access setting path %s",
					app_ids[i], label);
			ret = app_add_rule(app_ids[i], label, "rwx");
			if (ret != PC_OPERATION_SUCCESS) {
				C_LOGE("app_add_rule failed");
				while (i < app_ids_cnt)
					free(app_ids[i++]);
				return ret;
			}
			free(app_ids[i]);
		}

		/* Add all anti-viruses RWX access to settings RW shared folder */
		ret = add_all_anti_viruses_access_to_label(label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("add_all_anti_viruses_access_to_label failed");
			return ret;
		}

		return PC_OPERATION_SUCCESS;
	}

	case APP_PATH_ANY_LABEL: {
		C_LOGD("app_path_type is APP_PATH_ANY_LABEL.");
		const char *label = NULL;
		label = va_arg(ap, const char *);
		return app_label_dir(label, path);
	}

	default:
		C_LOGE("app_path_type is invalid.");
		return PC_ERR_INVALID_PARAM;
	}

	return PC_OPERATION_SUCCESS;
}
/* FIXME: remove this pragma once deprecated API is deleted */
#pragma GCC diagnostic warning "-Wdeprecated-declarations"

API int app_setup_path(const char* pkg_id, const char* path, app_path_type_t app_path_type, ...)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, path=%s, app_path_type=%d",
				__func__, pkg_id, path, app_path_type);

	va_list ap;
	int ret;
	va_start( ap, app_path_type );
	ret = perm_app_setup_path_internal( pkg_id, path, app_path_type, ap );
	va_end( ap );
	return ret;
}


API int perm_app_setup_path(const char* pkg_id, const char* path, app_path_type_t app_path_type, ...)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s, path=%s, app_path_type=%d",
				__func__, pkg_id, path, app_path_type);

	va_list ap;
	int ret;
	va_start( ap, app_path_type );
	ret = perm_app_setup_path_internal( pkg_id, path, app_path_type, ap );
	va_end( ap );
	return ret;
}

API int app_add_friend(const char* pkg_id1, const char* pkg_id2)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id1=%s, pkg_id2=%s",
				__func__, pkg_id1, pkg_id2);

	return perm_app_add_friend(pkg_id1, pkg_id2);
}

API int perm_app_add_friend(const char* pkg_id1, const char* pkg_id2)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id1=%s, pkg_id2=%s",
				__func__, pkg_id1, pkg_id2);

	int ret;

	if (!smack_label_is_valid(pkg_id1) || !smack_label_is_valid(pkg_id2)) {
		C_LOGE("Invalid pkg_id1 or pkg_id2.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = app_add_rule(pkg_id1, pkg_id2, "rwxat");
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("app_add_rule failed");
		return ret;
	}

	ret = app_add_rule(pkg_id2, pkg_id1, "rwxat");
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("app_add_rule failed");
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_install(const char* pkg_id)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s",
				__func__, pkg_id);

	return perm_app_install(pkg_id);
}

API int perm_app_install(const char* pkg_id)
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s",
				__func__, pkg_id);

	int ret;
	int fd AUTO_CLOSE;
	char* smack_path AUTO_FREE;
	struct smack_accesses *smack AUTO_SMACK_FREE;

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid param pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = smack_file_name(pkg_id, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("smack_file_name failed.");
		return ret;
	}

	ret = load_smack_from_file(pkg_id, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		return ret;
	}

	ret = add_app_id_to_databse(pkg_id);
	if (ret != PC_OPERATION_SUCCESS ) {
		SECURE_C_LOGE("Error while adding app %s to database: %s ", pkg_id, strerror(errno));
		return ret;
	}

	ret = register_app_for_av(pkg_id);
	if (ret != PC_OPERATION_SUCCESS) {
		SECURE_C_LOGE("Error while adding rules for anti viruses to app %s: %s ", pkg_id, strerror(errno));
		return ret;
	}

	ret = register_app_for_appsetting(pkg_id);
	if (ret != PC_OPERATION_SUCCESS) {
		SECURE_C_LOGE("Error while adding rules for setting managers to app %s: %s ", pkg_id, strerror(errno));
		return ret;
	}

	ret = register_app_for_public_dirs(pkg_id, smack);
	if (ret != PC_OPERATION_SUCCESS) {
		SECURE_C_LOGE("Error while adding rules for access to public dirs for app %s: %s ", pkg_id, strerror(errno));
		return ret;
	}

	if (have_smack() && smack_accesses_apply(smack)) {
		C_LOGE("smack_accesses_apply failed");
		return PC_ERR_INVALID_OPERATION;
	}

	if (smack_accesses_save(smack, fd)) {
		C_LOGE("smack_accesses_save failed");
		return PC_ERR_INVALID_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_uninstall(const char* pkg_id)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s",
				__func__, pkg_id);

	return perm_app_uninstall(pkg_id);
}

API int perm_app_uninstall(const char* pkg_id)
{
	// TODO: When real database will be used, then this function should remove app_id
	//       from database.
	//       It also should remove rules like: "anti_virus_label app_id rwx".
	SECURE_C_LOGD("Entering function: %s. Params: pkg_id=%s", __func__, pkg_id);
	char* smack_path AUTO_FREE;
	int ret;

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid param pkg_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = smack_file_name(pkg_id, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("smack_file_name failed.");
		return ret;
	}

	if (unlink(smack_path)) {
		C_LOGE("unlink failed (error: %s)", strerror(errno));
		return PC_OPERATION_SUCCESS;
	}

	ret = app_uninstall_remove_early_rules(pkg_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("app_uninstall_remove_early_rules failed.");
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

static int save_rules(int fd, struct smack_accesses* accesses) {
	SECURE_C_LOGD("Entering function: %s. Params: fd=%d", __func__, fd);

	if (flock(fd, LOCK_EX)) {
		C_LOGE("flock failed (error: %s)", strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	if (smack_accesses_save(accesses, fd)) {
		C_LOGE("smack_accesses_save failed");
		return PC_ERR_FILE_OPERATION;
	}
	return PC_OPERATION_SUCCESS ;
}

static int label_valid(const char *label) {
	if (label == NULL)
		return 0;

	// allow ~APP~ template when adding new feature
	if (strcmp(label, SMACK_APP_LABEL_TEMPLATE) == 0)
		return 1;

	return smack_label_is_valid(label);
}

static int validate_and_add_rule(char* rule, struct smack_accesses* accesses) {
	SECURE_C_LOGD("Entering function: %s. Params: rule=%s",
				__func__, rule);

	const char* subject = NULL;
	const char* object = NULL;
	const char* access = NULL;
	char* saveptr = NULL;

	subject = strtok_r(rule, " \t\n", &saveptr);
	object = strtok_r(NULL, " \t\n", &saveptr);
	access = strtok_r(NULL, " \t\n", &saveptr);

	// check rule validity
	if (access == NULL ||
		strtok_r(NULL, " \t\n", &saveptr) != NULL ||
		!label_valid(subject) ||
		!label_valid(object))
	{
		C_LOGE("Incorrect rule format: %s", rule);
		return PC_ERR_INVALID_PARAM;
	}

	if (smack_accesses_add(accesses, subject, object, access)) {
		C_LOGE("smack_accesses_add failed");
		return PC_ERR_INVALID_OPERATION;
	}
	return PC_OPERATION_SUCCESS ;
}

static int parse_and_save_rules(const char** smack_rules,
		struct smack_accesses* accesses, const char* feature_file) {
	SECURE_C_LOGD("Entering function: %s. Params: feature_file=%s",
				__func__, feature_file);

	size_t i = 0;
	int fd = 0;
	int ret = PC_OPERATION_SUCCESS;
	char* tmp = NULL;

	for (i = 0; smack_rules[i] != NULL ; i++) {
		// ignore empty lines
		if (strspn(smack_rules[i], " \t\n") == strlen(smack_rules[i]))
			continue;

		tmp = strdup(smack_rules[i]);
		ret = validate_and_add_rule(tmp, accesses);
		free(tmp);
		if (ret != PC_OPERATION_SUCCESS )
			return ret;
	}

	// save to file
	fd = open(feature_file, O_CREAT | O_WRONLY, 0644);
	if (fd == -1) {
		SECURE_C_LOGE("Unable to create file %s. (error: %s)", feature_file, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	ret = save_rules(fd, accesses);
	close(fd);
	return ret;
}

static int save_gids(FILE* file, const gid_t* list_of_db_gids, size_t list_size) {
	SECURE_C_LOGD("Entering function: %s.", __func__);
	int ret = PC_OPERATION_SUCCESS;
	int written = 0;
	size_t i = 0;

	if (file == NULL) {
		C_LOGE("Unable to create file. Error: %s", strerror(errno));
		return PC_ERR_FILE_OPERATION;	// TODO remove smack accesses?
	}

	if(-1 == fchmod(fileno(file), 0644)) {
		C_LOGE("Unable to chmod file. Error: %s", strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	for (i = 0; i < list_size ; ++i) {
		written = fprintf(file, "%u\n", list_of_db_gids[i]);
		if (written <= 0) {
			C_LOGE("fprintf failed for file. Error: %s", strerror(errno));
			ret = PC_ERR_FILE_OPERATION;
			break;
		}
	}
	return ret;
}

API int add_api_feature(app_type_t app_type,
                        const char* api_feature_name,
                        const char** smack_rules,
                        const gid_t* list_of_db_gids,
                        size_t list_size)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d, api_feature_name=%s",
				__func__, app_type, api_feature_name);

    return perm_add_api_feature(app_type, api_feature_name, smack_rules, list_of_db_gids, list_size);
}

API int perm_add_api_feature(app_type_t app_type,
						const char* api_feature_name,
						const char** smack_rules,
						const gid_t* list_of_db_gids,
						size_t list_size) {
	SECURE_C_LOGD("Entering function: %s. Params: app_type=%d, api_feature_name=%s",
				__func__, app_type, api_feature_name);

	int ret = PC_OPERATION_SUCCESS;
	char* smack_file AUTO_FREE;
	char* dac_file AUTO_FREE;
	struct smack_accesses* accesses = NULL;
	FILE* file = NULL;

	// TODO check process capabilities

	// get feature SMACK file name
	ret = perm_file_path(&smack_file, app_type, api_feature_name, ".smack", 0);
	if (ret != PC_OPERATION_SUCCESS || !smack_file ) {
		C_LOGE("perm_file_path failed.");
		return ret;
	}

	// check if feature exists
	if (file_exists(smack_file)) {
		C_LOGE("Feature file %s already exists", smack_file);
		return PC_ERR_INVALID_PARAM;
	}

	// check .dac existence only if gids are supported
	if (list_of_db_gids && list_size > 0) {
		// get feature DAC file name
		ret = perm_file_path(&dac_file, app_type, api_feature_name, ".dac", 0);
		if (ret != PC_OPERATION_SUCCESS || !dac_file ) {
			C_LOGE("perm_file_path failed.");
			return ret;
		}

		// check if feature exists
		if (file_exists(dac_file)) {
			C_LOGE("Feature file %s already exists", dac_file);
			return PC_ERR_INVALID_PARAM;
		}
	}

	// parse & save rules
	if (smack_rules) {
		if (smack_accesses_new(&accesses)) {
			C_LOGE("smack_acceses_new failed");
			return PC_ERR_MEM_OPERATION;
		}

		ret = parse_and_save_rules(smack_rules, accesses, smack_file);
		smack_accesses_free(accesses);
	}

	// go through gid list
	if (ret == PC_OPERATION_SUCCESS && list_of_db_gids && list_size > 0) {
		// save to file
		SECURE_C_LOGD("Opening file %s.", dac_file);
		file = fopen(dac_file, "w+");
		ret = save_gids(file, list_of_db_gids, list_size);
		fclose(file);
	}

	// remove both files in case of failure
	if (ret != PC_OPERATION_SUCCESS) {
		unlink(smack_file);
		if (dac_file) {
			unlink(dac_file);
		}
	}

	return ret;
}

/**
 * This function is marked as deprecated and will be removed
 */
API int app_register_av(const char* app_av_id)//deprecated
{
	SECURE_C_LOGD("Entering function: %s. Params: app_av_id=%s",
				__func__, app_av_id);

	int ret;
	int fd AUTO_CLOSE;
	char* smack_path AUTO_FREE;
	struct smack_accesses* smack AUTO_SMACK_FREE;

	if(app_av_id == NULL) {
		C_LOGE("Invalid param app_av_id.");
		return PC_ERR_INVALID_PARAM;
	}

	ret = load_smack_from_file(app_av_id, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS ) {
		C_LOGE("load_smack_from_file failed");
		return ret;
	}

	ret = app_register_av_internal(app_av_id, smack);
	if (PC_OPERATION_SUCCESS != ret) {
		C_LOGE("app_register_av_internal failed");
		return ret;
	}

	// Add permisions from OSP_antivirus.smack file
	ret = perm_to_smack(smack, app_av_id, APP_TYPE_OSP, TIZEN_PRIVILEGE_ANTIVIRUS);
	if (PC_OPERATION_SUCCESS != ret) {
		C_LOGE("perm_to_smack failed");
		return ret;
	}

	// Add permisions from OSP_antivirus.dac file
	ret = perm_to_dac(app_av_id, APP_TYPE_OSP, TIZEN_PRIVILEGE_ANTIVIRUS);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("perm_to_dac failed");
		return ret;
	}

	if (have_smack() && smack_accesses_apply(smack)) {
		C_LOGE("smack_accesses_apply failed");
		ret = PC_ERR_INVALID_OPERATION;
		return ret;
	}

	if (smack_accesses_save(smack, fd)) {
		C_LOGE("smack_accesses_save failed");
		ret = PC_ERR_INVALID_OPERATION;
		return ret;
	}

	return ret;
}
