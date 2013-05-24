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

#define SMACK_RULES_DIR  "/etc/smack/accesses.d/"

#define SMACK_APP_LABEL_TEMPLATE "~APP~"
#define SMACK_SRC_FILE_SUFFIX   "_src_file"
#define SMACK_SRC_DIR_SUFFIX    "_src_dir"
#define SMACK_DATA_SUFFIX       "_data"
#define WRT_BASE_DEVCAP         "WRT"
#define WRT_CLIENT_PATH         "/usr/bin/wrt-client"
#define ACC_LEN                 5
#define TIZEN_PRIVILEGE_ANTIVIRUS "http://tizen.org/privilege/antivirus"
#define TIZEN_PRIVILEGE_APPSETTING "http://tizen.org/privilege/appsetting"



typedef struct {
	char user_name[10];
	int uid;
	int gid;
	char home_dir[64];
	char group_list[64];
} new_user;

typedef struct state_node_t {
	char *key, *value;
} state_node;

static void *state_tree = NULL;

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

int state_tree_cmp(const void *first, const void *second)
{
	return strcmp(((state_node*)first)->key,
			((state_node*)second)->key);
}

int state_tree_push(const char* key_param, const char* value_param)
{
	state_node *node = malloc(sizeof(state_node));
	char *key = strdup(key_param);
	char *value = strdup(value_param);

	if (!node || !key || !value) {
		free(node);
		free(key);
		free(value);
		return PC_ERR_MEM_OPERATION;
	}

	node->key = key;
	node->value = value;

	if (NULL != tfind(node, &state_tree, state_tree_cmp)){
		free(node);
		free(key);
		free(value);
		return PC_OPERATION_SUCCESS; // 04.2013 Temporary fix. Allow for multiple call of app_give_access
	}

	tsearch(node, &state_tree, state_tree_cmp);
	return PC_OPERATION_SUCCESS;
}

char* state_tree_pop_new(char *key)
{
	state_node search, *node;
	void *wtf;
	char *value;
	search.key = key;
	search.value = NULL;

	wtf = tfind(&search, &state_tree, state_tree_cmp);
	if (!wtf)
		return NULL;

	node = *(state_node**)wtf;
	if (!node)
		return NULL;

	tdelete(node, &state_tree, state_tree_cmp);

	value = node->value;
	free(node->key);
	free(node);
	return value;
}

int state_save(const char *subject, const char *object, const char *perm)
{
	char *key = NULL;
	if (-1 == asprintf(&key, "%s|%s", subject, object)) {
		C_LOGE("Error in %s: asprintf failed.", __func__);
		return PC_ERR_INVALID_OPERATION;
	}
	int ret = state_tree_push(key, perm);
	free(key);
	return ret;
}

int state_restore(const char* subject, const char* object)
{
	char *key AUTO_FREE;
	char *perm AUTO_FREE;
	struct smack_accesses *smack AUTO_SMACK_FREE;

	if (-1 == asprintf(&key, "%s|%s", subject, object)) {
		C_LOGE("Error in %s: asprintf failed.", __func__);
		return PC_ERR_INVALID_OPERATION;
	}

	perm = state_tree_pop_new(key);
	if (!perm) {
		C_LOGE("Error in %s: state_tree_pop_new failed - no data for subject=%s object=%s.", __func__, subject, object);
		return PC_ERR_INVALID_OPERATION;
	}

	if (smack_accesses_new(&smack)) {
		C_LOGE("Error in %s: smack_accesses_new failed - memory error.", __func__);
		return PC_ERR_MEM_OPERATION;
	}

	if (smack_accesses_add(smack, subject, object, perm)) {
		C_LOGE("Error in %s: smack_accesses_add failed.", __func__);
		return PC_ERR_MEM_OPERATION;
	}

	if (smack_accesses_apply(smack)) {
		C_LOGE("Error in %s: smack_accesses_apply failed - operation not permitted.", __func__);
		return PC_ERR_NOT_PERMITTED;
	}

	return PC_OPERATION_SUCCESS;
}

static inline int have_smack(void)
{
	static int have_smack = -1;

	if (-1 == have_smack) {
		if (NULL == smack_smackfs_path()) {
			C_LOGD("Libprivilage-control: no smack found on phone");
			have_smack = 0;
		} else {
			C_LOGD("Libprivilege-control: found smack on phone");
			have_smack = 1;
		}
	}

	return have_smack;
}

API int control_privilege(void)
{
	C_LOGD("Enter function: %s", __func__);
	if(getuid() == APP_UID)	// current user is 'app'
		return PC_OPERATION_SUCCESS;

	if(set_app_privilege("org.tizen.", NULL, NULL) == PC_OPERATION_SUCCESS)
		return PC_OPERATION_SUCCESS;
	else
		return PC_ERR_NOT_PERMITTED;
}



static int get_user_groups(uid_t user_id, int *nbgroup, gid_t **groups_list)
{
	gid_t *groups = NULL;
	struct passwd * pw;
	C_LOGD("Enter function: %s", __func__);

	if ((!groups_list) || (!nbgroup))
		return PC_ERR_INVALID_OPERATION;
	pw = getpwuid(user_id);
	if(!pw) {
		C_LOGE("getgrouplist fails : Invalid User ID %d",user_id);
		return PC_ERR_INVALID_OPERATION;
	}
	*nbgroup = 0;
	//First call is done with *ngroup = 0 to get the number of groups found for the user (Usefull for next malloc operation). It should return -1 in this case.
	if (getgrouplist(pw->pw_name,  pw->pw_gid, groups, nbgroup) != -1)
		return PC_ERR_INVALID_OPERATION;

	C_LOGD("getgrouplist %s user is member of %d groups ",pw->pw_name,*nbgroup);
	groups = malloc(*nbgroup * sizeof (gid_t));
	if (!groups)
		return PC_ERR_INVALID_OPERATION;
	//Second call is done with the suitable ngroup value and structure groups allocated.
	if (getgrouplist(pw->pw_name,  pw->pw_gid, groups, nbgroup) == -1) {
		free(groups);
		C_LOGE("getgrouplist fails %d",nbgroup);
		return PC_ERR_INVALID_OPERATION;
	}
	*groups_list = groups;
	return  PC_OPERATION_SUCCESS;
}

/**
 * TODO: this function should be moved to libsmack in open-source.
 */
API int get_smack_label_from_process(pid_t pid, char smack_label[SMACK_LABEL_LEN + 1])
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	int fd AUTO_CLOSE;
	int PATH_MAX_LEN = 64;
	char path[PATH_MAX_LEN + 1];

	if (pid < 0) {
		ret = PC_ERR_INVALID_PARAM;
		goto out;
	}

	bzero(smack_label, SMACK_LABEL_LEN + 1);
	if (!have_smack()) { // If no smack just return success with empty label
		C_LOGD("No SMACK. Return empty label");
		ret = PC_OPERATION_SUCCESS;
		goto out;
	}

	bzero(path, PATH_MAX_LEN + 1);
	snprintf(path, PATH_MAX_LEN, "/proc/%d/attr/current", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		C_LOGE("cannot open file %s (errno: %s)", path, strerror(errno));
		ret = PC_ERR_FILE_OPERATION;
		goto out;
	}

	ret = read(fd, smack_label, SMACK_LABEL_LEN);
	if (ret < 0) {
		C_LOGE("cannot read from file %s", path);
		ret = PC_ERR_FILE_OPERATION;
		goto out;
	}

	ret = PC_OPERATION_SUCCESS;

out:
	return ret;
}

API int smack_pid_have_access(pid_t pid,
								const char* object,
								const char *access_type)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	char pid_subject_label[SMACK_LABEL_LEN + 1];
	cap_t cap;
	cap_flag_value_t cap_v;

	if (!have_smack()) {
		C_LOGD("No SMACK. Return access granted");
		return 1;
	}

	if (pid < 0 || object == NULL || strlen(object) == 0 ||
			access_type == NULL || strlen(access_type) == 0) {
		C_LOGE("Invalid param");
		return -1;
	}

	//get SMACK label of process
	ret = get_smack_label_from_process(pid, pid_subject_label);
	if (PC_OPERATION_SUCCESS != ret) {
		C_LOGE("get_smack_label_from_process %d failed: %d", pid, ret);
		return -1;
	}
	C_LOGD("pid %d have label: %s", pid, pid_subject_label);

	// if read empty label then do not call smack_have_access()
	if (pid_subject_label[0] != '\0') {
		ret = smack_have_access(pid_subject_label, object, access_type);
		if ( -1 == ret) {
			C_LOGE("smack_have_access failed");
			return -1;
		}
		if ( 1 == ret ) { // smack_have_access return 1 (access granted)
			C_LOGD("smack_have_access return 1 (access granted)");
			return 1;
		}
	}

	// smack_have_access return 0 (access denied). Now CAP_MAC_OVERRIDE should be checked
	C_LOGD("smack_have_access return 0 (access denied)");
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
		C_LOGD("pid %d have CAP_MAC_OVERRIDE", pid);
		return 1;

	} else {
		C_LOGD("pid %d have no CAP_MAC_OVERRIDE", pid);
		return 0;
	}
}

static int set_dac(const char *smack_label, const char *pkg_name)
{
	C_LOGD("Enter function: %s", __func__);
	uid_t t_uid = -1;		// uid of current process
	gid_t *glist = NULL;	// group list
	int glist_cnt = 0;		// for group list
	int result;
	int i;
	new_user usr;
	unsigned *additional_gids = NULL;

	/*
	 * initialize user structure
	 */
	C_LOGD("initialize user structure");
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
		}

		/*
		 * get group information
		 */
		C_LOGD("get group information");
		if (get_user_groups(usr.uid, &glist_cnt, &glist)) {
			result = PC_ERR_FILE_OPERATION;	// return -1
			goto error;
		}
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
					C_LOGE("Cannot allocate memory");
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
			C_LOGD("glist [ %d ] = %d", i, glist[i]);
		}
		C_LOGD("setgroups()");
		if(setgroups(glist_cnt, glist) != 0)
		{
			C_LOGE("[ERR] setgrouops fail\n");
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
			C_LOGE("[ERR] fail to execute setgid().");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}
		if(setuid(usr.uid) != 0)	// fail
		{
			C_LOGE("[ERR] fail to execute setuid().");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}

		C_LOGD("setenv(): USER = %s, HOME = %s", usr.user_name, usr.home_dir);
		if(setenv("USER", usr.user_name, 1) != 0)	//fail
		{
			C_LOGE("[ERR] fail to execute setenv() [USER].");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}
		if(setenv("HOME", usr.home_dir, 1) != 0)	// fail
		{
			C_LOGE("[ERR] fail to execute setenv() [HOME].");
			result = PC_ERR_INVALID_OPERATION;
			goto error;
		}
	}
	else	// current user is not only 'root' but 'app'
	{
		C_LOGE("[ERR] current user is NOT root\n");
		result = PC_ERR_NOT_PERMITTED;	// return -3
		goto error;
	}

	result = PC_OPERATION_SUCCESS;

error:
	if(glist != NULL)
		free(glist);
	free(additional_gids);

	return result;
}

/**
 * Set process SMACK label from EXEC label of a file.
 * This function is emulating EXEC label behaviour of SMACK for programs
 * run by dlopen/dlsym instead of execv.
 *
 * @param path file path to take label from
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
static int set_smack_from_binary(char **smack_label, const char* path, app_type_t type)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;

	C_LOGD("Path: %s", path);

	*smack_label = NULL;
	if(type == APP_TYPE_WGT
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

	if (*smack_label == NULL) {
		/* No label to set, just return with success */
		C_LOGD("No label to set, just return with success");
		ret = PC_OPERATION_SUCCESS;
	}
	else {
		C_LOGD("label = %s", *smack_label);
		if (have_smack()) {
			ret = smack_set_label_for_self(*smack_label);
			C_LOGD("smack_set_label_for_self returned %d", ret);
		} else
			ret = PC_OPERATION_SUCCESS;
	}

	return ret;
}

static int is_widget(const char* path)
{
	C_LOGD("Enter function: %s", __func__);
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
	C_LOGD("buf = %s", buf);

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
	C_LOGD("Enter function: %s", __func__);
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
/*
static const char* parse_widget_id(const char* path)
{
	C_LOGD("Enter function: %s", __func__);
	const char* basename = strrchr(path, '/');

	if (basename == NULL)
		basename = path;
	else
		++basename;

	C_LOGD("return widget id: %s", basename);
	return basename;
}*/

API int set_app_privilege(const char* name, const char* type, const char* path)
{
	C_LOGD("Enter function: %s", __func__);
	C_LOGD("Function params: name = %s, type = %s, path = %s", name, type, path);
	char *smack_label AUTO_FREE;
	int ret = PC_OPERATION_SUCCESS;

	if (path != NULL) {
		ret = set_smack_from_binary(&smack_label, path, verify_app_type(type, path));
		if (ret != PC_OPERATION_SUCCESS)
			return ret;
	}

	return set_dac(smack_label, name);
}

API int set_privilege(const char* pkg_name)
{
	C_LOGD("Enter function: %s", __func__);
	return set_app_privilege(pkg_name, NULL, NULL);
}

static inline const char* app_type_name(app_type_t app_type)
{
	switch (app_type) {
	case APP_TYPE_WGT:
		return "WRT";
	case APP_TYPE_OSP:
		return "OSP";
	case APP_TYPE_WGT_PARTNER:
		return "WRT_partner";
	case APP_TYPE_WGT_PLATFORM:
		return "WRT_platform";
	case APP_TYPE_OSP_PARTNER:
		return "OSP_partner";
	case APP_TYPE_OSP_PLATFORM:
		return "OSP_platform";
	default:
		return NULL;
	}
}

static inline const char* app_type_group_name(app_type_t app_type)
{
	switch (app_type) {
	case APP_TYPE_WGT:
	case APP_TYPE_WGT_PARTNER:
	case APP_TYPE_WGT_PLATFORM:
		return "WRT";
	case APP_TYPE_OSP:
	case APP_TYPE_OSP_PARTNER:
	case APP_TYPE_OSP_PLATFORM:
		return "OSP";
	default:
		return NULL;
	}
}

/**
 * This function changes permission URI to basename for file name.
 * For e.g. from http://tizen.org/privilege/contact.read will be
 * created basename : org.tizen.privilege.contact.read
 */

static int base_name_from_perm(const char *perm, char **name) {
	iri_t *ip = NULL;
	char *host_dot = NULL;
	char *rest_slash = NULL;
	int ret;

	ip = iri_parse(perm);
	if (ip == NULL || ip->host == NULL) {
		C_LOGE("Bad permission format : %s", perm);
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

static int perm_file_path(char** path, app_type_t app_type, const char* perm, const char *suffix)
{
	const char* app_type_prefix = NULL;
	char* perm_basename = NULL;
	int ret = 0;

	if (perm == NULL || strlen(perm) == 0) {
		C_LOGE("empty permission name");
		return PC_ERR_INVALID_PARAM;
	}

	app_type_prefix = app_type_group_name(app_type);

	ret = base_name_from_perm(perm, &perm_basename);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Couldn't get permission basename");
		return ret;
	}

	ret = asprintf(path, TOSTRING(SHAREDIR) "/%s%s%s%s",
			app_type_prefix ? app_type_prefix : "", app_type_prefix ? "_" : "",
			perm_basename, suffix);
	if (ret == -1) {
		C_LOGE("asprintf failed");
		return PC_ERR_MEM_OPERATION;
	}

	C_LOGD("Path : %s", *path);

	return PC_OPERATION_SUCCESS;
}

static bool file_exists(const char* path) {
	FILE* file = fopen(path, "r");
	if (file) {
		fclose(file);
		return true;
	}
	return false;
}

static int perm_to_smack(struct smack_accesses* smack, const char* app_label, app_type_t app_type, const char* perm)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	char* path AUTO_FREE;
	char* format_string AUTO_FREE;
	FILE* file AUTO_FCLOSE;
	char smack_subject[SMACK_LABEL_LEN + 1];
	char smack_object[SMACK_LABEL_LEN + 1];
	char smack_accesses[10];

	// get file name for permission (devcap)
	ret = perm_file_path(&path, app_type, perm, ".smack");
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGD("No smack config file for permission %s", perm);
		return ret;
	}

	if (asprintf(&format_string,"%%%ds %%%ds %%%lus\n",
			SMACK_LABEL_LEN, SMACK_LABEL_LEN, (unsigned long)sizeof(smack_accesses)) == -1) {
		C_LOGE("asprintf failed");
		return PC_ERR_MEM_OPERATION;
	}

	file = fopen(path, "r");
	C_LOGD("path = %s", path);
	if (file == NULL) {
		C_LOGE("fopen failed");
		return PC_OPERATION_SUCCESS;
	}

	while (fscanf(file, format_string, smack_subject, smack_object, smack_accesses) == 3) {
		if (!strcmp(smack_subject, SMACK_APP_LABEL_TEMPLATE))
			strcpy(smack_subject, app_label);

		if (!strcmp(smack_object, SMACK_APP_LABEL_TEMPLATE))
			strcpy(smack_object, app_label);

		C_LOGD("smack_accesses_add_modify (subject: %s, object: %s, access: %s)", smack_subject, smack_object, smack_accesses);
		if (smack_accesses_add_modify(smack, smack_subject, smack_object, smack_accesses, "") != 0) {
			C_LOGE("smack_accesses_add_modify failed");
			return PC_ERR_INVALID_OPERATION;
		}
	}

	return PC_OPERATION_SUCCESS;
}

static int perm_to_dac(const char* app_label, app_type_t app_type, const char* perm)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	char* path AUTO_FREE;
	FILE* file AUTO_FCLOSE;
	int gid;

	ret = perm_file_path(&path, app_type, perm, ".dac");
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGD("No dac config file for permission %s", perm);
		return ret;
	}

	file = fopen(path, "r");
	C_LOGD("path = %s", path);
	if (file == NULL) {
		C_LOGE("fopen failed");
		return PC_OPERATION_SUCCESS;
	}

	while (fscanf(file, "%d\n", &gid) == 1) {
		C_LOGD("Adding app_id %s to group %d", app_label, gid);
		ret = add_app_gid(app_label, gid);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("sadd_app_gid failed");
			return ret;
		}
	}

	return PC_OPERATION_SUCCESS;
}

static int label_all(const FTSENT* ftsent)
{
	return DECISION_LABEL;
}

static int label_execs(const FTSENT* ftsent)
{
	C_LOGD("Mode: %d", ftsent->fts_statp->st_mode);
	// label only regular executable files
	if (S_ISREG(ftsent->fts_statp->st_mode) && (ftsent->fts_statp->st_mode & S_IXUSR))
		return DECISION_LABEL;
	return DECISION_SKIP;
}

static int label_dirs(const FTSENT* ftsent)
{
	// label only directories
	if (S_ISDIR(ftsent->fts_statp->st_mode))
		return DECISION_LABEL;
	return DECISION_SKIP;
}

static int label_links_to_execs(const FTSENT* ftsent)
{
	struct stat buf;
	char* target AUTO_FREE;

	// check if it's a link
	if ( !S_ISLNK(ftsent->fts_statp->st_mode))
		return DECISION_SKIP;

	target = realpath(ftsent->fts_path, NULL);
	if (!target) {
		C_LOGE("Getting link target for %s failed. Error %s", ftsent->fts_path, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}
	if (-1 == stat(target, &buf)) {
		C_LOGE("stat failed for %s, error: %s",target, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}
	// skip if link target is not a regular executable file
	if (buf.st_mode != (buf.st_mode | S_IXUSR | S_IFREG)) {
		C_LOGD("%s Is not a regular executable file. Skipping.", target);
		return DECISION_SKIP;
	}

	return DECISION_LABEL;
}

static int dir_set_smack_r(const char *path, const char* label,
		enum smack_label_type type, label_decision_fn fn)
{
	C_LOGD("Enter function: %s", __func__);
	const char* path_argv[] = {path, NULL};
	FTS *fts AUTO_FTS_CLOSE;
	FTSENT *ftsent;
	int ret;

	fts = fts_open((char * const *) path_argv, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL) {
		C_LOGE("fts_open failed");
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
			return ret;
		}

		if (ret == DECISION_LABEL) {
			C_LOGD("smack_lsetlabel (label: %s (type: %d), path: %s)", label, type, ftsent->fts_path);
			if (smack_lsetlabel(ftsent->fts_path, label, type) != 0) {
				C_LOGE("smack_lsetlabel failed");
				return PC_ERR_FILE_OPERATION;
			}
		}
	}

	/* If last call to fts_read() set errno, we need to return error. */
	if (errno != 0) {
		C_LOGE("Last errno: %s", strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}
	return PC_OPERATION_SUCCESS;
}

API char* app_id_from_socket(int sockfd)
{
	C_LOGD("Enter function: %s", __func__);
	if (!have_smack())
		return NULL;

	char* app_id;
	int ret;

	ret = smack_new_label_from_socket(sockfd, &app_id);
	if (ret != 0) {
		C_LOGE("smack_new_label_from_socket failed");
		return NULL;
	}

	C_LOGD("app_id: %s", app_id);

	return app_id;
}

static int smack_file_name(const char* app_id, char** path)
{
	if (asprintf(path, SMACK_RULES_DIR "/%s", app_id) == -1) {
		C_LOGE("asprintf failed");
		*path = NULL;
		return PC_ERR_MEM_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

static int load_smack_from_file(const char* app_id, struct smack_accesses** smack, int *fd, char** path)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;

	ret = smack_file_name(app_id, path);
	if (ret != PC_OPERATION_SUCCESS)
		return ret;

	if (smack_accesses_new(smack)) {
		C_LOGE("smack_accesses_new failed");
		return PC_ERR_MEM_OPERATION;
	}

	*fd = open(*path, O_CREAT|O_RDWR, 0644);
	if (*fd == -1) {
		C_LOGE("file open failed: %s", strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	if (flock(*fd, LOCK_EX)) {
		C_LOGE("flock failed");
		return PC_ERR_INVALID_OPERATION;
	}

	if (smack_accesses_add_from_file(*smack, *fd)) {
		C_LOGE("smack_accesses_add_from_file failed");
		return PC_ERR_INVALID_OPERATION;
	}

	/* Rewind the file */
	if (lseek(*fd, 0, SEEK_SET) == -1) {
		C_LOGE("lseek failed");
		return PC_ERR_FILE_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

static int app_add_rule(const char *app_id, const char *object, const char *perm)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	int fd AUTO_CLOSE;
	char *smack_path AUTO_FREE;
	struct smack_accesses* smack AUTO_SMACK_FREE;

	ret = load_smack_from_file(app_id, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		return ret;
	}

	ret = smack_accesses_add_modify(smack, app_id, object, perm, "");
	if (ret == -1) {
		C_LOGE("smack_accesses_add_modify failed");
		return PC_ERR_INVALID_OPERATION;
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


static int
app_register_appsetting(const char *app_id, struct smack_accesses *smack)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	int i;

	char **label_app_list AUTO_FREE;
	char **label_dir_list AUTO_FREE;
	int app_list_len = 0;
	int dir_list_len = 0;

	if (!smack_label_is_valid(app_id))
		return PC_ERR_INVALID_PARAM;


	/* writing appsetting_id (app_id) to "database"*/
	ret = add_appsetting_id_to_databse(app_id);
	if (ret != PC_OPERATION_SUCCESS)
		goto out;


	/* Reading labels of all installed apps from "database"*/
	ret = get_all_apps_ids(&label_app_list, &app_list_len);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while geting data from database");
		goto out;
	}

	/*Add smack rules to rx access each app*/
	for (i = 0; i < app_list_len; ++i) {
		C_LOGD("Appsetting: applying rx rule for %s", label_app_list[i]);
		if (smack_accesses_add(smack, app_id,
				label_app_list[i], "rx") == -1) {
			C_LOGE("smack_accesses_add failed");
			ret = PC_ERR_INVALID_OPERATION;
			goto out;
		}
	}

	/* Reading labels of all registered settings dirs from "database"*/
	ret = get_all_settings_dir_ids(
			&label_dir_list, &dir_list_len);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while geting data from database");
		goto out;
	}
	/*Add smack rules to rwx access each app*/
	for (i = 0; i < dir_list_len; ++i) {
		C_LOGD("Appsetting: applying rwx rule for %s", label_dir_list[i]);
		if (smack_accesses_add(smack, app_id,
				label_dir_list[i], "rwx") == -1) {
			C_LOGE("smack_accesses_add failed");
			ret = PC_ERR_INVALID_OPERATION;
			goto out;
			/* Should we abort adding rules if once
			 * smack_accesses_add will fail?*/
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

static int app_register_av_internal(const char *app_av_id, struct smack_accesses* smack)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	int i;

	char** smack_label_app_list AUTO_FREE;
	int smack_label_app_list_len = 0;

	if (!smack_label_is_valid(app_av_id) || NULL == smack)
		return PC_ERR_INVALID_PARAM;

	// writing anti_virus_id (app_av_id) to "database"
	ret = add_av_id_to_databse(app_av_id);
	if (ret != PC_OPERATION_SUCCESS )
		goto out;

	// Reading labels of all installed apps from "database"
	ret = get_all_apps_ids(&smack_label_app_list, &smack_label_app_list_len);
	if (ret != PC_OPERATION_SUCCESS ) {
		C_LOGE("Error while geting data from database");
		goto out;
	}
	for (i = 0; i < smack_label_app_list_len; ++i) {
		C_LOGD("Applying rwx rule for %s", smack_label_app_list[i]);
		if (smack_accesses_add_modify(smack, app_av_id, smack_label_app_list[i], "wrx", "") == -1) {
			C_LOGE("smack_accesses_add_modify failed");
			ret = PC_ERR_INVALID_OPERATION;
			goto out;
			// Should we abort adding rules if once smack_accesses_add_modify will fail?
		}
	}

out:
	for (i = 0; i < smack_label_app_list_len; ++i) {
		free(smack_label_app_list[i]);
	}

	return ret;
}

/**
 *  This function will check in database labels of all anti viruses
 *  and for all anti viruses will add a rule "anti_virus_label app_id rwx".
 *  This should be call in app_install function.
 */
static int register_app_for_av(const char * app_id)
{
	int ret, i;
	char** smack_label_av_list AUTO_FREE;
	int smack_label_av_list_len = 0;

	// Reading labels of all installed anti viruses from "database"
	ret = get_all_avs_ids(&smack_label_av_list, &smack_label_av_list_len);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while geting data from database");
		return ret;
	}

	// for each anti-virus put rule: "anti_virus_id app_id rwx"
	for (i = 0; i < smack_label_av_list_len; ++i) {
		ret = app_add_rule(smack_label_av_list[i], app_id, "wrx");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("app_add_rule failed");
			goto out;
		}

		free(smack_label_av_list[i]);
	}

	ret = PC_OPERATION_SUCCESS;

out:
	// If something failed, then no all char* smack_label_av_list[i]
	// are deallocated. They must be freed
	for(; i<smack_label_av_list_len; ++i) {
		free(smack_label_av_list[i]);
	}

	return ret;
}

/**
 *  This function will check in database labels of all setting applications
 *  and for all of them will add a rule "appsetting_id app_id rwx".
 *  This should be call in app_install function.
 */
static int register_app_for_appsetting(const char *app_id)
{
	C_LOGD("Enter function: %s",__func__);
	int ret, i;
	char **smack_label_list AUTO_FREE;
	int smack_label_list_len = 0;

	/* Reading labels of all installed setting managers from "database"*/
	ret = get_all_appsetting_ids(&smack_label_list, &smack_label_list_len);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while geting data from database");
		return ret;
	}

	/* for each appsetting put rule: "appsetting_id app_id rx"*/
	for (i = 0; i < smack_label_list_len; ++i) {
		C_LOGD("Appsetting: app_add_rule (%s, %s rx)", smack_label_list[i], app_id);
		ret = app_add_rule(smack_label_list[i], app_id, "rx");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("app_add_rule failed");
			goto out;
		}

		free(smack_label_list[i]);
	}

	ret = PC_OPERATION_SUCCESS;

out:
	/* If something failed, then no all char* smack_label_list[i]
	 are deallocated. They must be freed*/
	for (; i < smack_label_list_len; ++i) {
		free(smack_label_list[i]);
	}

	return ret;
}


/**
 *  This function will grant app_id RX access to all public directories and
 *  files, previously designated by app_setup_path(APP_PATH_PUBLIC_RO)
 *  This should be call in app_install function.
 */
static int register_app_for_public_dirs(const char *app_id, struct smack_accesses *smack)
{
	C_LOGD("Enter function: %s", __func__);
	int ret, i;
	char **public_dirs AUTO_FREE;
	int public_dirs_cnt = 0;

	ret = db_get_public_dirs(&public_dirs, &public_dirs_cnt);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while geting data from database");
		return ret;
	}

	for (i = 0; i < public_dirs_cnt; ++i) {
		C_LOGD("Allowing app %s to access public path %s", app_id, public_dirs[i]);
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
	C_LOGD("Enter function: %s", __func__);
	char* smack_path AUTO_FREE;
	int i, ret;
	int fd AUTO_CLOSE;
	struct smack_accesses *smack AUTO_SMACK_FREE;
	const char* base_perm = NULL;

	if (!smack_label_is_valid(app_id))
		return PC_ERR_INVALID_PARAM;

	ret = load_smack_from_file(app_id, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		return ret;
	}

	/* Implicitly enable base permission for an app_type */
	base_perm = app_type_name(app_type);
	if (base_perm) {
		C_LOGD("perm_to_smack params: app_id: %s, %s", app_id, base_perm);
		ret = perm_to_smack(smack, app_id, APP_TYPE_OTHER, base_perm);
		if (ret != PC_OPERATION_SUCCESS){
			C_LOGE("perm_to_smack failed");
			return ret;
		}
	}
	for (i = 0; perm_list[i] != NULL; ++i) {
		C_LOGD("perm_to_smack params: app_id: %s, perm_list[%d]: %s", app_id, i, perm_list[i]);
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

	if (permanent && smack_accesses_save(smack, fd)) {
		C_LOGE("smack_accesses_save failed");
		return PC_ERR_INVALID_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_add_permissions(const char* app_id, const char** perm_list)
{
	C_LOGD("Enter function: %s", __func__);
	return app_add_permissions_internal(app_id, APP_TYPE_OTHER, perm_list, 1);
}

API int app_add_volatile_permissions(const char* app_id, const char** perm_list)
{
	C_LOGD("Enter function: %s", __func__);
	return app_add_permissions_internal(app_id, APP_TYPE_OTHER, perm_list, 0);
}

API int app_enable_permissions(const char* pkg_id, app_type_t app_type, const char** perm_list, bool persistent)
{
	C_LOGD("Enter function: %s", __func__);
	return app_add_permissions_internal(pkg_id, app_type, perm_list, persistent);
}

/* FIXME: this function is only a stub */
API int app_disable_permissions(const char* pkg_id, app_type_t app_type, const char** perm_list)
{
	C_LOGD("Enter function: %s", __func__);
	return PC_OPERATION_SUCCESS;
}

static int app_revoke_permissions_internal(const char* app_id, bool persistent)
{
	C_LOGD("Enter function: %s", __func__);
	char* smack_path AUTO_FREE;
	int ret;
	int fd AUTO_CLOSE;
	struct smack_accesses *smack AUTO_SMACK_FREE;

	if (!smack_label_is_valid(app_id))
		return PC_ERR_INVALID_PARAM;

	ret = load_smack_from_file(app_id, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		return ret;
	}

	if (have_smack() && smack_accesses_clear(smack)) {
		ret = PC_ERR_INVALID_OPERATION;
		C_LOGE("smack_accesses_clear failed");
		return ret;
	}

	if (have_smack() && smack_revoke_subject(app_id)) {
		ret = PC_ERR_INVALID_OPERATION;
		C_LOGE("smack_revoke_subject failed");
		return ret;
	}

	if (persistent && ftruncate(fd, 0) == -1)
		C_LOGE("file truncate failed");

	return PC_OPERATION_SUCCESS;
}

API int app_revoke_permissions(const char* pkg_id)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;

	if (!smack_label_is_valid(pkg_id))
		return PC_ERR_INVALID_PARAM;

	ret = app_revoke_permissions_internal(pkg_id, true);
	if (ret) {
		C_LOGE("Revoking permissions failed");
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_reset_permissions(const char* pkg_id)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;

	if (!smack_label_is_valid(pkg_id))
		return PC_ERR_INVALID_PARAM;

	ret = app_revoke_permissions_internal(pkg_id, false);
	if (ret) {
		C_LOGE("Revoking permissions failed");
		return ret;
	}

	/* Add empty permissions set to trigger re-read of rules */
	return app_enable_permissions(pkg_id, APP_TYPE_OTHER, (const char*[]){NULL}, 0);
}

API int app_label_dir(const char* label, const char* path)
{
	C_LOGD("Enter function: %s", __func__);

	int ret = PC_OPERATION_SUCCESS;

	if (!smack_label_is_valid(label))
		return PC_ERR_INVALID_PARAM;

	//setting access label on everything in given directory and below
	ret = dir_set_smack_r(path, label, SMACK_LABEL_ACCESS, &label_all);
	if (PC_OPERATION_SUCCESS != ret)
		return ret;

	//setting execute label for everything with permission to execute
	ret = dir_set_smack_r(path, label, SMACK_LABEL_EXEC, &label_execs);
	if (PC_OPERATION_SUCCESS != ret)
		return ret;

	//setting execute label for everything with permission to execute
	ret = dir_set_smack_r(path, label, SMACK_LABEL_EXEC, &label_links_to_execs);
	return ret;
}

int smack_get_access_new(const char* subject, const char* object, char** label)
{
	char buff[ACC_LEN] = {'r', 'w', 'x', 'a', 't'};
	char perm[2] = {'-'};
	int i;

	if(!smack_label_is_valid(subject) || !smack_label_is_valid(object) || !label)
		return PC_ERR_INVALID_PARAM;

	for (i=0; i<ACC_LEN; ++i) {
		perm[0] = buff[i];
		int ret = smack_have_access(subject, object, perm);
		if (-1 == ret)
			return PC_ERR_INVALID_OPERATION;
		if (0 == ret)
			buff[i] = '-';
	}

	*label = malloc(ACC_LEN+1);
	if (NULL == *label)
		return PC_ERR_MEM_OPERATION;

	memcpy(*label, buff, ACC_LEN);
	(*label)[ACC_LEN] = 0;
	return PC_OPERATION_SUCCESS;
}

/*
 * This function will be used to allow direct communication between 2 OSP application.
 * This function requires to store "state" with list of added label.
 *
 * Full implementation requires some kind of database. This implemetation works without
 * database so you wont be able to revoke permissions added by different process.
 */
API int app_give_access(const char* subject, const char* object, const char* permissions)
{
	C_LOGD("Enter function: %s", __func__);
	int ret = PC_OPERATION_SUCCESS;
	struct smack_accesses *smack AUTO_SMACK_FREE;
	char *current_permissions AUTO_FREE;

	if (!have_smack())
		return PC_OPERATION_SUCCESS;

	if (!smack_label_is_valid(subject) || !smack_label_is_valid(object)) {
		C_LOGE("Error in %s: invalid param.", __func__);
		return PC_ERR_INVALID_PARAM;
	}

	if (PC_OPERATION_SUCCESS != (ret = smack_get_access_new(subject, object, &current_permissions))) {
		C_LOGE("Error in %s: smack_get_access_new failed.", __func__);
		return ret;
	}

	if (smack_accesses_new(&smack)) {
		C_LOGE("Error in %s: smack_accesses_new failed.", __func__);
		return PC_ERR_MEM_OPERATION;
	}

	if (smack_accesses_add_modify(smack, subject, object, permissions, "")) {
		C_LOGE("Error in %s: smack_accesses_add_modify failed.", __func__);
		return PC_ERR_MEM_OPERATION;
	}

	if (smack_accesses_apply(smack)) {
		C_LOGE("Error in %s: smack_accesses_apply failed.", __func__);
		return PC_ERR_NOT_PERMITTED;
	}

	return state_save(subject, object, current_permissions);
}

/*
 * This function will be used to revoke direct communication between 2 OSP application.
 *
 * Full implementation requires some kind of database. This implemetation works without
 * database so you wont be able to revoke permissions added by different process.
 */
API int app_revoke_access(const char* subject, const char* object)
{
	C_LOGD("Enter function: %s", __func__);
	if (!have_smack())
		return PC_OPERATION_SUCCESS;

	if (!smack_label_is_valid(subject) || !smack_label_is_valid(object)) {
		C_LOGE("Error in %s: invalid param.", __func__);
		return PC_ERR_INVALID_PARAM;
	}

	return state_restore(subject, object);
}

API int app_label_shared_dir(const char* app_label, const char* shared_label, const char* path)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;

	if (!smack_label_is_valid(app_label) || !smack_label_is_valid(shared_label))
		return PC_ERR_INVALID_PARAM;

	if (strcmp(app_label, shared_label) == 0) {
		C_LOGE("app_label equals shared_label");
		return PC_ERR_INVALID_PARAM;
	}

	//setting label on everything in given directory and below
	ret = dir_set_smack_r(path, shared_label, SMACK_LABEL_ACCESS, label_all);
	if(ret != PC_OPERATION_SUCCESS){
		C_LOGE("dir_set_smakc_r failed");
		return ret;
	}

	//setting transmute on dir
	ret = dir_set_smack_r(path, "1", SMACK_LABEL_TRANSMUTE, label_dirs);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("dir_set_smakc_r failed");
		return ret;
	}

	ret = app_add_rule(app_label, shared_label, "rwxat");
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("app_add_rule failed");
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int add_shared_dir_readers(const char* shared_label, const char** app_list)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	int i;

	if (!smack_label_is_valid(shared_label))
				return PC_ERR_INVALID_PARAM;

	for (i = 0; app_list[i] != NULL; i++) {

		if (!smack_label_is_valid(app_list[i]))
					return PC_ERR_INVALID_PARAM;

		ret = app_add_rule(app_list[i], shared_label, "rx");
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("app_add_rule failed");
			return ret;
		}
	}

	return PC_OPERATION_SUCCESS;
}

static char* smack_label_for_path(const char *app_id, const char *path)
{
	C_LOGD("Enter function: %s", __func__);
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
/* FIXME: remove this pragma once deprecated API is deleted */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
API int app_setup_path(const char* pkg_id, const char* path, app_path_type_t app_path_type, ...)
{
	C_LOGD("Enter function: %s", __func__);
	va_list ap;

	if (!smack_label_is_valid(pkg_id)) {
		C_LOGE("Invalid app_id %s", pkg_id);
		return PC_ERR_INVALID_PARAM;
	}

	switch (app_path_type) {
	case APP_PATH_PRIVATE:
		va_start(ap, app_path_type);
		va_end(ap);
		return app_label_dir(pkg_id, path);

	case APP_PATH_GROUP_RW: {
		const char *shared_label;

		va_start(ap, app_path_type);
		shared_label = va_arg(ap, const char *);
		va_end(ap);

		if (!smack_label_is_valid(shared_label)) {
			C_LOGE("Invalid shared_label %s", shared_label);
			return PC_ERR_INVALID_PARAM;
		}

		if (strcmp(pkg_id, shared_label) == 0) {
			C_LOGE("app_id equals shared_label");
			return PC_ERR_INVALID_PARAM;
		}

		return app_label_shared_dir(pkg_id, shared_label, path);
	}

	case APP_PATH_PUBLIC_RO: {
		char **app_ids AUTO_FREE;
		int app_ids_cnt = 0;
		const char *label;
		int i, ret;

		va_start(ap, app_path_type);
		va_end(ap);

		C_LOGD("New public RO path %s", path);
		label = smack_label_for_path(pkg_id, path);
		if (label == NULL)
			return PC_ERR_INVALID_OPERATION;

		C_LOGD("Generated label '%s' for public RO path %s", label, path);
		ret = app_label_shared_dir(pkg_id, label, path);
		if (ret != PC_OPERATION_SUCCESS)
			return ret;

		/* FIXME: This should be in some kind of transaction/lock */
		ret = db_add_public_dir(label);
		if (ret != PC_OPERATION_SUCCESS)
			return ret;

		ret = get_all_apps_ids(&app_ids, &app_ids_cnt);
		if (ret != PC_OPERATION_SUCCESS)
			return ret;

		for (i = 0; i < app_ids_cnt; ++i) {
			C_LOGD("Allowing app %s to access public path %s", pkg_id, label[i]);
			ret = app_add_rule(app_ids[i], label, "rx");
			if (ret != PC_OPERATION_SUCCESS) {
				C_LOGE("smack_accesses_new failed");
				while (i < app_ids_cnt)
					free(app_ids[i++]);
				return ret;
			}
			free(app_ids[i]);
		}

		return PC_OPERATION_SUCCESS;
	}

	case APP_PATH_SETTINGS_RW:
	{
		char **app_ids AUTO_FREE;
		int app_ids_cnt = 0;
		const char *label;
		int i;
		int ret;

		va_start(ap, app_path_type);
		va_end(ap);

		/*get path id*/
		label = smack_label_for_path(pkg_id, path);
		if (label == NULL)
			return PC_ERR_INVALID_OPERATION;

		/*set id for path and all subfolders*/
		C_LOGD("Appsetting: generated label '%s' for setting path %s", label, path);
		ret = app_label_shared_dir(pkg_id, label, path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("Appsetting: app_label_shared_dir failed (%d)", ret);
			return ret;
		}

		/*add path to database*/
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
		C_LOGD("Appsetting: %d appsetting privileged apps registeres",
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

		return PC_OPERATION_SUCCESS;
	}
	default:
		va_start(ap, app_path_type);
		va_end(ap);
		return PC_ERR_INVALID_PARAM;
	}

	return PC_OPERATION_SUCCESS;
}
/* FIXME: remove this pragma once deprecated API is deleted */
#pragma GCC diagnostic warning "-Wdeprecated-declarations"

API int app_add_friend(const char* pkg_id1, const char* pkg_id2)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;

	if (!smack_label_is_valid(pkg_id1) || !smack_label_is_valid(pkg_id2))
		return PC_ERR_INVALID_PARAM;

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

API int app_install(const char* pkg_id)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	int fd AUTO_CLOSE;
	char* smack_path AUTO_FREE;
	struct smack_accesses *smack AUTO_SMACK_FREE;

	if (!smack_label_is_valid(pkg_id))
		return PC_ERR_INVALID_PARAM;

	ret = smack_file_name(pkg_id, &smack_path);
	if (ret != PC_OPERATION_SUCCESS)
		return ret;

	fd = open(smack_path, O_RDWR|O_CREAT, 0644);
	if (fd == -1) {
		C_LOGE("file open failed: %s", strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	if (smack_accesses_new(&smack)) {
		C_LOGE("smack_accesses_new failed");
		return PC_ERR_MEM_OPERATION;
	}

	ret = add_app_id_to_databse(pkg_id);
	if (ret != PC_OPERATION_SUCCESS ) {
		C_LOGE("Error while adding app %s to database: %s ", pkg_id, strerror(errno));
		return ret;
	}

	ret = register_app_for_av(pkg_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while adding rules for anti viruses to app %s: %s ", pkg_id, strerror(errno));
		return ret;
	}

	ret = register_app_for_appsetting(pkg_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while adding rules for setting managers to app %s: %s ", pkg_id, strerror(errno));
		return ret;
	}

	ret = register_app_for_public_dirs(pkg_id, smack);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while adding rules for access to public dirs for app %s: %s ", pkg_id, strerror(errno));
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

API int app_uninstall(const char* pkg_id)
{
	// TODO: When real database will be used, then this function should remove app_id
	//       from database.
	//       It also should remove rules looks like: "anti_virus_label app_id rwx".
	C_LOGD("Enter function: %s", __func__);
	char* smack_path AUTO_FREE;
	int ret;

	if (!smack_label_is_valid(pkg_id))
		return PC_ERR_INVALID_PARAM;

	ret = smack_file_name(pkg_id, &smack_path);
	if (ret != PC_OPERATION_SUCCESS)
		return ret;

	if (unlink(smack_path)) {
		C_LOGE("unlink failed: ", strerror(errno));
//		return PC_ERR_INVALID_OPERATION;
		return PC_OPERATION_SUCCESS;
	}

	return PC_OPERATION_SUCCESS;
}

static int save_rules(int fd, struct smack_accesses* accesses) {
	if (flock(fd, LOCK_EX)) {
		C_LOGE("flock failed, error %s", strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	if (smack_accesses_save(accesses, fd)) {
		C_LOGE("smack_accesses_save failed");
		return PC_ERR_FILE_OPERATION;
	}
	return PC_OPERATION_SUCCESS ;
}

static int validate_and_add_rule(char* rule, struct smack_accesses* accesses) {
	const char* subject = NULL;
	const char* object = NULL;
	const char* access = NULL;
	char* saveptr = NULL;

	subject = strtok_r(rule, " \t\n", &saveptr);
	object = strtok_r(NULL, " \t\n", &saveptr);
	access = strtok_r(NULL, " \t\n", &saveptr);

	// check rule validity
	if (subject == NULL ||
		object == NULL ||
		access == NULL ||
		strtok_r(NULL, " \t\n", &saveptr) != NULL ||
		!smack_label_is_valid(subject) ||
		!smack_label_is_valid(object))
	{
		C_LOGE("Incorrect rule format: %s", rule);
		return PC_ERR_INVALID_PARAM;
	}

	if (smack_accesses_add_modify(accesses, subject, object, access, "")) {
		C_LOGE("smack_accesses_add_modify failed");
		return PC_ERR_INVALID_OPERATION;
	}
	return PC_OPERATION_SUCCESS ;
}

static int parse_and_save_rules(const char** smack_rules,
		struct smack_accesses* accesses, const char* feature_file) {
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
		C_LOGE("Unable to create file %s. Error: %s", feature_file, strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	ret = save_rules(fd, accesses);
	close(fd);
	return ret;
}

static int save_gids(FILE* file, const gid_t* list_of_db_gids, size_t list_size) {
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
						size_t list_size) {
	C_LOGD("Enter function: %s", __func__);

	int ret = PC_OPERATION_SUCCESS;
	char* smack_file AUTO_FREE;
	char* dac_file AUTO_FREE;
	struct smack_accesses* accesses = NULL;
	FILE* file = NULL;

	// TODO check process capabilities

	// get feature SMACK file name
	ret = perm_file_path(&smack_file, app_type, api_feature_name, ".smack");
	if (ret != PC_OPERATION_SUCCESS || !smack_file ) {
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
		ret = perm_file_path(&dac_file, app_type, api_feature_name, ".dac");
		if (ret != PC_OPERATION_SUCCESS || !dac_file ) {
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
		file = fopen(dac_file, "w+");
		ret = save_gids(file, list_of_db_gids, list_size);
		fclose(file);
	}

	// remove both files in case of failure
	if (ret != PC_OPERATION_SUCCESS) {
		unlink(smack_file);
		unlink(dac_file);
	}

	return ret;
}

/**
 * This function is marked as deprecated and will be removed
 */
API int app_register_av(const char* app_av_id)
{
	int ret;
	int fd AUTO_CLOSE;
	char* smack_path AUTO_FREE;
	struct smack_accesses* smack AUTO_SMACK_FREE;

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

	// Add permisions from OSP_antivirus.samck file
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
