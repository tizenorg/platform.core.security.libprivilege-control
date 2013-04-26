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
#include <stdbool.h>
#include <search.h>

#include "privilege-control.h"
#include "access-db.h"
#include "common.h"

#define APP_GID	5000
#define APP_UID	5000
#define ADMIN_GROUP		6504
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
#define SMACK_ANTIVIRUS_PERM    "antivirus"

static int set_smack_for_wrt(char **smack_label, const char* widget_id);

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
		return PC_ERR_INVALID_OPERATION;
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
	if (-1 == asprintf(&key, "%s|%s", subject, object))
		return PC_ERR_INVALID_OPERATION;
	int ret = state_tree_push(key, perm);
	free(key);
	return ret;
}

int state_restore(const char* subject, const char* object)
{
	char *key AUTO_FREE;
	char *perm AUTO_FREE;
	struct smack_accesses *smack AUTO_SMACK_FREE;

	if (-1 == asprintf(&key, "%s|%s", subject, object))
		return PC_ERR_INVALID_OPERATION;

	perm = state_tree_pop_new(key);
	if (!perm)
		return PC_ERR_INVALID_OPERATION;

	if (smack_accesses_new(&smack))
		return PC_ERR_MEM_OPERATION;

	if (smack_accesses_add(smack, subject, object, perm))
		return PC_ERR_MEM_OPERATION;

	if (smack_accesses_apply(smack))
		return PC_ERR_NOT_PERMITTED;

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

	if(set_app_privilege("com.samsung.", NULL, NULL) == PC_OPERATION_SUCCESS)
		return PC_OPERATION_SUCCESS;
	else
		return PC_ERR_NOT_PERMITTED;
}

static int set_dac(const char *smack_label, const char *pkg_name)
{
	C_LOGD("Enter function: %s", __func__);
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
			strncpy(usr.group_list, APP_GROUP_PATH, sizeof(usr.group_list));
		}

		/*
		 * get group information
		 */
		C_LOGD("get group information");
		if(!(fp_group = fopen(usr.group_list, "r")))
		{
			C_LOGE("[ERR] file open error: [%s]\n", usr.group_list);
			result = PC_ERR_FILE_OPERATION;	// return -1
			goto error;
		}

		while(fgets(buf, 10, fp_group) != NULL)
		{
			errno = 0;
			temp_gid = strtoul(buf, 0, 10);
			if(errno != 0)	// error occured during strtoul()
			{
				C_LOGE("[ERR] cannot change string to integer: [%s]", buf);
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

		/*
		 * in case of dialer, add admin to glist
		 */
		if(!strncmp(pkg_name, "com.samsung.phone", 17) || !strncmp(pkg_name, "com.samsung.call", 16) ||
		   !strncmp(pkg_name, "phone-tabui-efl", 15))
		{
			gid_t *glist_new;
			C_LOGD("Dialer app - add admin to glist");
			glist_new = (gid_t*)realloc(glist, sizeof(gid_t) * (glist_cnt + 1));
			if (glist_new == NULL) {
				result = PC_ERR_MEM_OPERATION;	// return -2
				C_LOGE("Cannot allocate memory");
				goto error;
			}
			glist = glist_new;
			glist[glist_cnt] = ADMIN_GROUP;	// 6504
			glist_cnt++;
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
	if(fp_group != NULL)
		fclose(fp_group);
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
static int set_smack_from_binary(char **smack_label, const char* path)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;

	C_LOGD("Path: %s", path);

	*smack_label = NULL;
	ret = smack_getlabel(path, smack_label, SMACK_LABEL_EXEC);
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
		}
	} else {
		if (type == NULL || strcmp(type, "wgt")){
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
	const char* widget_id;
	char *smack_label AUTO_FREE;
	int ret = PC_OPERATION_SUCCESS;

	switch(verify_app_type(type, path)) {
	case APP_TYPE_WGT:
		//widget_id = parse_widget_id(path);
		widget_id = name;
		if (widget_id == NULL) {
			C_LOGE("PC_ERR_INVALID_PARAM");
			ret = PC_ERR_INVALID_PARAM;
		}
		else
			ret = set_smack_for_wrt(&smack_label, widget_id);
		break;
	default:
		if (path != NULL)
			ret = set_smack_from_binary(&smack_label, path);
		break;
	}

	if (ret != PC_OPERATION_SUCCESS)
		return ret;

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
	default:
		return NULL;
	}
}

static int perm_file_path(char** path, app_type_t app_type, const char* perm, const char *suffix)
{
	const char* app_type_prefix = NULL;
	const char* perm_basename = NULL;
	int ret = 0;

	if (perm == NULL || strlen(perm) == 0) {
		C_LOGE("empty permission name");
		return PC_ERR_INVALID_PARAM;
	}

	app_type_prefix = app_type_name(app_type);

	perm_basename = strrchr(perm, '/');
	if (perm_basename)
		++perm_basename;
	else
		perm_basename = perm;

	ret = asprintf(path, TOSTRING(SHAREDIR) "/%s%s%s%s",
			app_type_prefix ? app_type_prefix : "", app_type_prefix ? "_" : "",
			perm_basename, suffix);
	if (ret == -1) {
		C_LOGE("asprintf failed");
		return PC_ERR_MEM_OPERATION;
	}

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

static int dir_set_smack_r(const char *path, const char* label,
		enum smack_label_type type, mode_t type_mask)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	const char* path_argv[] = {path, NULL};
	FTS *fts = NULL;
	FTSENT *ftsent;

	ret = PC_ERR_FILE_OPERATION;

	fts = fts_open((char * const *) path_argv, FTS_PHYSICAL | FTS_NOCHDIR, NULL);
	if (fts == NULL) {
		C_LOGE("fts_open failed");
		goto out;
	}

	while ((ftsent = fts_read(fts)) != NULL) {
		/* Check for error (FTS_ERR) or failed stat(2) (FTS_NS) */
		if (ftsent->fts_info == FTS_ERR || ftsent->fts_info == FTS_NS) {
			C_LOGE("FTS_ERR error or failed stat(2) (FTS_NS)");
			goto out;
		}

		if (ftsent->fts_statp->st_mode & type_mask) {
			C_LOGD("smack_lsetlabel (label: %s (type: %d), path: %s)", label, type, ftsent->fts_path);
			if (smack_lsetlabel(ftsent->fts_path, label, type) != 0) {
				C_LOGE("smack_lsetlabel failed");
				goto out;
			}
		}
	}

	/* If last call to fts_read() set errno, we need to return error. */
	if (errno == 0)
		ret = PC_OPERATION_SUCCESS;
	else
		C_LOGE("Last errno: %s", strerror(errno));

out:
	if (fts != NULL)
		fts_close(fts);
	return ret;
}

static int set_smack_for_wrt(char **smack_label, const char* widget_id)
{
	C_LOGD("Enter function: %s", __func__);

	*smack_label = strdup(widget_id);
	if (smack_label == NULL)
		return PC_ERR_MEM_OPERATION;

	if (!have_smack())
		return PC_OPERATION_SUCCESS;
/*
	int ret;
	ret = app_reset_permissions(widget_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("app_reset_permissions failed");
		return ret;
	}
*/
	if (smack_set_label_for_self(widget_id) != 0) {
		C_LOGE("smack_set_label_for_self failed");
		return PC_ERR_INVALID_OPERATION;
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
	struct smack_accesses* smack AUTO_SMACK_FREE;

	ret = smack_accesses_new(&smack);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("smack_accesses_new failed");
		return ret;
	}

	// Reading labels of all installed anti viruses from "database"
	ret = get_all_avs_ids(&smack_label_av_list, &smack_label_av_list_len);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while geting data from database");
		return ret;
	}

	// for each anti-virus put rule: "anti_virus_id app_id rwx"
	for (i = 0; i < smack_label_av_list_len; ++i) {
		int fd AUTO_CLOSE;
		char* smack_path AUTO_FREE;
		C_LOGD("Adding rwx rule for antivirus: %s", smack_label_av_list[i]);

		ret = load_smack_from_file(smack_label_av_list[i], &smack, &fd, &smack_path);
		if (ret != PC_OPERATION_SUCCESS ) {
			C_LOGE("load_smack_from_file failed");
			goto out;
		}

		if (smack_accesses_add(smack, smack_label_av_list[i], app_id, "wrx") == -1) {
			C_LOGE("smack_accesses_add failed");
			ret = PC_ERR_INVALID_OPERATION;
			goto out; // Should we abort adding rules if once smack_accesses_add will fail?
		}

		if (have_smack() && smack_accesses_apply(smack)) {
			C_LOGE("smack_accesses_apply failed");
			ret = PC_ERR_INVALID_OPERATION;
			goto out;
		}

		if (smack_accesses_save(smack, fd)) {
			C_LOGE("smack_accesses_save failed");
			ret = PC_ERR_INVALID_OPERATION;
			goto out;
		}
		// Clearing char* smack_label_av_list[i] got from database.
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

static int app_add_permissions_internal(const char* app_id, app_type_t app_type, const char** perm_list, int permanent)
{
	C_LOGD("Enter function: %s", __func__);
	int i, ret;
	char* smack_path AUTO_FREE;
	int fd AUTO_CLOSE;
	struct smack_accesses *smack AUTO_SMACK_FREE;
	const char* base_perm = NULL;

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

API int app_enable_permissions(const char* app_id, app_type_t app_type, const char** perm_list, bool persistent)
{
	C_LOGD("Enter function: %s", __func__);
	return app_add_permissions_internal(app_id, app_type, perm_list, persistent);
}

/* FIXME: this function is only a stub */
API int app_disable_permissions(const char* app_id, app_type_t app_type, const char** perm_list)
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

API int app_revoke_permissions(const char* app_id)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;

	if (!smack_label_is_valid(app_id))
		return PC_ERR_INVALID_PARAM;

	ret = app_revoke_permissions_internal(app_id, true);
	if (ret) {
		C_LOGE("Revoking permissions failed");
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_reset_permissions(const char* app_id)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;

	if (!smack_label_is_valid(app_id))
		return PC_ERR_INVALID_PARAM;

	ret = app_revoke_permissions_internal(app_id, false);
	if (ret) {
		C_LOGE("Revoking permissions failed");
		return ret;
	}

	/* Add empty permissions set to trigger re-read of rules */
	return app_enable_permissions(app_id, APP_TYPE_OTHER, (const char*[]){NULL}, 0);
}

API int app_label_dir(const char* label, const char* path)
{
	C_LOGD("Enter function: %s", __func__);

	int ret = PC_OPERATION_SUCCESS;

	//setting access label on everything in given directory and below
	ret = dir_set_smack_r(path, label, SMACK_LABEL_ACCESS, ~0);
	if (PC_OPERATION_SUCCESS != ret)
		return ret;

	//setting execute label for everything with permission to execute
	ret = dir_set_smack_r(path, label, SMACK_LABEL_EXEC, S_IXUSR);
	if (PC_OPERATION_SUCCESS != ret)
		return ret;

	//removing execute label from directories
	ret = dir_set_smack_r(path, "", SMACK_LABEL_EXEC, S_IFMT & ~S_IFREG);

	return ret;
}

static int smack_get_access_new(const char* subject, const char* object, char** label)
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
	static const char * const revoke = "-----";
	char *current_permissions AUTO_FREE;

	if (!have_smack())
		return PC_OPERATION_SUCCESS;

	if (!smack_label_is_valid(subject) || !smack_label_is_valid(object))
		return PC_ERR_INVALID_PARAM;

	if (PC_OPERATION_SUCCESS != (ret = smack_get_access_new(subject, object, &current_permissions)))
		return ret;

	if (smack_accesses_new(&smack))
		return PC_ERR_MEM_OPERATION;

	if (smack_accesses_add_modify(smack, subject, object, permissions, revoke))
		return PC_ERR_MEM_OPERATION;

	if (smack_accesses_apply(smack))
		return PC_ERR_NOT_PERMITTED;

	ret = state_save(subject, object, current_permissions);

	return ret;
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

	if (!smack_label_is_valid(subject) || !smack_label_is_valid(object))
		return PC_ERR_INVALID_PARAM;

	return state_restore(subject, object);
}

API int app_label_shared_dir(const char* app_label, const char* shared_label, const char* path)
{
	C_LOGD("Enter function: %s", __func__);
	char* smack_path AUTO_FREE;
	int ret;
	int fd AUTO_CLOSE;
	struct smack_accesses *smack AUTO_SMACK_FREE;


	if (strcmp(app_label, shared_label) == 0) {
		C_LOGE("app_label equals shared_label");
		return PC_ERR_INVALID_PARAM;
	}

	//setting label on everything in given directory and below
	ret = dir_set_smack_r(path, shared_label, SMACK_LABEL_ACCESS, ~0);
	if(ret != PC_OPERATION_SUCCESS){
		C_LOGE("dir_set_smakc_r failed");
		return ret;
	}

	//setting transmute on dir
	ret = dir_set_smack_r(path, "1", SMACK_LABEL_TRANSMUTE, S_IFDIR);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("dir_set_smakc_r failed");
		return ret;
	}

	ret = load_smack_from_file(app_label, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		return ret;
	}

	//setting access rule for application
	if (smack_accesses_add(smack, app_label,shared_label, "wrxat") == -1) {
		C_LOGE("smack_accesses_add failed");
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

API int add_shared_dir_readers(const char* shared_label, const char** app_list)
{
	C_LOGD("Enter function: %s", __func__);
	int ret = PC_ERR_INVALID_PARAM;
	int i;
	int fd AUTO_CLOSE;

	if (!smack_label_is_valid(shared_label))
				return PC_ERR_INVALID_PARAM;

	for (i = 0; app_list[i] != NULL; i++) {
		char *smack_path AUTO_FREE;
		struct smack_accesses *smack AUTO_SMACK_FREE;

		if (!smack_label_is_valid(app_list[i]))
					return PC_ERR_INVALID_PARAM;

		ret = load_smack_from_file(
				app_list[i], &smack, &fd, &smack_path);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("load_smack_from_file failed");
			return ret;
		}
		if (smack_accesses_add_modify(smack, app_list[i], shared_label,
				"rx", "") == -1) {
			C_LOGE("smack_accesses_add failed");
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
	}

	return PC_OPERATION_SUCCESS;
}

API int app_add_friend(const char* app_id1, const char* app_id2)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	int fd1 AUTO_CLOSE;
	int fd2 AUTO_CLOSE;
	char* smack_path1 AUTO_FREE;
	char* smack_path2 AUTO_FREE;
	struct smack_accesses* smack1 AUTO_SMACK_FREE;
	struct smack_accesses* smack2 AUTO_SMACK_FREE;

	ret = load_smack_from_file(app_id1, &smack1, &fd1, &smack_path1);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		return ret;
	}

	ret = load_smack_from_file(app_id2, &smack2, &fd2, &smack_path2);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		return ret;
	}

	if (smack_accesses_add(smack1, app_id1, app_id2, "wrxat") == -1 ||
		(smack_accesses_add(smack2, app_id2, app_id1, "wrxat") == -1)) {
		C_LOGE("smack_accesses_add failed");
		return ret;
	}

	if (have_smack() &&
		(smack_accesses_apply(smack1) || smack_accesses_apply(smack2))) {
		C_LOGE("smack_accesses_apply failed");
		return PC_ERR_INVALID_OPERATION;
	}

	if (smack_accesses_save(smack1, fd1) || smack_accesses_save(smack2, fd2)) {
		C_LOGE("smack_accesses_save failed");
		return PC_ERR_INVALID_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_install(const char* app_id)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	int fd AUTO_CLOSE;
	char* smack_path AUTO_FREE;

	ret = smack_file_name(app_id, &smack_path);
	if (ret != PC_OPERATION_SUCCESS)
		return ret;

	fd = open(smack_path, O_RDWR|O_CREAT, 0644);
	if (fd == -1) {
		C_LOGE("file open failed: %s", strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	ret = add_app_id_to_databse(app_id);
	if (ret != PC_OPERATION_SUCCESS ) {
		C_LOGE("Error while adding app %s to database: %s ", app_id, strerror(errno));
		return ret;
	}

	ret = register_app_for_av(app_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while adding rules for anti viruses to app %s: %s ", app_id, strerror(errno));
		return ret;
	}

	return PC_OPERATION_SUCCESS;
}

API int app_uninstall(const char* app_id)
{
	// TODO: When real database will be used, then this function should remove app_id
	//       from database.
	//       It also should remove rules looks like: "anti_virus_label app_id rwx".
	C_LOGD("Enter function: %s", __func__);
	char* smack_path AUTO_FREE;
	int ret;

	ret = smack_file_name(app_id, &smack_path);
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

	if (smack_accesses_add(accesses, subject, object, access)) {
		C_LOGE("smack_accesses_add failed");
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

API int app_register_av(const char* app_av_id)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	int i;
	int fd AUTO_CLOSE;
	FILE* file AUTO_FCLOSE;

	char** smack_label_app_list AUTO_FREE;
	int smack_label_app_list_len = 0;
	char* smack_path AUTO_FREE;
	struct smack_accesses* smack AUTO_SMACK_FREE;

	if (!smack_label_is_valid(app_av_id))
		return PC_ERR_INVALID_PARAM;

	ret = smack_accesses_new(&smack);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("smack_accesses_new failed");
		return PC_ERR_MEM_OPERATION;
	}

	// writing anti_virus_id (app_av_id) to "database"
	ret = add_av_id_to_databse(app_av_id);
	if (ret != PC_OPERATION_SUCCESS)
	goto out;

	ret = load_smack_from_file(app_av_id, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		goto out;
	}

	// Reading labels of all installed apps from "database"
	ret = get_all_apps_ids(&smack_label_app_list, &smack_label_app_list_len);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error while geting data from database");
		goto out;
	}
	for (i=0; i<smack_label_app_list_len; ++i) {
		C_LOGD("Applying rwx rule for %s", smack_label_app_list[i]);
		if (smack_accesses_add(smack, app_av_id, smack_label_app_list[i], "wrx") == -1) {
			C_LOGE("smack_accesses_add failed");
			ret = PC_ERR_INVALID_OPERATION;
			goto out; // Should we abort adding rules if once smack_accesses_add will fail?
		}
	}

	// Add permisions from OSP_antivirus.samck file - only the OSP app can be an Anti Virus
	ret = perm_to_smack(smack, app_av_id, APP_TYPE_OSP, SMACK_ANTIVIRUS_PERM);
	if (PC_OPERATION_SUCCESS != ret) {
		C_LOGE("perm_to_smack failed");
		goto out;
	}

	if (have_smack() && smack_accesses_apply(smack)) {
		C_LOGE("smack_accesses_apply failed");
		ret = PC_ERR_INVALID_OPERATION;
		goto out;
	}

	if (smack_accesses_save(smack, fd)) {
		C_LOGE("smack_accesses_save failed");
		ret = PC_ERR_INVALID_OPERATION;
		goto out;
	}

out:
	for (i=0; i<smack_label_app_list_len; ++i) {
		free(smack_label_app_list[i]);
	}

	return PC_OPERATION_SUCCESS;
}
