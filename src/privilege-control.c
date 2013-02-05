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
#include <dlog.h>
#include <string.h>

#include "privilege-control.h"

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

#define SMACK_APP_LABEL         "~APP~"
#define SMACK_WRT_LABEL_PREFIX  "wrt_widget_"
#define SMACK_SRC_FILE_SUFFIX   "_src_file"
#define SMACK_SRC_DIR_SUFFIX    "_src_dir"
#define SMACK_DATA_SUFFIX       "_data"
#define WRT_BASE_DEVCAP         "WRT"
#define WRT_CLIENT_PATH         "/usr/bin/wrt-client"

#ifndef SMACK_ENABLED
#undef WRT_SMACK_ENABLED
#endif

#ifdef WRT_SMACK_ENABLED
static int set_smack_for_wrt(const char* widget_id);
#endif // WRT_SMACK_ENABLED

#ifdef LOG_TAG
    #undef LOG_TAG
#endif // LOG_TAG
#ifndef LOG_TAG
    #define LOG_TAG "PRIVILEGE_CONTROL"
#endif // LOG_TAG

// conditional_log macro for dlogutil (debug)
#ifdef DLOG_ENABLED
#define C_LOGD(...) LOGD(__VA_ARGS__)
#define C_LOGE(...) LOGE(__VA_ARGS__)
#else
#define C_LOGD(...) do { } while(0)
#define C_LOGE(...) do { } while(0)
#endif //DLOG_ENABLED

typedef enum {
	PKG_TYPE_WGT,
	PKG_TYPE_OTHER
} pkg_type_t;

typedef struct {
	char user_name[10];
	int uid;
	int gid;
	char home_dir[64];
	char group_list[64];
} new_user;

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

static int set_dac(const char* pkg_name)
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

	return result;
}

#ifdef SMACK_ENABLED
/**
 * Set process SMACK label from EXEC label of a file.
 * This function is emulating EXEC label behaviour of SMACK for programs
 * run by dlopen/dlsym instead of execv.
 *
 * @param path file path to take label from
 * @return PC_OPERATION_SUCCESS on success, PC_ERR_* on error
 */
static int set_smack_from_binary(const char* path)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	char* label;

	C_LOGD("Path: %s", path);
	ret = smack_getlabel(path, &label, SMACK_LABEL_EXEC);
	if (ret != 0) {
		C_LOGE("Getting exec label from file %s failed", path);
		return PC_ERR_INVALID_OPERATION;
	}

	if (label == NULL) {
		/* No label to set, just return with success */
		C_LOGD("No label to set, just return with success");
		ret = PC_OPERATION_SUCCESS;
	}
	else {
		ret = smack_set_label_for_self(label);
		C_LOGD("label = %s", label);
		C_LOGD("smack_set_label_for_self returned %d", ret);
	}

	free(label);
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
static pkg_type_t verify_app_type(const char* type, const char* path)
{
	C_LOGD("Enter function: %s", __func__);
	/* TODO: this should actually be treated as error, but until the old
	 * set_privilege API is removed, it must be ignored */
	if (path == NULL) {
		C_LOGD("PKG_TYPE_OTHER");
		return PKG_TYPE_OTHER; /* good */
	}

	if (is_widget(path)) {
		if (!strcmp(type, "wgt")) {
			C_LOGD("PKG_TYPE_WGT");
			return PKG_TYPE_WGT; /* good */
		}
	} else {
		if (type == NULL || strcmp(type, "wgt")){
			C_LOGD("PKG_TYPE_OTHER");
			return PKG_TYPE_OTHER; /* good */
		}
	}

	/* bad */
	C_LOGE("EXIT_FAILURE");
	exit(EXIT_FAILURE);
}

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
}
#endif // SMACK_ENABLED

API int set_app_privilege(const char* name, const char* type, const char* path)
{
	C_LOGD("Enter function: %s", __func__);
	C_LOGD("Function params: name = %s, type = %s, path = %s", name, type, path);
#ifdef SMACK_ENABLED
	const char* widget_id;
	int ret = PC_OPERATION_SUCCESS;

	switch(verify_app_type(type, path)) {
	case PKG_TYPE_WGT:
		widget_id = parse_widget_id(path);
		if (widget_id == NULL) {
			C_LOGE("PC_ERR_INVALID_PARAM");
			ret = PC_ERR_INVALID_PARAM;
		}
#ifdef WRT_SMACK_ENABLED
		else
			ret = set_smack_for_wrt(widget_id);
#endif
		break;
	case PKG_TYPE_OTHER:
		if (path != NULL)
		ret = set_smack_from_binary(path);
	}

	if (ret != PC_OPERATION_SUCCESS)
		return ret;
#endif // SMACK_ENABLED

	return set_dac(name);
}

API int set_privilege(const char* pkg_name)
{
	C_LOGD("Enter function: %s", __func__);
	return set_app_privilege(pkg_name, NULL, NULL);
}

API int wrt_set_privilege(const char* widget_id)
{
	C_LOGD("Enter function: %s", __func__);
#ifdef WRT_SMACK_ENABLED
	int ret;

	ret = set_smack_for_wrt(widget_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("set_smack_for_wrt returned error");
		return ret;
	}
#endif // WRT_SMACK_ENABLED

	return set_dac("com.samsung.");
}

#ifdef WRT_SMACK_ENABLED
static inline char* wrt_smack_label(const char* widget_id, const char* suffix)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	char* label;

	ret = asprintf(&label, "%s%s%s", SMACK_WRT_LABEL_PREFIX, widget_id,
		(suffix ? suffix : ""));

	if (ret == -1) {
		C_LOGE("asprintf failed");
		return NULL;
	}

	if (strlen(label) > SMACK_LABEL_LEN) {
		C_LOGE("strlen(label) [%s] > SMACK_LABEL_LEN", label);
		free(label);
		return NULL;
	}

	return label;
}
#endif // WRT_SMACK_ENABLED

static inline int perm_to_smack(struct smack_accesses* smack, const char* app_label, const char* perm)
{
	C_LOGD("Enter function: %s", __func__);
	int ret = PC_OPERATION_SUCCESS;
	char* path = NULL;
	char* format_string = NULL;
	FILE* file = NULL;
	char smack_subject[SMACK_LABEL_LEN + 1];
	char smack_object[SMACK_LABEL_LEN + 1];
	char smack_accesses[10];

	if (asprintf(&path, TOSTRING(SHAREDIR) "/%s.smack", perm) == -1) {
		C_LOGE("asprintf failed");
		ret = PC_ERR_MEM_OPERATION;
		goto out;
	}

	if (asprintf(&format_string,"%%%ds %%%ds %%%ds\n",
			SMACK_LABEL_LEN, SMACK_LABEL_LEN, sizeof(smack_accesses)) == -1) {
		C_LOGE("asprintf failed");
		ret = PC_ERR_MEM_OPERATION;
		goto out;
	}

	file = fopen(path, "r");
	C_LOGD("path = %s", path);
	if (file == NULL) {
		C_LOGE("fopen failed");
		ret = PC_ERR_FILE_OPERATION;
		goto out;
	}

	while (1) {
		if (fscanf(file, format_string, smack_subject, smack_object, smack_accesses) != 3) {
			C_LOGE("fscanf failed");
			goto out;
		}

		if (!strcmp(smack_subject, SMACK_APP_LABEL))
			strcpy(smack_subject, app_label);

		if (!strcmp(smack_object, SMACK_APP_LABEL))
			strcpy(smack_object, app_label);

		C_LOGD("smack_accesses_add_modify (subject: %s, object: %s, access: %s)", smack_subject, smack_object, smack_accesses);
		if (smack_accesses_add_modify(smack, smack_subject, smack_object, smack_accesses, "") != 0) {
			C_LOGE("smack_accesses_add_modify failed");
			ret = PC_ERR_INVALID_OPERATION;
			goto out;
		}
	}

out:
	free(path);
	free(format_string);
	if (file != NULL)
		fclose(file);
	return ret;
}

API int wrt_permissions_reset(const char* widget_id)
{
	C_LOGD("Enter function: %s", __func__);
	int ret = PC_OPERATION_SUCCESS;
#ifdef WRT_SMACK_ENABLED
	char* label = NULL;

	label = wrt_smack_label(widget_id, NULL);
	if (label == NULL) {
		C_LOGE("wrt_smack_label failed");
		return PC_ERR_MEM_OPERATION;
	}

	if (smack_revoke_subject(label)) {
		C_LOGE("smack_revoke_subject failed");
		ret = PC_ERR_INVALID_OPERATION;
	}

	free(label);
#endif // WRT_SMACK_ENABLED
	return ret;
}

API int wrt_permissions_add(const char* widget_id, const char** devcap_list)
{
	C_LOGD("Enter function: %s", __func__);
	int ret = PC_OPERATION_SUCCESS;
#ifdef WRT_SMACK_ENABLED
	char* widget_label = NULL;
	struct smack_accesses* smack = NULL;
	int i;

	widget_label = wrt_smack_label(widget_id, NULL);
	if (widget_label == NULL) {
		C_LOGE("wrt_smack_label failed");
		return PC_ERR_MEM_OPERATION;
	}

	if (smack_accesses_new(&smack)) {
		C_LOGE("smack_accesses_new failed");
		ret = PC_ERR_MEM_OPERATION;
		goto out;
	}

	for (i = 0; devcap_list[i] != NULL; ++i) {
		char* perm = NULL;

		/* Prepend devcap with "WRT_" */
		if (asprintf(&perm, "%s_%s", WRT_BASE_DEVCAP, devcap_list[i]) == -1) {
			C_LOGE("asprintf failed");
			ret = PC_ERR_MEM_OPERATION;
			goto out;
		}

		C_LOGD("Adding permission %s", perm);
		ret = perm_to_smack(smack, widget_label, perm);
		free(perm);
		if (ret != PC_OPERATION_SUCCESS) {
			C_LOGE("perm_to_smack failed (%d)", ret);
			goto out;
		}
	}

	if (smack_accesses_apply(smack) != 0) {
		C_LOGE("smack_accesses_apply failed");
		ret = PC_ERR_INVALID_OPERATION;
		goto out;
	}

out:
	smack_accesses_free(smack);
	free(widget_label);
#endif // WRT_SMACK_ENABLED
	return ret;
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

API int wrt_set_src_dir(const char* widget_id, const char *path)
{
	C_LOGD("Enter function: %s", __func__);
	C_LOGD("Path: %s", path);
	int ret = PC_OPERATION_SUCCESS;
#ifdef WRT_SMACK_ENABLED
	char* src_label_dir = NULL;
	char* src_label_file = NULL;

	ret = PC_ERR_MEM_OPERATION;

	src_label_dir = wrt_smack_label(widget_id, SMACK_SRC_DIR_SUFFIX);
	if (src_label_dir == NULL) {
		C_LOGE("src_label_dir is NULL");
		goto out;
	}

	src_label_file = wrt_smack_label(widget_id, SMACK_SRC_FILE_SUFFIX);
	if (src_label_file == NULL) {
		C_LOGE("src_label_file in NULL");
		goto out;
	}

	/* Set label for directories */
	ret = dir_set_smack_r(path, src_label_dir, SMACK_LABEL_ACCESS, S_IFDIR);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("dir_set_smack_r failed");
		goto out;
	}

	/* Set label for non-directories */
	ret = dir_set_smack_r(path, src_label_file, SMACK_LABEL_ACCESS, ~S_IFDIR);

out:
	free(src_label_dir);
	free(src_label_file);
#endif // WRT_SMACK_ENABLED
	return ret;
}

API int wrt_set_data_dir(const char* widget_id, const char *path)
{
	C_LOGD("Enter function: %s", __func__);
	C_LOGD("Path: %s", path);
	int ret = PC_OPERATION_SUCCESS;
#ifdef WRT_SMACK_ENABLED
	char* data_label = NULL;
	struct stat st;

	ret = PC_ERR_FILE_OPERATION;
	/* Check whether path exists */
	if (lstat(path, &st) == 0) {
		if (!S_ISDIR(st.st_mode)) {
			/* Exists, but it's not a directory? */
			C_LOGE("Exists, but it's not a directory?");
			goto out;
		}
	} else {
		if (errno != ENOENT) {
			/* Some other error than "no such file or directory" */
			C_LOGE("Other error: %s", strerror(errno));
			goto out;
		}
		if (mkdir(path, S_IRWXU) != 0) {
			/* Error while creating the directory */
			C_LOGE("Error while creating the directory");
			goto out;
		}
		if (chown(path, APP_UID, APP_GID)) {
			/* Error while setting the directory owner */
			C_LOGE("Error while setting the directory owner");
			int e = errno;
			rmdir(path);
			errno = e;
			goto out;
		}
	}

	ret = PC_ERR_MEM_OPERATION;

	data_label = wrt_smack_label(widget_id, SMACK_DATA_SUFFIX);
	if (data_label == NULL) {
		C_LOGE("data_label is NULL");
		goto out;
	}

	/* Set label for everything inside data path */
	ret = dir_set_smack_r(path, data_label, SMACK_LABEL_ACCESS, ~0);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("dir_set_smack_r failed");
		goto out;
	}

	/* Enable transmute on all directories */
	ret = dir_set_smack_r(path, "1", SMACK_LABEL_TRANSMUTE, S_IFDIR);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("dir_set_smack_r failed");
		goto out;
	}

out:
	free(data_label);
#endif // WRT_SMACK_ENABLED
	return ret;
}

#ifdef WRT_SMACK_ENABLED
static int set_smack_for_wrt(const char* widget_id)
{
	C_LOGD("Enter function: %s", __func__);
	char* widget_label = NULL;
	char* src_label_file = NULL;
	char* src_label_dir = NULL;
	char* data_label = NULL;
	struct smack_accesses* smack = NULL;
	int ret;

	ret = PC_ERR_MEM_OPERATION;

	widget_label = wrt_smack_label(widget_id, NULL);
	C_LOGD("widget id: %s", widget_id);
	if (widget_label == NULL) {
		C_LOGE("widget_label is NULL");
		goto out;
	}

	src_label_file = wrt_smack_label(widget_id, SMACK_SRC_FILE_SUFFIX);
	if (src_label_file == NULL) {
		C_LOGE("src_label_file is NULL");
		goto out;
	}

	src_label_dir = wrt_smack_label(widget_id, SMACK_SRC_DIR_SUFFIX);
	if (src_label_file == NULL) {
		C_LOGE("src_label_file is NULL");
		goto out;
	}

	data_label = wrt_smack_label(widget_id, SMACK_DATA_SUFFIX);
	if (data_label == NULL) {
		C_LOGE("data_label is NULL");
		goto out;
	}

	if (smack_accesses_new(&smack) != 0) {
		C_LOGE("smack_accesses_new failed");
		goto out;
	}

	ret = wrt_permissions_reset(widget_id);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("wrt_permissions_reset failed");
		goto out;
	}

	ret = PC_ERR_INVALID_OPERATION;

	if (smack_set_label_for_self(widget_label) != 0) {
		C_LOGE("smack_set_label_for_self failed");
		goto out;
	}

	/* Allow widget to only read and execute it's source directories */
	C_LOGD("Adding implicit Smack rule: %s %s %s", widget_label, src_label_dir, "rx");
	if (smack_accesses_add(smack, widget_label, src_label_dir, "rx") != 0) {
		C_LOGE("smack_accesses_add failed (rx)");
		goto out;
	}

	/* Allow widget to only read read it's source files */
	C_LOGD("Adding implicit Smack rule: %s %s %s", widget_label, src_label_file, "r");
	if (smack_accesses_add(smack, widget_label, src_label_file, "r") != 0) {
		C_LOGE("smack_accesses_add failed (r)");
		goto out;
	}

	/* Allow widget to do everything with it's data */
	/*
	 * FIXME: If a malicious widget finds a way to execute files, it will be
	 * able to execute it's data files, which are fully controlled by the
	 * widget itself. This currently cannot be prevented by SMACK, so other
	 * means must be used.
	 */
	C_LOGD("Adding implicit Smack rule: %s %s %s", widget_label, data_label, "rwxat");
	if (smack_accesses_add(smack, widget_label, data_label, "rwxat") != 0) {
		C_LOGE("smack_accesses_add failed (rwxat)");
		goto out;
	}

	C_LOGD("Adding Smack rules from pseudo-devcap %s", WRT_BASE_DEVCAP);
	ret = perm_to_smack(smack, widget_label, WRT_BASE_DEVCAP);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("perm_to_smack failed");
		goto out;
	}

	if (smack_accesses_apply(smack) != 0) {
		C_LOGE("smack_accesses_apply failed");
		ret = PC_ERR_INVALID_OPERATION;
	}

out:
	smack_accesses_free(smack);
	free(widget_label);
	free(src_label_file);
	free(src_label_dir);
	free(data_label);

	return ret;
}
#endif // WRT_SMACK_ENABLED

API char* wrt_widget_id_from_socket(int sockfd)
{
	C_LOGD("Enter function: %s", __func__);
	char* smack_label;
	char* widget_id;
	int ret;

	ret = smack_new_label_from_socket(sockfd, &smack_label);
	if (ret != 0) {
		C_LOGE("smack_new_label_from_socket failed");
		return NULL;
	}

	if (strncmp(smack_label, SMACK_WRT_LABEL_PREFIX,
		    strlen(SMACK_WRT_LABEL_PREFIX))) {
		free(smack_label);
		return NULL;
	}

	widget_id = strdup(smack_label + strlen(SMACK_WRT_LABEL_PREFIX));
	free(smack_label);
	C_LOGD("widget id: %s", widget_id);
	return widget_id;
}


static int load_smack_from_file(const char* app_id, struct smack_accesses** smack, int *fd)
{
	C_LOGD("Enter function: %s", __func__);

	char* path = NULL;
	int ret;

	if (asprintf(&path, SMACK_RULES_DIR "/%s", app_id) == -1) {
		ret = PC_ERR_MEM_OPERATION;
		C_LOGE("asprintf failed");
		goto out;
	}

	if (smack_accesses_new(smack)) {
		ret = PC_ERR_MEM_OPERATION;
		C_LOGE("smack_accesses_new failed");
		goto out;
	}

	*fd = open(path, O_CREAT|O_RDWR, 0644);
	if (*fd == -1) {
		ret = PC_ERR_FILE_OPERATION;
		C_LOGE("file open failed");
		goto out;
	}

	if (flock(*fd, LOCK_EX)) {
		ret = PC_ERR_INVALID_OPERATION;
		C_LOGE("flock failed");
		goto out;
	}

	if (smack_accesses_add_from_file(*smack, *fd)) {
		ret = PC_ERR_INVALID_OPERATION;
		C_LOGE("smack_accesses_add_from_file failed");
		goto out;
	}

	/* Rewind the file */
	if (lseek(*fd, 0, SEEK_SET) == -1) {
		ret = PC_ERR_FILE_OPERATION;
		C_LOGE("lseek failed");
		goto out;
	}

	ret = PC_OPERATION_SUCCESS;

out:
	free(path);

	return ret;
}

static int save_smack_to_file(struct smack_accesses *smack, int fd)
{
	if (smack_accesses_apply(smack)) {
		C_LOGE("smack_accesses_apply failed");
		return PC_ERR_INVALID_OPERATION;
	}

	if (smack_accesses_save(smack, fd)) {
		C_LOGE("smack_accesses_save failed");
		return PC_ERR_INVALID_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}


API int app_add_permissions(const char* app_id, const char** perm_list)
{
	C_LOGD("Enter function: %s", __func__);
	char* path = NULL;
	int i, ret;
	int fd = -1;
	struct smack_accesses *smack = NULL;

#ifdef SMACK_ENABLED

	ret = load_smack_from_file(app_id, &smack, &fd);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		goto out;
	}
	for (i = 0; perm_list[i] != NULL; ++i) {
		ret = perm_to_smack(smack, app_id, perm_list[i]);
		C_LOGD("perm_to_smack params: app_id: %s, perm_list[%d]: %s", app_id, i, perm_list[i]);
		if (ret != PC_OPERATION_SUCCESS){
			C_LOGE("perm_to_smack failed");
			goto out;
		}
	}

	ret = save_smack_to_file(smack, fd);
	if(ret != PC_OPERATION_SUCCESS){
		C_LOGE("save_smack_to_file failed");
		goto out;
	}
#endif

	ret = PC_OPERATION_SUCCESS;
out:
	if (fd != -1)
		close(fd);
	if (smack != NULL)
		smack_accesses_free(smack);
	free(path);

	return ret;
}

API int app_revoke_permissions(const char* app_id)
{
	C_LOGD("Enter function: %s", __func__);
	char* path = NULL;
	int ret;
	int fd = -1;
	struct smack_accesses *smack = NULL;

#ifdef SMACK_ENABLED
	if (asprintf(&path, SMACK_RULES_DIR "/%s", app_id) == -1) {
		ret = PC_ERR_MEM_OPERATION;
		C_LOGE("asprintf failed");
		goto out;
	}

	if (smack_accesses_new(&smack)) {
		ret = PC_ERR_MEM_OPERATION;
		C_LOGE("smack_accesses_new failed");
		goto out;
	}

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		ret = PC_ERR_FILE_OPERATION;
		C_LOGE("file open failed");
		goto out;
	}

	if (flock(fd, LOCK_EX | LOCK_NB)) {
		/* Non-blocking lock request on a file failed. */
		ret = PC_ERR_INVALID_OPERATION;
		C_LOGE("flock failed");
		goto out;
	}

	if (unlink(path)) {
		ret = PC_ERR_INVALID_OPERATION;
		C_LOGE("unlink failed");
		goto out;
	}

	if (smack_accesses_add_from_file(smack, fd)) {
		ret = PC_ERR_INVALID_OPERATION;
		C_LOGE("smack_accesses_add_from_file failed");
		goto out;
	}

	if (smack_accesses_clear(smack)) {
		ret = PC_ERR_INVALID_OPERATION;
		C_LOGE("smack_accesses_clear failed");
		goto out;
	}

	if (smack_revoke_subject(app_id)) {
		ret = PC_ERR_INVALID_OPERATION;
		C_LOGE("smack_revoke_subject failed");
		goto out;
	}
#endif

	ret = PC_OPERATION_SUCCESS;
out:
	if (fd != -1)
		close(fd);
	if (smack != NULL)
		smack_accesses_free(smack);
	free(path);

	return ret;
}

API int app_label_dir(const char* label, const char* path)
{
	C_LOGD("Enter function: %s", __func__);
#ifdef SMACK_ENABLED

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
#else
	return PC_OPERATION_SUCCESS;
#endif
}

API int app_label_shared_dir(const char* app_label, const char* shared_label, const char* path)
{
	C_LOGD("Enter function: %s", __func__);
#ifdef SMACK_ENABLED
	int ret;
	int fd = -1;
	struct smack_accesses *smack = NULL;


	//setting label on everything in given directory and below
	ret = dir_set_smack_r(path, shared_label, SMACK_LABEL_ACCESS, ~0);
	if(ret != PC_OPERATION_SUCCESS){
		C_LOGE("dir_set_smakc_r failed");
		goto out;
	}

	//setting transmute on dir
	ret = dir_set_smack_r(path, "1", SMACK_LABEL_TRANSMUTE, S_IFDIR);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("dir_set_smakc_r failed");
		goto out;
	}

	ret = load_smack_from_file(app_label, &smack, &fd);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		goto out;
	}

	//setting access rule for application
	if (smack_accesses_add(smack, app_label,shared_label, "wrxat") == -1) {
		C_LOGE("smack_accesses_add failed");
		goto out;
	}

	ret = save_smack_to_file(smack, fd);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("save_smack_to_file failed");
		goto out;
	}

	ret = PC_OPERATION_SUCCESS;
out:
	if (fd != -1)
		close(fd);
	if (smack != NULL)
		smack_accesses_free(smack);
	return ret;
#else
	return PC_OPERATION_SUCCESS;
#endif
}


