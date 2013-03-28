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
#include <stdbool.h>

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

#define SMACK_APP_LABEL_TEMPLATE "~APP~"
#define SMACK_SRC_FILE_SUFFIX   "_src_file"
#define SMACK_SRC_DIR_SUFFIX    "_src_dir"
#define SMACK_DATA_SUFFIX       "_data"
#define WRT_BASE_DEVCAP         "WRT"
#define WRT_CLIENT_PATH         "/usr/bin/wrt-client"

#ifdef SMACK_ENABLED
static int set_smack_for_wrt(const char* widget_id);
#endif

#ifdef LOG_TAG
    #undef LOG_TAG
#endif // LOG_TAG
#ifndef LOG_TAG
    #define LOG_TAG "PRIVILEGE_CONTROL"
#endif // LOG_TAG

// conditional log macro for dlogutil (debug)
#ifdef DLOG_DEBUG_ENABLED
#define C_LOGD(...) LOGD(__VA_ARGS__)
#else
#define C_LOGD(...) do { } while(0)
#endif //DDLOG_DEBUG_ENABLED

// conditional log macro for dlogutil (error)
#ifdef DLOG_ERROR_ENABLED
#define C_LOGE(...) LOGE(__VA_ARGS__)
#else
#define C_LOGE(...) do { } while(0)
#endif //DLOG_ERROR_ENABLED

typedef struct {
	char user_name[10];
	int uid;
	int gid;
	char home_dir[64];
	char group_list[64];
} new_user;

static inline int have_smack(void)
{
	static int have_smack = -1;

	if (-1 == have_smack) {
		int fd = open("/smack/load2", O_WRONLY);
		if (-1 == fd) {
			C_LOGD("Libprivilage-control: no smack found on phone");
			have_smack = 0;
		} else {
			C_LOGD("Libprivilege-control: found smack on phone");
			close(fd);
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
	if (!have_smack())
		return PC_OPERATION_SUCCESS;

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
#endif // SMACK_ENABLED

API int set_app_privilege(const char* name, const char* type, const char* path)
{
	C_LOGD("Enter function: %s", __func__);
	C_LOGD("Function params: name = %s, type = %s, path = %s", name, type, path);
#ifdef SMACK_ENABLED
	const char* widget_id;
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
			ret = set_smack_for_wrt(widget_id);
		break;
	default:
		if (path != NULL)
			ret = set_smack_from_binary(path);
		break;
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

#ifdef SMACK_ENABLED
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

static int perm_to_smack(struct smack_accesses* smack, const char* app_label, app_type_t app_type, const char* perm)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	char* path = NULL;
	char* format_string = NULL;
	FILE* file = NULL;
	char smack_subject[SMACK_LABEL_LEN + 1];
	char smack_object[SMACK_LABEL_LEN + 1];
	char smack_accesses[10];
	const char* app_type_prefix;
	const char* perm_suffix;

	app_type_prefix = app_type_name(app_type);

	perm_suffix = strrchr(perm, '/');
	if (perm_suffix)
		++perm_suffix;
	else
		perm_suffix = perm;

	ret = asprintf(&path, TOSTRING(SHAREDIR) "/%s%s%s.smack",
			app_type_prefix ? app_type_prefix : "", app_type_prefix ? "_" : "", perm_suffix);
	if (ret == -1) {
		C_LOGE("asprintf failed");
		ret = PC_ERR_MEM_OPERATION;
		goto out;
	}

	if (asprintf(&format_string,"%%%ds %%%ds %%%lus\n",
			SMACK_LABEL_LEN, SMACK_LABEL_LEN, (unsigned long)sizeof(smack_accesses)) == -1) {
		C_LOGE("asprintf failed");
		ret = PC_ERR_MEM_OPERATION;
		goto out;
	}

	file = fopen(path, "r");
	C_LOGD("path = %s", path);
	if (file == NULL) {
		C_LOGE("fopen failed");
		ret = PC_OPERATION_SUCCESS;
		goto out;
	}

	ret = PC_OPERATION_SUCCESS;
	while (fscanf(file, format_string, smack_subject, smack_object, smack_accesses) == 3) {
		if (!strcmp(smack_subject, SMACK_APP_LABEL_TEMPLATE))
			strcpy(smack_subject, app_label);

		if (!strcmp(smack_object, SMACK_APP_LABEL_TEMPLATE))
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

static int set_smack_for_wrt(const char* widget_id)
{
	C_LOGD("Enter function: %s", __func__);
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
#endif

API char* app_id_from_socket(int sockfd)
{
	C_LOGD("Enter function: %s", __func__);
	if (!have_smack())
		return NULL;

#ifdef SMACK_ENABLED
	char* app_id;
	int ret;

	ret = smack_new_label_from_socket(sockfd, &app_id);
	if (ret != 0) {
		C_LOGE("smack_new_label_from_socket failed");
		return NULL;
	}

	C_LOGD("app_id: %s", app_id);

	return app_id;
#else
	return NULL;
#endif
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

#ifdef SMACK_ENABLED
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
#endif

static int app_add_permissions_internal(const char* app_id, app_type_t app_type, const char** perm_list, int permanent)
{
	C_LOGD("Enter function: %s", __func__);
#ifdef SMACK_ENABLED
	char* smack_path = NULL;
	int i, ret;
	int fd = -1;
	struct smack_accesses *smack = NULL;
	const char* base_perm = NULL;

	ret = load_smack_from_file(app_id, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		goto out;
	}

	/* Implicitly enable base permission for an app_type */
	base_perm = app_type_name(app_type);
	if (base_perm) {
		C_LOGD("perm_to_smack params: app_id: %s, %s", app_id, base_perm);
		ret = perm_to_smack(smack, app_id, APP_TYPE_OTHER, base_perm);
		if (ret != PC_OPERATION_SUCCESS){
			C_LOGE("perm_to_smack failed");
			goto out;
		}
	}

	for (i = 0; perm_list[i] != NULL; ++i) {
		C_LOGD("perm_to_smack params: app_id: %s, perm_list[%d]: %s", app_id, i, perm_list[i]);
		ret = perm_to_smack(smack, app_id, app_type, perm_list[i]);
		if (ret != PC_OPERATION_SUCCESS){
			C_LOGE("perm_to_smack failed");
			goto out;
		}
	}

	if (have_smack() && smack_accesses_apply(smack)) {
		C_LOGE("smack_accesses_apply failed");
		ret = PC_ERR_INVALID_OPERATION;
		goto out;
	}

	if (permanent && smack_accesses_save(smack, fd)) {
		C_LOGE("smack_accesses_save failed");
		ret = PC_ERR_INVALID_OPERATION;
		goto out;
	}

	ret = PC_OPERATION_SUCCESS;
out:
	if (fd != -1)
		close(fd);
	if (smack != NULL)
		smack_accesses_free(smack);
	free(smack_path);

	return ret;
#else
	return PC_OPERATION_SUCCESS;
#endif
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

API int app_revoke_permissions(const char* app_id)
{
	C_LOGD("Enter function: %s", __func__);
#ifdef SMACK_ENABLED
	char* smack_path = NULL;
	int ret;
	int fd = -1;
	struct smack_accesses *smack = NULL;

	ret = load_smack_from_file(app_id, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		goto out;
	}

	if (have_smack() && smack_accesses_clear(smack)) {
		ret = PC_ERR_INVALID_OPERATION;
		C_LOGE("smack_accesses_clear failed");
		goto out;
	}

	if (have_smack() && smack_revoke_subject(app_id)) {
		ret = PC_ERR_INVALID_OPERATION;
		C_LOGE("smack_revoke_subject failed");
		goto out;
	}

	ret = PC_OPERATION_SUCCESS;
out:
	if (fd != -1)
		close(fd);
	if (smack != NULL)
		smack_accesses_free(smack);
	free(smack_path);

	return ret;
#else
	return PC_OPERATION_SUCCESS;
#endif
}

API int app_reset_permissions(const char* app_id)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;

	ret = app_revoke_permissions(app_id);
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
	char* smack_path = NULL;
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

	ret = load_smack_from_file(app_label, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		goto out;
	}

	//setting access rule for application
	if (smack_accesses_add(smack, app_label,shared_label, "wrxat") == -1) {
		C_LOGE("smack_accesses_add failed");
		goto out;
	}

	if (have_smack() && smack_accesses_apply(smack)) {
		C_LOGE("smack_accesses_apply failed");
		ret =  PC_ERR_INVALID_OPERATION;
		goto out;
	}

	if (smack_accesses_save(smack, fd)) {
		C_LOGE("smack_accesses_save failed");
		ret =  PC_ERR_INVALID_OPERATION;
		goto out;
	}

	ret = PC_OPERATION_SUCCESS;
out:
	if (fd != -1)
		close(fd);
	if (smack != NULL)
		smack_accesses_free(smack);
	free(smack_path);

	return ret;
#else
	return PC_OPERATION_SUCCESS;
#endif
}

API int add_shared_dir_readers(const char* shared_label, const char** app_list)
{
	// TODO this needs to be fully implemented
	C_LOGD("Enter function: %s", __func__);
	return PC_OPERATION_SUCCESS;
}

API int app_add_friend(const char* app_id1, const char* app_id2)
{
	C_LOGD("Enter function: %s", __func__);
#ifdef SMACK_ENABLED
	int ret;
	int fd1 = -1, fd2 = -1;
	char* smack_path1 = NULL;
	char* smack_path2 = NULL;
	struct smack_accesses* smack1 = NULL;
	struct smack_accesses* smack2 = NULL;

	ret = load_smack_from_file(app_id1, &smack1, &fd1, &smack_path1);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		goto out;
	}

	ret = load_smack_from_file(app_id2, &smack2, &fd2, &smack_path2);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("load_smack_from_file failed");
		goto out;
	}

	if (smack_accesses_add(smack1, app_id1, app_id2, "wrxat") == -1 ||
		(smack_accesses_add(smack2, app_id2, app_id1, "wrxat") == -1)) {
		C_LOGE("smack_accesses_add failed");
		goto out;
	}

	if (have_smack() &&
		(smack_accesses_apply(smack1) || smack_accesses_apply(smack2))) {
		C_LOGE("smack_accesses_apply failed");
		ret =  PC_ERR_INVALID_OPERATION;
		goto out;
	}

	if (smack_accesses_save(smack1, fd1) || smack_accesses_save(smack2, fd2)) {
		C_LOGE("smack_accesses_save failed");
		ret =  PC_ERR_INVALID_OPERATION;
		goto out;
	}

	ret = PC_OPERATION_SUCCESS;

out:
	if (fd1 != -1)
		close(fd1);
	if (fd2 != -1)
		close(fd2);
	smack_accesses_free(smack1);
	smack_accesses_free(smack2);
	free(smack_path1);
	free(smack_path2);

	return ret;
#else
	return PC_OPERATION_SUCCESS;
#endif
}

API int app_install(const char* app_id)
{
	C_LOGD("Enter function: %s", __func__);
	char* smack_path = NULL;
	int ret, fd = -1;

	ret = smack_file_name(app_id, &smack_path);
	if (ret != PC_OPERATION_SUCCESS)
		goto out;

	fd = open(smack_path, O_RDWR|O_EXCL|O_CREAT, 0644);
	if (fd == -1) {
		C_LOGE("file open failed: %s", strerror(errno));
		ret = PC_ERR_FILE_OPERATION;
		goto out;
	}

	ret = PC_OPERATION_SUCCESS;

out:
	free(smack_path);
	if (fd != -1)
		close(fd);

	return ret;
}

API int app_uninstall(const char* app_id)
{
	C_LOGD("Enter function: %s", __func__);
	char* smack_path = NULL;
	int ret;

	ret = smack_file_name(app_id, &smack_path);
	if (ret != PC_OPERATION_SUCCESS)
		goto out;

	if (unlink(smack_path)) {
		C_LOGE("unlink failed: ", strerror(errno));
		ret = PC_ERR_INVALID_OPERATION;
		goto out;
	}

	ret = PC_OPERATION_SUCCESS;

out:
	free(smack_path);

	return ret;
}
