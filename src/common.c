/*
 * libprivilege control
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Rafal Krypa <r.krypa@samsung.com>
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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/smack.h>
#include <sys/stat.h>
#include <sys/file.h>

#include "common.h"
#include "privilege-control.h"

/* TODO: implement such function in libsmack instead */
int smack_label_is_valid(const char* smack_label)
{
	C_LOGD("Enter function: %s", __func__);
	int i;

	if (!smack_label || smack_label[0] == '\0' || smack_label[0] == '-')
		goto err;

	for (i = 0; smack_label[i]; ++i) {
		if (i >= SMACK_LABEL_LEN)
			return 0;
		switch (smack_label[i]) {
		case '~':
		case ' ':
		case '/':
		case '"':
		case '\\':
		case '\'':
			goto err;
		default:
			break;
		}
	}

	return 1;
err:
	C_LOGD("Invalid Smack label: %s", smack_label);
	return 0;
}

/* Auto cleanup stuff */
void freep(void *p)
{
	free(*(void**) p);
}

void closep(int *fd)
{
	if (*fd >= 0)
		close(*fd);
}

void fclosep(FILE **f)
{
	if (*f)
		fclose(*f);
}

void smack_freep(struct smack_accesses **smack)
{
	smack_accesses_free(*smack);
}

void fts_closep(FTS **f)
{
	if (*f)
		fts_close(*f);

}

/**
 * This function checks if SMACK rules of application were already loaded
 * by checking if specific file exist. This function doesn't create such file.
 * Return values:
 *  0 if rules weren't yet loaded,
 *  1 if rules were loaded
 * -1 if error occurs while checking
 */
int check_if_rules_were_loaded(const char *app_id)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	char *path AUTO_FREE;

	ret = smack_mark_file_name(app_id, &path);
	if(PC_OPERATION_SUCCESS != ret) {
		return -1;
	}

	return file_exists(path);
}

/**
 * This function marks that rules for app were already loaded by creating
 * specific for this app (empty) file.
 */
void mark_rules_as_loaded(const char *app_id)
{
	struct stat s;
	char *path AUTO_FREE;
	FILE *file = NULL;

	if(smack_mark_file_name(app_id, &path)) {
		C_LOGE("Error in smack_mark_file_name");
		return;
	}

	if (-1 == stat(SMACK_LOADED_APP_RULES, &s)) {
		if (ENOENT == errno) {
			C_LOGD("Creating dir %s", SMACK_LOADED_APP_RULES);
			mkdir(SMACK_LOADED_APP_RULES, S_IRWXU | S_IRWXG | S_IRWXO);
		}
	}

	file = fopen(path, "w");
	fclose(file);
}

int add_app_first_run_rules(const char *app_id)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	int fd AUTO_CLOSE;
	char *smack_path AUTO_FREE;
	struct smack_accesses* smack AUTO_SMACK_FREE;

	ret = load_smack_from_file(app_id, &smack, &fd, &smack_path);
	if (ret != PC_OPERATION_SUCCESS) {
		C_LOGE("Error in load_smack_from_file");
		return ret;
	}
	if (have_smack() && smack_accesses_apply(smack)) {
		C_LOGE("smack_accesses_apply failed");
		return PC_ERR_INVALID_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}


static int load_smack_from_file_generic(const char* app_id, struct smack_accesses** smack, int *fd, char** path, bool is_early)
{
	/* Notice that app_id is ignored when flag is_early is set.
	 * It's because all of the "early rules" (for all apps) should
	 * be in one common file: SMACK_STARTUP_RULES_FILE
	 */
	C_LOGD("Enter function: %s", __func__);
	int ret;

	if (is_early) {
		if (0 > asprintf(path, "%s", SMACK_STARTUP_RULES_FILE)) {
			*path = NULL;
			C_LOGE("asprintf failed");
			return PC_ERR_MEM_OPERATION;
		}
	}
	else {
		ret = smack_file_name(app_id, path);
		if (ret != PC_OPERATION_SUCCESS)
			return ret;
	}

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

int load_smack_from_file(const char* app_id, struct smack_accesses** smack, int *fd, char** path)
{
	return load_smack_from_file_generic(app_id, smack, fd, path, 0);
}

int load_smack_from_file_early(const char* app_id, struct smack_accesses** smack, int *fd, char** path)
{
	return load_smack_from_file_generic(app_id, smack, fd, path, 1);
}

int smack_mark_file_name(const char *app_id, char **path)
{
	if (asprintf(path, SMACK_LOADED_APP_RULES "/%s", app_id) == -1) {
		C_LOGE("asprintf failed");
		*path = NULL;
		return PC_ERR_MEM_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

bool file_exists(const char* path) {
	FILE* file = fopen(path, "r");
	if (file) {
		fclose(file);
		return true;
	}
	return false;
}

int smack_file_name(const char* app_id, char** path)
{
	if (asprintf(path, SMACK_RULES_DIR "/%s", app_id) == -1) {
		C_LOGE("asprintf failed");
		*path = NULL;
		return PC_ERR_MEM_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

inline int have_smack(void)
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
