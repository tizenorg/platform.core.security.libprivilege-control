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
int smack_label_is_valid(const char *smack_label)
{
	SECURE_C_LOGD("Entering function: %s. Params: smack_label=%s",
		      __func__, smack_label);

	int i;

	if(!smack_label || smack_label[0] == '\0' || smack_label[0] == '-')
		goto err;

	for(i = 0; smack_label[i]; ++i) {
		if(i >= SMACK_LABEL_LEN)
			goto err;
		switch(smack_label[i]) {
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
	SECURE_C_LOGE("Invalid SMACK label %s", smack_label);
	return 0;
}


int tokenize_rule(const char *const s_rule,
		  char s_subject[],
		  char s_object[],
		  char s_access[])
{
	if(sscanf(s_rule, "%s %s %s", s_subject, s_object, s_access) < 3) {
		C_LOGE("RDB: Failed to tokenize the rule: %s", s_rule);
		return PC_ERR_INVALID_OPERATION;
	}
	return PC_OPERATION_SUCCESS;
}


bool is_wildcard(const char *const s_label)
{
	return 	!strcmp(s_label, "~ALL_APPS~") ||
		!strcmp(s_label, "~ALL_APPS_WITH_SAME_PERMISSION~") ||
		!strcmp(s_label, "~PUBLIC_PATH~") ||
		!strcmp(s_label, "~GROUP_PATH~") ||
		!strcmp(s_label, "~SETTINGS_PATH~");
}


int parse_rule(const char *const s_rule,
	       char s_label[],
	       char s_access[],
	       int *pi_is_reverse)
{
	int ret = PC_OPERATION_SUCCESS;
	char tmp_s_subject[SMACK_LABEL_LEN + 1];
	char tmp_s_object[SMACK_LABEL_LEN + 1];
	char tmp_s_access[ACC_LEN + 1];

	bool b_subject_is_template;
	bool b_object_is_template;

	// Tokenize
	ret = tokenize_rule(s_rule, tmp_s_subject, tmp_s_object, tmp_s_access);
	if(ret != PC_OPERATION_SUCCESS) return ret;

	// Check SMACK_APP_LABEL_TEMPLATE
	b_subject_is_template = (bool) !strcmp(tmp_s_subject, SMACK_APP_LABEL_TEMPLATE);
	b_object_is_template = (bool) !strcmp(tmp_s_object, SMACK_APP_LABEL_TEMPLATE);
	if((b_subject_is_template && b_object_is_template) ||
	    (!b_subject_is_template && !b_object_is_template)) {
		C_LOGE("RDB: Incorrect rule format in rule: %s", s_rule);
		ret = PC_ERR_INVALID_PARAM;
		return ret;
	}

	// Check label validity and copy rules
	if(b_subject_is_template) {
		// Not reversed
		if(!smack_label_is_valid(tmp_s_object) &&
		    !is_wildcard(tmp_s_object)) {
			C_LOGE("RDB: Incorrect subject label: %s", tmp_s_object);
			return ret;
		}
		strcpy(s_label, tmp_s_object);
		if(pi_is_reverse != NULL) *pi_is_reverse = 0;
	} else if(b_object_is_template) {
		// Reversed
		if(!smack_label_is_valid(tmp_s_subject) &&
		    !is_wildcard(tmp_s_subject)) {
			C_LOGE("RDB: Incorrect subject label: %s", tmp_s_subject);
			return ret;
		}
		strcpy(s_label, tmp_s_subject);
		if(pi_is_reverse != NULL) *pi_is_reverse = 1;
	}
	strcpy(s_access, tmp_s_access);

	return PC_OPERATION_SUCCESS;
}


int validate_all_rules(const char *const *const pp_permissions_list)
{
	int i;
	char s_label[SMACK_LABEL_LEN + 1];
	char s_access[ACC_LEN + 1];

	// Parse and check rules.
	for(i = 0; pp_permissions_list[i] != NULL; ++i) {
		// C_LOGE("RDB: Validating rules: %s", pp_permissions_list[i]);

		// Ignore empty lines
		if(strspn(pp_permissions_list[i], " \t\n")
		    == strlen(pp_permissions_list[i]))
			continue;

		if(parse_rule(pp_permissions_list[i], s_label, s_access, NULL)
		    != PC_OPERATION_SUCCESS) {
			C_LOGE("RDB: Invalid parameter");
			return PC_ERR_INVALID_PARAM;
		}

		// Check the other label
		if(!is_wildcard(s_label) &&
		    !smack_label_is_valid(s_label)) {
			C_LOGE("RDB: Incorrect object label: %s", s_label);
			return PC_ERR_INVALID_PARAM;
		}
	}

	return PC_OPERATION_SUCCESS;
}

/* Auto cleanup stuff */
void freep(void *p)
{
	free(*(void **) p);
}

void closep(int *fd)
{
	if(*fd >= 0)
		close(*fd);
}

void fclosep(FILE **f)
{
	if(*f)
		fclose(*f);
}

void smack_freep(struct smack_accesses **smack)
{
	smack_accesses_free(*smack);
}

void fts_closep(FTS **f)
{
	if(*f)
		fts_close(*f);

}

static int load_smack_from_file_generic(const char *app_id, struct smack_accesses **smack, int *fd, char **path, bool is_early)
{
	/* Notice that app_id is ignored when flag is_early is set.
	 * It's because all of the "early rules" (for all apps) should
	 * be in one common file: SMACK_STARTUP_RULES_FILE
	 */
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
		      __func__, app_id);

	int ret;

	if(is_early) {
		if(0 > asprintf(path, "%s", SMACK_STARTUP_RULES_FILE)) {
			*path = NULL;
			C_LOGE("asprintf failed.");
			return PC_ERR_MEM_OPERATION;
		}
	} else {
		ret = smack_file_name(app_id, path);
		if(ret != PC_OPERATION_SUCCESS)
			return ret;
	}

	if(smack_accesses_new(smack)) {
		C_LOGE("smack_accesses_new failed.");
		return PC_ERR_MEM_OPERATION;
	}

	*fd = open(*path, O_CREAT | O_RDWR, 0644);
	if(*fd == -1) {
		C_LOGE("file open failed (error: %s)", strerror(errno));
		return PC_ERR_FILE_OPERATION;
	}

	if(flock(*fd, LOCK_EX)) {
		C_LOGE("flock failed");
		return PC_ERR_INVALID_OPERATION;
	}

	if(smack_accesses_add_from_file(*smack, *fd)) {
		C_LOGE("smack_accesses_add_from_file failed.");
		return PC_ERR_INVALID_OPERATION;
	}

	/* Rewind the file */
	if(lseek(*fd, 0, SEEK_SET) == -1) {
		C_LOGE("lseek failed.");
		return PC_ERR_FILE_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

int load_smack_from_file(const char *app_id, struct smack_accesses **smack, int *fd, char **path)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
		      __func__, app_id);

	return load_smack_from_file_generic(app_id, smack, fd, path, 0);
}

int load_smack_from_file_early(const char *app_id, struct smack_accesses **smack, int *fd, char **path)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
		      __func__, app_id);

	return load_smack_from_file_generic(app_id, smack, fd, path, 1);
}

int smack_mark_file_name(const char *app_id, char **path)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
		      __func__, app_id);

	if(asprintf(path, SMACK_LOADED_APP_RULES "/%s", app_id) == -1) {
		C_LOGE("asprintf failed.");
		*path = NULL;
		return PC_ERR_MEM_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

bool file_exists(const char *path)
{
	SECURE_C_LOGD("Entering function: %s. Params: path=%s",
		      __func__, path);

	SECURE_C_LOGD("Opening file %s.", path);
	FILE *file = fopen(path, "r");
	if(file) {
		fclose(file);
		return true;
	}
	return false;
}

int smack_file_name(const char *app_id, char **path)
{
	SECURE_C_LOGD("Entering function: %s. Params: app_id=%s",
		      __func__, app_id);

	if(asprintf(path, SMACK_RULES_DIR "/%s", app_id) == -1) {
		C_LOGE("asprintf failed.");
		*path = NULL;
		return PC_ERR_MEM_OPERATION;
	}

	return PC_OPERATION_SUCCESS;
}

inline int have_smack(void)
{
	SECURE_C_LOGD("Entering function: %s.", __func__);

	static int have_smack = -1;

	if(-1 == have_smack) {
		if(NULL == smack_smackfs_path()) {
			C_LOGD("Libprivilege-control: no smack found on phone");
			have_smack = 0;
		} else {
			C_LOGD("Libprivilege-control: found smack on phone");
			have_smack = 1;
		}
	}

	return have_smack;
}