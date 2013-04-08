/*
 * libprivilege control
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Janusz Kozerski <j.kozerski@samsung.com>
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
#include <errno.h>
#include <string.h>
#include <sys/smack.h>
#include <dlog.h>

#include "privilege-control.h"

#define SMACK_APPS_LABELS_DATABASE "/opt/dbspace/.privilege_control_all_apps_id.db"
#define SMACK_AVS_LABELS_DATABASE "/opt/dbspace/.privilege_control_all_avs_id.db"

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

typedef enum {
	DB_APP_TYPE_APPLICATION,
	DB_APP_TYPE_ANTIVIRUS,
} db_app_type_t;

typedef struct element_s {
	struct element_s* next;
	char* value;
} element_t;

static element_t* add_element (element_t* elem, const char* value)
{
	C_LOGD("Enter function: %s", __func__);

	if (NULL == elem)
		return NULL;

	element_t* new_element = malloc(sizeof(element_t));
	if (NULL == new_element)
		return NULL;

	new_element->value = malloc(sizeof(char) * (SMACK_LABEL_LEN + 1) );
	if (NULL == new_element->value)
		return NULL;

	strncpy(new_element->value, value, SMACK_LABEL_LEN);
	new_element->value[SMACK_LABEL_LEN] = '\0';
	new_element->next = NULL;
	elem->next = new_element;

	return new_element;
}

static int remove_list(element_t* first_elem)
{
	C_LOGD("Enter function: %s", __func__);

	element_t* current = NULL;

	while (NULL != first_elem) {
		current = first_elem;
		first_elem = first_elem->next;
		free(current);
	}
	return 0;
}

/* TODO: implement such function in libsmack instead -- copied from privilege-control.c*/
static int smack_label_is_valid(const char* smack_label)
{
	C_LOGD("Enter function: %s", __func__);
	int i;

	if (!smack_label || smack_label[0] == '\0' || !smack_label[0] == '-')
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
	C_LOGE("Invalid Smack label: %s", smack_label);
	return 0;
}

static int add_id_to_database_internal(const char * id, db_app_type_t app_type)
{
	C_LOGD("Enter function: %s", __func__);
	int ret;
	FILE* file_db = NULL;
	char* db_type;

	if (DB_APP_TYPE_APPLICATION == app_type) {
		db_type = SMACK_APPS_LABELS_DATABASE;
	}
	else if (DB_APP_TYPE_ANTIVIRUS == app_type) {
		db_type = SMACK_AVS_LABELS_DATABASE;
	}
	else {
		return PC_ERR_INVALID_PARAM;
	}

	file_db = fopen(db_type, "a");
	if (NULL == file_db) {
		C_LOGE("Error while opening database file: %s", db_type);
		ret = PC_ERR_FILE_OPERATION;
		goto out;
	}

	if (0 > fprintf(file_db, "%s\n", id)) {
		C_LOGE("Write label %s to database failed: %s", id, strerror(errno));
		ret = PC_ERR_FILE_OPERATION;
		goto out;
	}

	ret = PC_OPERATION_SUCCESS;

out:
	if (file_db != NULL)
		fclose(file_db);

	return ret;
}

static int get_all_ids_internal (char *** ids, int * len, db_app_type_t app_type)
{
	int ret;
	char* scanf_label_format = NULL;
	FILE* file_db = NULL;
	char* db_type;
	char smack_label[SMACK_LABEL_LEN + 1];
	element_t* begin_of_list = NULL;

	if (DB_APP_TYPE_APPLICATION == app_type) {
		db_type = SMACK_APPS_LABELS_DATABASE;
	} else if (DB_APP_TYPE_ANTIVIRUS == app_type) {
		db_type = SMACK_AVS_LABELS_DATABASE;
	} else {
		return PC_ERR_INVALID_PARAM;
	}

	if (asprintf(&scanf_label_format, "%%%ds\\n", SMACK_LABEL_LEN) < 0) {
		C_LOGE("Error while creating scanf input label format");
		ret = PC_ERR_MEM_OPERATION;
		goto out;
	}

	file_db = fopen(db_type, "r");
	if (NULL == file_db) {
		C_LOGE("Error while opening antivirus_ids database file: %s", db_type);
		ret = PC_ERR_FILE_OPERATION;
		goto out;
	}

	// intialization of list of smack labels
	*len = 0;
	begin_of_list = malloc(sizeof(element_t));
	if (begin_of_list == NULL ) {
		C_LOGE("Error while allocating memory");
		ret = PC_ERR_MEM_OPERATION;
		goto out;
	}
	begin_of_list->next  = NULL;
	begin_of_list->value = NULL;
	element_t* current = begin_of_list;

	// reading from file ("database")
	// notice that first element always stays with empty "value"
	while (fscanf(file_db, scanf_label_format, smack_label) == 1) {
		smack_label[SMACK_LABEL_LEN] = '\0';
		if (!smack_label_is_valid(smack_label)) {
			C_LOGD("Found entry in database, but it's not correct SMACK label: \"%s\"", smack_label);
			continue;
		}
		C_LOGD("Found installed anti virus label: \"%s\"", smack_label);
		++(*len);
		current = add_element(current, smack_label);
		if (NULL == current) {
			C_LOGE("Error while adding smack label to the list");
			ret = PC_ERR_MEM_OPERATION;
			goto out;
		}
	}

	if (*len > 0) {
		C_LOGD("Allocating memory for list of %d labels", *len);
		*ids = malloc((*len) * sizeof(char*));
		if (NULL == *ids) {
			C_LOGE("Error while allocating memory for list of labels");
			ret = PC_ERR_MEM_OPERATION;
			goto out;
		}
		current = begin_of_list->next;
		int i;
		for (i=0; i < *len; ++i) {
			C_LOGD("Allocating memory for \"%s\" label", current->value);
			(*ids)[i] = malloc((SMACK_LABEL_LEN + 1) * sizeof(char));
			if (NULL == (*ids)[i]) {
				ret = PC_ERR_MEM_OPERATION;
				C_LOGE("Error while allocating memory for \"%s\" label", current->value);
				goto out;
			}
			strncpy((*ids)[i], current->value, SMACK_LABEL_LEN);
			(*ids)[i][SMACK_LABEL_LEN] = '\0';
			current = current->next;
		}
	}
	else {
		C_LOGD("Not found any labels!");
		*ids = NULL;
	}

	ret =  PC_OPERATION_SUCCESS;


out:
	if (file_db != NULL)
		fclose(file_db);
	free(scanf_label_format);
	remove_list(begin_of_list);

	return ret;
}

int get_all_apps_ids (char *** apps_ids, int * len)
{
	if (get_all_ids_internal(apps_ids, len, DB_APP_TYPE_APPLICATION))
		return PC_ERR_DB_OPERATION;

	return PC_OPERATION_SUCCESS;
}

int get_all_avs_ids (char *** av_ids, int * len)
{
	if (get_all_ids_internal(av_ids, len, DB_APP_TYPE_ANTIVIRUS))
		return PC_ERR_DB_OPERATION;

	return PC_OPERATION_SUCCESS;
}

int add_app_id_to_databse(const char * app_id)
{
	C_LOGD("Enter function: %s", __func__);

	if (add_id_to_database_internal(app_id, DB_APP_TYPE_APPLICATION))
		return PC_ERR_DB_OPERATION;

	return PC_OPERATION_SUCCESS;
}

int add_av_id_to_databse (const char * av_id)
{
	C_LOGD("Enter function: %s", __func__);

	if (add_id_to_database_internal(av_id, DB_APP_TYPE_ANTIVIRUS))
		return PC_ERR_DB_OPERATION;

	return PC_OPERATION_SUCCESS;
}
