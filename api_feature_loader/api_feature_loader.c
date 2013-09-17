/*
 * libprivilege control, rules database
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Jan Olszak <j.olszak@samsung.com>
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

/**
* @file        api_feature_loader.c
* @author      Jan Olszak (j.olszak@samsung.com)
* @version     1.0
* @brief       Binary file for loading predefined API features to the database.
*/

#define _GNU_SOURCE
#include <stdio.h>              // For file manipulation
#include <stdlib.h>             // For malloc and free
#include <dirent.h>             // For iterating directories
#include <obstack.h>            // For obstack implementation
#include <privilege-control.h>  // For app_type
#include <sys/smack.h>          // For SMACK_LABEL_LEN
#include <getopt.h>             // For getopt


#define API_FEATURE_LOADER_VERSION "1.0"

#define obstack_chunk_alloc malloc
#define obstack_chunk_free  free

#define vector_init(V)              obstack_init(&(V))
#define vector_push_back_ptr(V, I)  obstack_ptr_grow(&(V), (I))
#define vector_finish(V)            obstack_finish(&(V))
#define vector_free(V)              obstack_free(&(V), NULL)

#define ACC_LEN 6

#define API_FEATURES_DIR "/usr/share/privilege-control/"

#define API_FEATURE_LOADER_LOG(format, ...) if(i_verbose_flag__) printf(format, ##__VA_ARGS__)

typedef struct obstack vector_t;
static int i_verbose_flag__ = 0;
static const size_t ui_smack_ext_len__ = 6; // = strlen(".smack");

bool has_prefix(const char *const s_str, const char *const s_prefix)
{
	return !strncmp(s_str, s_prefix, strlen(s_prefix));
}

bool has_smack_ext(const char *const s_str)
{
	return strlen(s_str) > ui_smack_ext_len__ &&
	       !strncmp(&s_str[strlen(s_str) - ui_smack_ext_len__], ".smack", ui_smack_ext_len__);
}

int wrt_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "WRT.smack");
}

int wrt_partner_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "WRT_partner.smack");
}

int wrt_platform_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "WRT_platform.smack");
}

int wrt_family_filter(const struct dirent *entry)
{
	return has_prefix(entry->d_name, "WRT_") &&
	       !has_prefix(entry->d_name, "WRT_partner") &&
	       !has_prefix(entry->d_name, "WRT_platform") &&
	       has_smack_ext(entry->d_name);
}

int osp_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "OSP.smack");
}

int osp_partner_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "OSP_partner.smack");
}

int osp_platform_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "OSP_platform.smack");
}

int osp_family_filter(const struct dirent *entry)
{
	return has_prefix(entry->d_name, "OSP_") &&
	       !has_prefix(entry->d_name, "OSP_partner") &&
	       !has_prefix(entry->d_name, "OSP_platform") &&
	       has_smack_ext(entry->d_name);
}

int efl_filter(const struct dirent *entry)
{
	return !strcmp(entry->d_name, "EFL.smack");
}

int efl_family_filter(const struct dirent *entry)
{
	return has_prefix(entry->d_name, "EFL_") &&
	       has_smack_ext(entry->d_name);
}

void load_rules_from_file(const char *s_rules_file_path,
			  const char *s_permission_name,
			  const app_type_t app_type)
{
	FILE *p_file       = NULL;
	char *s_rule       = NULL;
	char **rules_array = NULL;
	size_t i_num_rules = 0;
	size_t i           = 0;
	int ret;
	vector_t rules_vector;

	p_file = fopen(s_rules_file_path, "r");
	if(!p_file) goto finish;

	API_FEATURE_LOADER_LOG("Loading permission: %s  \n", s_permission_name);

	vector_init(rules_vector);
	while(getline(&s_rule, &i, p_file) > 0) {
		vector_push_back_ptr(rules_vector, s_rule);
		++i_num_rules;
		s_rule = NULL;
	}
	vector_push_back_ptr(rules_vector, NULL);

	rules_array = vector_finish(rules_vector);

	ret = perm_add_api_feature(app_type,
				   s_permission_name,
				   (const char **)rules_array,
				   NULL,
				   i_num_rules);
	if(ret != PC_OPERATION_SUCCESS)
		API_FEATURE_LOADER_LOG("Error %d\n", ret);

finish:
	if(p_file != NULL) fclose(p_file);
	if(rules_array != NULL) {
		for(i = 0; i < i_num_rules; ++i) {
			free(rules_array[i]);
		}
		vector_free(rules_vector);
	}
}

void load_permission_family(int (*filter)(const struct dirent *),
			    int i_prefix_len,
			    const app_type_t app_type,
			    const char const *s_dir)
{
	int i, num_files          = 0;
	struct dirent **file_list = NULL;
	char *s_path              = NULL;
	char *s_permission_name   = NULL;
	int i_perm_name_len;

	num_files = scandir(s_dir, &file_list, filter, alphasort);
	for(i = 0; i < num_files; ++i) {
		if(asprintf(&s_path, "%s%s", s_dir, file_list[i]->d_name) <= 0) continue;

		i_perm_name_len = strlen(file_list[i]->d_name);
		s_permission_name = (char *) malloc(i_perm_name_len);
		if(!s_permission_name) {
			API_FEATURE_LOADER_LOG("Error during allocating memory.\n");
			return;
		}
		strncpy(s_permission_name,
			&(file_list[i]->d_name[i_prefix_len]),
			i_perm_name_len - i_prefix_len - ui_smack_ext_len__);
		s_permission_name[i_perm_name_len - i_prefix_len - ui_smack_ext_len__ ] = '\0';
		load_rules_from_file(s_path, s_permission_name, app_type);

		free(file_list[i]);
		free(s_path);
		free(s_permission_name);
		s_path = NULL;
		s_permission_name = NULL;
	}
	free(file_list);
}

void load_pemission_type_rules(int (*filter)(const struct dirent *),
			       const char const *s_permission_name,
			       const app_type_t app_type,
			       const char const *s_dir)
{
	char *s_path              = NULL;
	struct dirent **file_list = NULL;
	int i, num_files;

	num_files = scandir(s_dir, &file_list, filter, alphasort);
	for(i = 0; i < num_files; ++i) {
		if(asprintf(&s_path, "%s%s", API_FEATURES_DIR, file_list[i]->d_name) <= 0) continue;

		load_rules_from_file(s_path, s_permission_name, app_type);

		if(file_list[i]) free(file_list[i]);
		if(s_path) free(s_path);
		s_path = NULL;
	}
	free(file_list);
}


void load_from_dir(const char  *const s_dir)
{

	API_FEATURE_LOADER_LOG("Loading rules from directory...\n");
	if(perm_modification_start()) return;

	// Load rules specific to permission's types:
	load_pemission_type_rules(wrt_filter, "WRT", APP_TYPE_WGT, s_dir);
	load_pemission_type_rules(wrt_partner_filter, "WRT_partner", APP_TYPE_WGT_PARTNER, s_dir);
	load_pemission_type_rules(wrt_platform_filter, "WRT_platform", APP_TYPE_WGT_PLATFORM, s_dir);
	load_pemission_type_rules(osp_filter, "OSP", APP_TYPE_OSP, s_dir);
	load_pemission_type_rules(osp_partner_filter, "OSP_partner" , APP_TYPE_OSP_PARTNER, s_dir);
	load_pemission_type_rules(osp_platform_filter, "OSP_platform", APP_TYPE_OSP_PLATFORM, s_dir);
	load_pemission_type_rules(efl_filter, "EFL", APP_TYPE_EFL, s_dir);

	// Load rules for each permission type:
	load_permission_family(wrt_family_filter, strlen("WRT_"), APP_TYPE_WGT, s_dir);
	load_permission_family(osp_family_filter, strlen("OSP_"), APP_TYPE_OSP, s_dir);
	load_permission_family(efl_family_filter, strlen("EFL_"), APP_TYPE_EFL, s_dir);

	perm_modification_finish();
	API_FEATURE_LOADER_LOG("Done.\n");

}

int main(int argc, char *argv[])
{
	int c;
	int i_option_index = 0;

	bool b_load_from_file = false;
	const char *s_file;

	bool b_load_from_dir = false;
	const char *s_dir;

	static struct option long_options[] = {
		{"verbose", no_argument,       &i_verbose_flag__,  1},
		{"file",    required_argument, 0, 'f'},
		{"dir",     required_argument, 0, 'd'},
		{"help",    no_argument,       0, 'h'},
		{"version", no_argument,       0, 'v'},
		{0, 0, 0, 0}
	};

	while((c = getopt_long(argc, argv,
			       "f:d:hav",
			       long_options,
			       &i_option_index)) != -1) {
		switch(c) {
		case 0:
			// If this option set a flag, do nothing.
			break;
		case '?':
			// No such command.
			// getopt_long already printed an error message.
			return 0;
		case 'f':
			b_load_from_file = true;
			s_file = optarg;
			break;

		case 'd':
			b_load_from_dir = false;
			s_dir = optarg;
			break;

		case 'h':
			printf("Api feature loader v." API_FEATURE_LOADER_VERSION "\n\n");
			printf("    Options:\n");
			printf("        -d,--dir=path        load api-features from the directory\n");
			printf("        -f,--file=file_name  load api-feature from the file\n");
			printf("        -h,--help            print this help\n");
			printf("        --verbose            verbose output\n");
			printf("        -v,--version         show applcation version\n");

			return 0;

		case 'v':
			printf("Api feature loader v." API_FEATURE_LOADER_VERSION "\n");
			return 0;

		default:
			break;
		}
	}

	// Print unknown remaining command line arguments
	if(optind < argc) {
		printf("Unknown options: ");
		while(optind < argc)
			printf("%s ", argv[optind++]);
		putchar('\n');
		return 0;
	}


	if(b_load_from_dir) load_from_dir(s_dir);

	if(b_load_from_file) {
		// TODO: Call the function that loads the permission from a file.
	}

	// By default we load from API_FEATURES_DIR
	load_from_dir(API_FEATURES_DIR);

	return 0;

}


