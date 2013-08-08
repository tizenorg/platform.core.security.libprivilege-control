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

#ifndef _ACCESS_DB_H_
#define _ACCESS_DB_H_

/**
 * This function adds app_id to database.
 * Needs to be called by privileged user.
 */
int add_app_id_to_databse(const char * app_id);

/**
 * This function adds anti_virus_id to database.
 * Needs to be called by privileged user.
 */
int add_av_id_to_databse(const char * av_id);

/**
 * This function adds appsetting_id to database.
 * Needs to be called by privileged user.
 */
int add_appsetting_id_to_databse(const char *appsetting_id);

/**
 * This function adds setting_dir_id to database.
 * Needs to be called by privileged user.
 */
int add_setting_dir_id_to_databse(const char *setting_dir_id);


/**
 * This function returns (in params) labels of all installed applications.
 * apps_ids should be freed by caller.
 */
int get_all_apps_ids(char *** apps_ids, int * len);


/**
 * This function returns (in params) labels of all registered settings dirs of
 * all installed applications.
 * apps_ids should be freed by caller.
 */
int get_all_settings_dir_ids(char ***apps_ids, int *len);


/**
 * This function returns (in params) labels of all registered apps with
 * appsettings privilege
 *
 * apps_ids should be freed by caller.
 */
int get_all_appsetting_ids(char ***apps_ids, int *len);

/**
 * This function returns (in params) labels of all installed anti viruses.
 * avs_ids should be freed by caller.
 */
int get_all_avs_ids(char *** av_ids, int * len);

/**
 * This function adds an app to a supplementary group identified by gid
 */
int add_app_gid(const char *app_id, unsigned gid);

/**
 * This function returns (in params) supplementary group ids that an app
 * has been assigned to.
 * gids should be freed by caller.
 */
int get_app_gids(const char *app_id, unsigned **gids, int *len);

/**
 * This functions add public RO path to the database.
 */
int db_add_public_dir(const char *dir_label);

/**
 * This function returns (in params) list of public RO paths
 * dir_labels should be freed by caller.
 */
int db_get_public_dirs(char ***dir_labels, int *len);

#endif // _ACCESS_DB_H_
