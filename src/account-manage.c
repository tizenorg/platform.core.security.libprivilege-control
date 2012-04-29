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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include "privilege-control.h"
#include <openssl/md2.h>

#define FIRST_UID		20001
#define USERNAME_SIZE	128
#define HOMEDIR_SIZE	128
#define FILENAME_SIZE	128
#define PASSWD_LINE		256
#define GROUP_LINE		256

#define base64table	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#define base64pad	'='

int md2_hashing(unsigned char* in, unsigned char* out)
{
	MD2_CTX mctx;

	if(!MD2_Init(&mctx))
		return PC_ERR_INVALID_PARAM;
	if(!MD2_Update(&mctx, in, strlen((char*)in)))
		return PC_ERR_INVALID_PARAM;
	if(!MD2_Final(out, &mctx))
		return PC_ERR_INVALID_PARAM;

	return PC_OPERATION_SUCCESS;
}

int base64_encode(unsigned char* in, unsigned long int in_len, char** out, unsigned long int* out_len)
{
	unsigned char* current = in;
	long int out_num = 0;
	int str_len = 0;

	if((in == NULL) || (in_len <= 0) || (out == NULL))
		return -1;	// error

	*out_len = (((in_len + 2) / 3) * 4) + 1;
	*out = (char*)malloc(*out_len);

	if(*out == NULL)
		return 0;

	while(in_len > 2) 
	{
		/* keep going until we have less than 24 bits */
		((char*)*out)[out_num++] = base64table[current[0] >> 2];
		((char*)*out)[out_num++] = base64table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
		((char*)*out)[out_num++] = base64table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
		((char*)*out)[out_num++] = base64table[current[2] & 0x3f];

		current += 3;
		in_len -= 3;
		str_len += 4;
	}
	/* now deal with the tail end of things */
	if (in_len != 0) 
	{
		((char*)*out)[out_num++] = base64table[current[0] >> 2];
		if (in_len > 1) 
		{
			((char*)*out)[out_num++] = base64table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
			((char*)*out)[out_num++] = base64table[(current[1] & 0x0f) << 2];
			((char*)*out)[out_num++] = base64pad;
		}
		else 
		{
			((char*)*out)[out_num++] = base64table[(current[0] & 0x03) << 4];
			((char*)*out)[out_num++] = base64pad;
			((char*)*out)[out_num++] = base64pad;
		}
		str_len += 4;
	}
	((char*)*out)[out_num++] = '\0';

	return PC_OPERATION_SUCCESS;
}

int convert_user_name_from_pkgname(const char* pkg_name, char* user_name)
{
	char* hashing = NULL;
	char* base64 = NULL;
	unsigned long int len = 0;
	int ret = PC_OPERATION_SUCCESS;
	
	if(!pkg_name || !user_name)
	{
		ret = PC_ERR_INVALID_PARAM;
		goto err;
	}

	hashing = (char*)malloc(sizeof(char) * MD2_DIGEST_LENGTH);
	memset(hashing, 0x00, MD2_DIGEST_LENGTH);

	if(md2_hashing((unsigned char*)pkg_name, (unsigned char*)hashing) != PC_OPERATION_SUCCESS)
	{
		fprintf(stderr, "[ERR] Fail to hashing\n");
		ret = PC_ERR_INVALID_OPERATION;
		goto err;
	}

	if(base64_encode((unsigned char*)hashing, MD2_DIGEST_LENGTH, &base64, &len) != PC_OPERATION_SUCCESS)
	{
		fprintf(stderr, "[ERR] Fail to encode\n");
		ret = PC_ERR_INVALID_OPERATION;
		goto err;
	}

	strncpy(user_name, base64, 16);
	user_name[16] = '\0';
	
err:
	if(hashing != NULL)
		free(hashing);
	return ret;
}

API int add_user_and_group(const char* pkg_name, const char* permissions)
{	
	FILE* fp_passwd = NULL;
	FILE* fp_passwd2 = NULL;
	FILE* fp_group = NULL;
	FILE* fp_group2 = NULL;
	FILE* fp_perm = NULL;
	char user_name[USERNAME_SIZE];
	char homedir[HOMEDIR_SIZE];
	char linebuf[USERNAME_SIZE + HOMEDIR_SIZE + 128];
	char linebuf2[USERNAME_SIZE + 20];
	char buf_passwd[PASSWD_LINE];
	char buf_group[GROUP_LINE];
	char conf_filename[FILENAME_SIZE];
	char perm_group[20];
	char chown_cmd[32];
	char str_orig[256];
	char seps[] = ", \t\n\r";
	int result = PC_OPERATION_SUCCESS;
	int uid = -1, gid = -1, i = 0, cnt = 0, flag = 0;
	char* expr = "3rd party user\0";
	char* shell = "/bin/sh\0";
	char* linebuf3 = NULL;
	char* tempbuf = NULL;
	char* token = NULL;
	int inputed, pid, ret;

	memset(user_name, 0x00, USERNAME_SIZE);
	memset(homedir, 0x00, HOMEDIR_SIZE);
	memset(linebuf, 0x00, (USERNAME_SIZE + HOMEDIR_SIZE + 128));
	memset(linebuf2, 0x00, (USERNAME_SIZE + 20));
	memset(buf_passwd, 0x00, PASSWD_LINE);
	memset(buf_group, 0x00, GROUP_LINE);
	memset(conf_filename, 0x00, FILENAME_SIZE);
	memset(perm_group, 0x00, 20);
	memset(str_orig, 0x00, 256);
	memset(chown_cmd, 0x00, 32);

	/* 0. this user MUST be 'root' */
	if(getuid() != 0) {	// not root
		fprintf(stderr, "%s", "[ERR] Only root user can add new user\n");
		result = PC_ERR_NOT_PERMITTED;
		goto error;
	}
	
	/* 1. convert pkg_name to real user name */
	result = convert_user_name_from_pkgname(pkg_name, user_name);
	if(result != PC_OPERATION_SUCCESS) {
		fprintf(stderr, "%s", "[ERR] Fail to convert pkg name\n");
		result = PC_ERR_INVALID_OPERATION;
		goto error;
	}
	/*    1.1. check there is a same user or not */
	if(getpwnam(user_name)) {
		fprintf(stderr, "%s", "[ERR] Fail to add new user - already exist\n");
		result = PC_ERR_INVALID_OPERATION;
		goto error;
	}
	
	/* 2. add user into /etc/passwd */
	/*    2.1. get uid, gid */
	uid = FIRST_UID;
	while(getpwuid(uid) != NULL)	// is there same uid?
		uid++;
	gid = uid;
	/*    2.2. get home directory and make home directory */
	snprintf(homedir, HOMEDIR_SIZE, "/opt/apps/%s", pkg_name);
	if(mkdir(homedir, 0755) != 0) {	// fail to make directory
		if(errno == EEXIST) {
			fprintf(stderr, "%s%s%s", "[LOG] ", homedir, " is already exist. Does NOT make new one.\n");
		}
		else {
			fprintf(stderr, "%s", "[ERR] Fail to make home directory\n");
			result = PC_ERR_FILE_OPERATION;
			goto error;
		}
	}
	memset(homedir, 0x00, HOMEDIR_SIZE);
	snprintf(homedir, HOMEDIR_SIZE, "/opt/apps/%s/data", pkg_name);
	if(mkdir(homedir, 0755) != 0) {	// fail to make directory
		if(errno == EEXIST) {
			fprintf(stderr, "%s%s%s", "[LOG] ", homedir, " is already exist. Does NOT make new one.\n");
		}
		else {
			fprintf(stderr, "%s", "[ERR] Fail to make home directory\n");
			result = PC_ERR_FILE_OPERATION;
			goto error;
		}
	}
	
	pid = fork();
	if(pid == 0) {
		snprintf(chown_cmd, 32, "%d:%d", uid, gid);
		ret = execl("/bin/chown", "/bin/chown", "-R", chown_cmd, homedir, NULL);
		if(ret == -1) {
			fprintf(stderr, "%s", "[ERR] fail to execute execl()\n");
			perror("Fail to execute execl()");
			exit(-1);
		}
	}
	else if(pid > 0) {
		wait((int*)0);
	}
	else {
		fprintf(stderr, "%s", "[ERR] fail to execute fork()\n");
		exit(-1);
	}
	/*    2.3. make one line of /etc/passwd */
	snprintf(linebuf, (USERNAME_SIZE + HOMEDIR_SIZE + 128), "%s:x:%d:%d:%s:%s:%s", user_name, uid, gid, expr, homedir, shell);
	uid = FIRST_UID;
	/*    2.4. write to /etc/passwd */
	if((fp_passwd = fopen("/opt/etc/passwd", "r")) == NULL) {	// open original passwd file
		fprintf(stderr, "%s", "[ERR] Fail to open /etc/passwd\n");
		result = PC_ERR_FILE_OPERATION;
		goto error;
	}
	if((fp_passwd2 = fopen("/opt/etc/passwd-modi", "w")) == NULL) {	// open mofified file
		fprintf(stderr, "%s", "[ERR] Fail to open /etc/passwd-modi\n");
		result = PC_ERR_FILE_OPERATION;
		goto error;
	}

	while(fgets(buf_passwd, PASSWD_LINE, fp_passwd))
		fprintf(fp_passwd2, "%s", buf_passwd);
	fprintf(fp_passwd2, "%s\n", linebuf);
	
	fclose(fp_passwd);
	fp_passwd = NULL;
	fclose(fp_passwd2);
	fp_passwd2 = NULL;
	
	if(rename("/opt/etc/passwd", "/opt/etc/passwd-") != 0) {	// if fail,
		fprintf(stderr, "%s", "[ERR] Fail to change file name(/opt/etc/passwd)\n");
		result = PC_ERR_FILE_OPERATION;
		goto error;
	}
	if(rename("/opt/etc/passwd-modi", "/opt/etc/passwd") != 0) {	// if fail,
		fprintf(stderr, "%s", "[ERR] Fail to change file name(/opt/etc/passwd-modi)\n");
		result = PC_ERR_FILE_OPERATION;
		goto error;
	}
	/*    2.5. make one line of /etc/group */
	snprintf(linebuf2, (USERNAME_SIZE + 20), "%s:x:%d:", user_name, gid);
	/*    2.6. write to /etc/group */
	if((fp_group = fopen("/opt/etc/group", "r")) == NULL) {
		fprintf(stderr, "%s", "[ERR] Fail to open /etc/grup\n");
		result =  PC_ERR_FILE_OPERATION;
		goto error;
	}
	if((fp_group2 = fopen("/opt/etc/group-modi", "w")) == NULL) {
		fprintf(stderr, "%s", "[ERR] Fail to open /etc/group-modi\n");
		result = PC_ERR_FILE_OPERATION;
		goto error;
	}

	while(1) {
		linebuf3 = (char*)malloc(sizeof(char) * 128);
		if(linebuf3 == NULL) {
			fprintf(stderr, "%s", "[ERR] Fail to allocate memory\n");
			result = PC_ERR_MEM_OPERATION;
			goto error;
		}
		memset(linebuf3, 0x00, 128);
		cnt = 128;
		i = 0;

		while(1) {	// get one line from /etc/group
			inputed = fgetc(fp_group);
			if(inputed == EOF)	// end of /etc/group,
				goto end_of_while;
			else if((char)inputed == '\n') {
				linebuf3[i] = '\0';
				break;
			}
			else if((i == cnt) && ((char)inputed != '\n')) {
				tempbuf = (char*)realloc(linebuf3, sizeof(char) * (i + 128));
				if(tempbuf == NULL) {
					fprintf(stderr, "%s", "[ERR] Fail to allocate memory\n");
					result = PC_ERR_MEM_OPERATION;
					goto error;
				}
				linebuf3 = tempbuf;
				linebuf3[i] = (char)inputed;
				cnt = i + 128;
			}
			else
				linebuf3[i] = (char)inputed;

			i++;
		}

		/* 3. get real group name from permissions */
		strncpy(str_orig, permissions, strlen(permissions));
		token = strtok(str_orig, seps);
		while(token != NULL) {
			/* 3.1. make dat file name */
			snprintf(conf_filename, FILENAME_SIZE, "/usr/share/privilege-control/%s.dat", token);
			if((fp_perm = fopen(conf_filename, "r")) == NULL) {
				fprintf(stderr, "%s%s%s", "[ERR] Fail to open ", conf_filename, "\n");
				result = PC_ERR_FILE_OPERATION;
				goto error;
			}
			while(fgets(perm_group, 20, fp_perm)) {
				perm_group[strlen(perm_group) - 1] = ':';
				perm_group[strlen(perm_group)] = '\0';
				if(strncmp(linebuf3, perm_group, strlen(perm_group)) == 0) {	// found!!
					if(!strncmp(linebuf3, user_name, strlen(user_name))) {	// already have same user
						flag = 1;
						fprintf(fp_group2, "%s\n", linebuf3);
						break;
					}
					if(linebuf3[strlen(linebuf3) - 1] == ':')
						strncat(linebuf3, user_name, strlen(user_name));
					else {
						strncat(linebuf3, ",", 1);
						strncat(linebuf3, user_name, strlen(user_name));
					}
					flag = 1;

					fprintf(fp_group2, "%s\n", linebuf3);
					break;
				}
			}
			if(fp_perm != NULL) {
				fclose(fp_perm);
				fp_perm = NULL;
			}
			memset(conf_filename, 0x00, FILENAME_SIZE);
			memset(perm_group, 0x00, 20);
			
			if(flag == 1)
				break;
		
			token = strtok(NULL, seps);
		}

		if(flag != 1)
			fprintf(fp_group2, "%s\n", linebuf3);

		flag = 0;
		if(linebuf3 != NULL) {
			free(linebuf3);
			linebuf3 = NULL;
		}
	}
end_of_while:
	fprintf(fp_group2, "%s\n", linebuf2);
	
	fclose(fp_group);
	fp_group = NULL;
	fclose(fp_group2);
	fp_group2 = NULL;
	
	if(rename("/opt/etc/group", "/opt/etc/group-") != 0) {	// if fail,
		fprintf(stderr, "%s", "[ERR] Fail to change file name(/opt/etc/group)\n");
		result = PC_ERR_FILE_OPERATION;
		goto error;
	}
	if(rename("/opt/etc/group-modi", "/opt/etc/group") != 0) {	// if fail,
		fprintf(stderr, "%s", "[ERR] Fail to change file name(/opt/etc/group-modi)\n");
		result = PC_ERR_FILE_OPERATION;
		goto error;
	}

error:
	if(fp_passwd != NULL)
		fclose(fp_passwd);
	if(fp_passwd2 != NULL)
		fclose(fp_passwd2);
	if(fp_group != NULL)
		fclose(fp_group);
	if(fp_group2 != NULL)
		fclose(fp_group2);
	if(fp_perm != NULL)
		fclose(fp_perm);

	if(linebuf3 != NULL)
		free(linebuf3);

	return result;
}

API int delete_user_and_group(const char* pkg_name)
{
	FILE* fp_passwd = NULL;
	FILE* fp_passwd2 = NULL;
	FILE* fp_group = NULL;
	FILE* fp_group2 = NULL;
	char user_name[USERNAME_SIZE];
	char user_name2[USERNAME_SIZE];
	char linebuf[512];
	char* linebuf2 = NULL;
	char* linebuf3 = NULL;
	char* tempbuf = NULL;
	char* start = NULL;
	char* end = NULL;
	int i = 0, cnt = 0, flag = 0;
	int result = PC_OPERATION_SUCCESS;
	int inputed;
	char* temp = NULL;
	
	memset(user_name, 0x00, USERNAME_SIZE);
	memset(user_name2, 0x00, USERNAME_SIZE);
	memset(linebuf, 0x00, 512);
	
	/* 0. user MUST be 'root' */
	if(getuid() != 0) {	// not root
		fprintf(stderr, "%s", "[ERR] Only root user can add new user\n");
		result = PC_ERR_NOT_PERMITTED;
		goto error;
	}
	
	/* 1. convert pkg_name to real user name */
	result = convert_user_name_from_pkgname(pkg_name, user_name);
	if(result != PC_OPERATION_SUCCESS) {
		fprintf(stderr, "%s", "[ERR] Fail to convert pkg name\n");
		result = PC_ERR_INVALID_OPERATION;
		goto error;
	}
	/*    1.1. check there is a same user or not */
	if(!getpwnam(user_name)) {
		fprintf(stderr, "%s", "[ERR] Fail to delete user - not exist\n");
		result = PC_ERR_INVALID_OPERATION;
		goto error;
	}
	
	/* 2. delete user from /etc/passwd */
	/*    2.1. open */
	if((fp_passwd = fopen("/opt/etc/passwd", "r")) == NULL) {	// open original passwd file
		fprintf(stderr, "%s", "[ERR] Fail to open /etc/passwd\n");
		result = PC_ERR_FILE_OPERATION;
		goto error;
	}
	if((fp_passwd2 = fopen("/opt/etc/passwd-modi", "w")) == NULL) {	// open mofified file
		fprintf(stderr, "%s", "[ERR] Fail to open /etc/passwd-modi\n");
		result = PC_ERR_FILE_OPERATION;
		goto error;
	}

	/*    2.2. write */
	strncpy(user_name2, user_name, (strlen(user_name) + 1));
	user_name2[strlen(user_name)] = ':';

	while(fgets(linebuf, 512, fp_passwd)) {
		if(!strncmp(linebuf, user_name2, strlen(user_name2))) 	// found
			continue;
		fprintf(fp_passwd2, "%s", linebuf);
	}
	
	/*    2.3. rename file */
	if(rename("/opt/etc/passwd", "/opt/etc/passwd-") != 0) {	// if fail,
		fprintf(stderr, "%s", "[ERR] Fail to change file name(/opt/etc/passwd)\n");
		result = PC_ERR_FILE_OPERATION;
		goto error;
	}
	if(rename("/opt/etc/passwd-modi", "/opt/etc/passwd") != 0) {	// if fail,
		fprintf(stderr, "%s", "[ERR] Fail to change file name(/opt/etc/passwd-modi)\n");
		result = PC_ERR_FILE_OPERATION;
		goto error;
	}
	
	/* 3. delete group from /etc/group */
	/*    3.1. open */
	if((fp_group = fopen("/opt/etc/group", "r")) == NULL) {
		fprintf(stderr, "%s", "[ERR] Fail to open /etc/grup\n");
		result =  PC_ERR_FILE_OPERATION;
		goto error;
	}
	if((fp_group2 = fopen("/opt/etc/group-modi", "w")) == NULL) {
		fprintf(stderr, "%s", "[ERR] Fail to open /etc/group-modi\n");
		result = PC_ERR_FILE_OPERATION;
		goto error;
	}

	/*    3.2. search and delete */
	while(1) {
		linebuf2 = (char*)malloc(sizeof(char) * 128);
		if(linebuf2 == NULL) {
			fprintf(stderr, "%s", "[ERR] Fail to allocate memory\n");
			result = PC_ERR_MEM_OPERATION;
			goto error;
		}
		memset(linebuf2, 0x00, 128);
		cnt = 128;
		i = 0;

		while(1) {
			inputed = fgetc(fp_group);
			if(inputed == EOF)
				goto end_of_while;
			else if((char)inputed == '\n') {
				linebuf2[i] = '\0';
				break;
			}
			else if((i == cnt) && ((char)inputed != '\n')) {
				tempbuf = (char*)realloc(linebuf2, sizeof(char) * (i + 128));
				if(tempbuf == NULL) {
					fprintf(stderr, "%s", "[ERR] Fail to allocate memory\n");
					result = PC_ERR_MEM_OPERATION;
					goto error;
				}
				linebuf2 = tempbuf;
				linebuf2[i] = (char)inputed;
				cnt = i + 128;
			}
			else
				linebuf2[i] = (char)inputed;

			i++;
		}

		if(strncmp(linebuf2, user_name2, strlen(user_name2)) == 0)	// group of user
			continue;

		if((start = strstr(strchr(linebuf2, ':'), user_name)) != NULL) {	// found!!
			linebuf3 = (char*)malloc(sizeof(char) * strlen(linebuf2));
			memset(linebuf3, 0x00, strlen(linebuf2));

repeat:
			end = start + strlen(user_name);
			// end MUST be ',' or '\0'
			if(end[0] == ',')
				end = end + 1;
			else if(end[0] == '\0') {
				temp = start - 1;
				if(temp[0] == ',')
					start = start - 1;
			}
			else {
				start = strstr(end, user_name);
				if(start[0] != '\0')
					goto repeat;
			}
			
			strncpy(linebuf3, linebuf2, ((int)start - (int)linebuf2));
			linebuf3 = strcat(linebuf3, end);
			fprintf(fp_group2, "%s\n", linebuf3);
			flag = 1;
		}

		if(flag != 1)
			fprintf(fp_group2, "%s\n", linebuf2);
		flag = 0;
		
		if(linebuf2 != NULL) {
			free(linebuf2);
			linebuf2 = NULL;
		}
		if(linebuf3 != NULL) {
			free(linebuf3);
			linebuf3 = NULL;
		}
	}
end_of_while:
	fclose(fp_group);
	fp_group = NULL;
	fclose(fp_group2);
	fp_group2 = NULL;

	if(rename("/opt/etc/group", "/opt/etc/group-") != 0) {	// if fail,
		fprintf(stderr, "%s", "[ERR] Fail to change file name(/opt/etc/group)\n");
		result = PC_ERR_FILE_OPERATION;
		goto error;
	}
	if(rename("/opt/etc/group-modi", "/opt/etc/group") != 0) {	// if fail,
		fprintf(stderr, "%s", "[ERR] Fail to change file name(/opt/etc/group-modi)\n");
		result = PC_ERR_FILE_OPERATION;
		goto error;
	}

error:
	if(fp_passwd != NULL)
		fclose(fp_passwd);
	if(fp_passwd2 != NULL)
		fclose(fp_passwd2);
	if(fp_group != NULL)
		fclose(fp_group);
	if(fp_group2 != NULL)
		fclose(fp_group2);

	if(linebuf2 != NULL)
		free(linebuf2);
	if(linebuf3 != NULL)
		free(linebuf3);
	
	return result;
}
