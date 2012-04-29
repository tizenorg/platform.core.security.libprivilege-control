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
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
//#include <errno.h>

#define FILE_NAME	"/tmp/.testpkg"

int main()
{
	int uid = -1;
	int pid = -1;
	FILE* fp_in = NULL;

	/* if not root, fail */
	uid = getuid();
	if(uid != 0) {	// not root
		fprintf(stderr, "[ERR][kill_app] You MUST be root.\n");
		goto err;
	}

	/* open file - /tmp/.testpkg */
	if(!(fp_in = fopen(FILE_NAME, "r"))) {
		fprintf(stderr, "[ERR][kill_app] Fail to open file, [%s]\n", FILE_NAME);
		perror("err: ");
		goto err;
	}

	/* get pid */
	fscanf(fp_in, "%d", &pid);
	if(pid <= 0) {
		fprintf(stderr, "[ERR][kill_app] Invalid pid.\n");
		goto err;
	}

	/* kill that process */
	if(kill(pid, SIGKILL) < 0) {
		fprintf(stderr, "[ERR][kill_app] Fail to kill application which has the pid [%d]\n", pid);
		perror("err: ");
		goto err;
	}

	/* delete the file */
	if(unlink(FILE_NAME) < 0) {
		fprintf(stderr, "[ERR][kill_app] Fail to delete file, [%s]\n", FILE_NAME);
		perror("err: ");
		goto err;
	}

err:
	if(fp_in != NULL)
		fclose(fp_in);

	return 0;
}
