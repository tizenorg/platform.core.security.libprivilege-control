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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "privilege-control.h"

void print_usage(void)
{
	printf("%s", "Usage: slp-su [PKG_NAME]\n\n");
	printf("%s", "Execute new shell which be belonged to user related with PKG_NAME\n\n");
}

int main(int argc, char* argv[])
{
	pid_t pid = -1;
	char* buf = NULL;

	if(argc != 2)
	{
		fprintf(stderr, "%s", "[ERR] Check your argument.\n\n");
		print_usage();
		return 0;
	}

	pid = fork();
	switch(pid)
	{
		case 0:		// child
			{
				if(set_privilege(argv[1]) == 0)	// success
				{
					fprintf(stderr, "%s", "[LOG] Success to execute set_privilege()\n");
				}
				else
				{
					fprintf(stderr, "%s", "[ERR] Fail to execute set_privilege()\n");
					exit(1);
				}

				buf = getenv("HOME");
				if(buf == NULL)	// fail
				{
					fprintf(stderr, "%s", "[ERR] Fail to execute getenv()\n");
					exit(0);
				}
				else
				{
					fprintf(stderr, "%s: [%s]%s", "[LOG] HOME", buf, "\n");
				}
				
				if(chdir(buf) == 0)	// success
				{
					fprintf(stderr, "%s", "[LOG] Success to change working directory\n");
				}
				else
				{
					fprintf(stderr, "%s", "[ERR] Fail to execute chdir()\n");
					exit(0);
				}
				
				execl("/bin/sh", "/bin/sh", NULL);
				break;
			}
		case -1:	// error
			{
				fprintf(stderr, "%s", "[ERR] Fail to execute fork()\n");
				exit(1);
				break;
			}
		default:	// parent
			{
				wait((int*)0);
				fprintf(stderr, "%s", "[LOG] Parent end\n");
				exit(0);
			}
	}

	return 1;
}
