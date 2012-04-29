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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "security-server.h"
#include "privilege-control.h"

#define DEVELOPER_UID 5100

int main(int argc, char *argv[])
{
	int uid = 0, ret = -1;

	uid = getuid();
	
	if(uid == DEVELOPER_UID) {
		fprintf(stderr, "%s", "[LOG] Sending request to security server...\n");
		ret = security_server_launch_debug_tool(argc - 1, (const char **)argv + 1);
		if(ret != SECURITY_SERVER_API_SUCCESS) {
			fprintf(stderr, "[ERR] Failed to launch tool, [%d]\n", ret);
			return 0;
		}
		return 1;
	}
	else if(uid == 0) {
		fprintf(stderr, "%s", "[LOG] Executed as root privilege\n");
		
		/*
		 * argv[0]   : /usr/bin/debug-util
		 * 
		 * argv[1]   : package name
		 * argv[2]   : command of developer(SDK)
		 * argv[3] ~ : parameter(s) of argv[2]
		 */
		if(!strncmp(argv[1], "/usr/bin/launch_app", 19) || !strncmp(argv[1], "/usr/bin/kill_app", 17)) { 
			ret = execve(argv[1], (char * const*)argv + 1, NULL);
			if(ret == -1) {
				perror("[ERR] 1. Fail to execute execve()");
			}
		}
		else if(set_privilege(argv[1]) == 0) {	// success
			if(!strncmp(argv[2], "/bin/gdbserver", 14) || !strncmp(argv[2], "/usr/bin/opcontrol", 18) || !strncmp(argv[2], "/usr/bin/valgrind", 17 )) {
				ret = execve(argv[2], (char * const*)argv + 2, NULL);
				if(ret == -1) {	// error
					perror("[ERR] 2. Fail to execute execve()");
				}
			}
		}
		else
			fprintf(stderr, "[ERR] Fail to execute set_privilege()\n");
	}
	else {
		fprintf(stderr, "[ERR] Wrong uid: %d\n", uid);
		fprintf(stderr, "[ERR] You must run %s under root user or developer(%d) user\n", argv[0], DEVELOPER_UID);
		return 0;
	}

	return 1;
}
