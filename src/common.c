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

#include <stdlib.h>
#include <unistd.h>
#include <sys/smack.h>
#include "common.h"

#ifdef SMACK_ENABLED
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
	C_LOGE("Invalid Smack label: %s", smack_label);
	return 0;
}
#endif

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
