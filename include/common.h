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

#ifndef COMMON_H_
#define COMMON_H_

#include <stdio.h>
#include <dlog.h>
#include <fts.h>

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

void freep(void *p);
void closep(int *fd);
void fclosep(FILE **f);
void smack_freep(struct smack_accesses **smack);
void fts_closep(FTS **f);
#define AUTO_FREE       __attribute__ ((cleanup(freep)))       = NULL
#define AUTO_CLOSE      __attribute__ ((cleanup(closep)))      = -1
#define AUTO_FCLOSE     __attribute__ ((cleanup(fclosep)))     = NULL
#define AUTO_SMACK_FREE __attribute__ ((cleanup(smack_freep))) = NULL
#define AUTO_FTS_CLOSE  __attribute__ ((cleanup(fts_closep)))   = NULL

int smack_label_is_valid(const char* smack_label);

#endif /* COMMON_H_ */
