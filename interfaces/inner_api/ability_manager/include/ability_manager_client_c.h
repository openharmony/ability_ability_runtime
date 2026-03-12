/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_CLIENT_C_H
#define OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_CLIENT_C_H

#include <cinttypes>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Record app exit reason.
 * @param exitReason The reason of app exit. defined in ability_state.h
 * @param exitMsg The message of app exit.
 * @return Returns ERR_OK on success, others on failure.
 */
int RecordAppExitReason(int exitReason, const char *exitMsg = "");

/**
 * Record app with reason.
 * @param pid The process ID of the app.
 * @param uid The user ID.
 * @param exitReason The reason of app exit. defined in ability_state.h
 * @param killId The reason of app exit. defined in xcollie/process_kill_reason.h
 * @param exitMsg The message of app exit.
 * @return Returns ERR_OK on success, others on failure.
 */
int RecordAppWithReason(int pid, int uid, int exitReason, int killId, const char *exitMsg = "");
#ifdef __cplusplus
}
#endif
#endif // OHOS_ABILITY_RUNTIME_ABILITY_MANAGER_CLIENT_C_H
