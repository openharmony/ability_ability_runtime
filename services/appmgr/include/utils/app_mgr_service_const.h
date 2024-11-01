/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_APP_MGR_SERVICE_CONST_H
#define OHOS_ABILITY_RUNTIME_APP_MGR_SERVICE_CONST_H

#include <cstring>

namespace OHOS {
namespace AppExecFwk {
constexpr const char* MSG_DUMP_IPC_START_STAT = "StartIpcStatistics\t";
constexpr const char* MSG_DUMP_IPC_STOP_STAT = "StopIpcStatistics\t";
constexpr const char* MSG_DUMP_IPC_STAT = "IpcStatistics\t";
constexpr const char* MSG_DUMP_FAIL = "fail\n";
constexpr const char* MSG_DUMP_FAIL_REASON_INTERNAL = "internal error.\n";
constexpr const char* MSG_DUMP_FAIL_REASON_INVALILD_CMD = "invalid cmd.\n";
constexpr const char* MSG_DUMP_FAIL_REASON_INVALILD_PID = "invalid pid.\n";
constexpr const char* MSG_DUMP_FAIL_REASON_INVALILD_NUM_ARGS = "invalid number of arguments.\n";
constexpr const char* MSG_DUMP_FAIL_REASON_PERMISSION_DENY = "permission deny.\n";
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_APP_MGR_SERVICE_CONST_H
