/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MODULETEST_OHOS_ABILITY_RUNTIME_MOCK_APP_SCHEDULER_H
#define MODULETEST_OHOS_ABILITY_RUNTIME_MOCK_APP_SCHEDULER_H

#include "singleton.h"

#include "running_process_info.h"

namespace OHOS {
namespace AAFwk {
class AppScheduler {
    DECLARE_DELAYED_SINGLETON(AppScheduler)
public:
    /**
     * Get running process information by pid.
     *
     * @param pid process id.
     * @param info Output parameters, return runningProcessInfo.
     * @return Returns ERR_OK on success, others on failure.
     */
    void GetRunningProcessInfoByPid(const pid_t pid, OHOS::AppExecFwk::RunningProcessInfo &info) const;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // MODULETEST_OHOS_ABILITY_RUNTIME_MOCK_APP_SCHEDULER_H
