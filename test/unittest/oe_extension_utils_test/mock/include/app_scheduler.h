/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef OHOS_ABILITY_RUNTIME_APP_SCHEDULER_H
#define OHOS_ABILITY_RUNTIME_APP_SCHEDULER_H

#include <string>
#include <vector>

#include "singleton.h"

namespace OHOS {
namespace AppExecFwk {
enum class AppProcessState {
    NONE,
    APP_STATE_FOREGROUND
};
struct RunningProcessInfo {
    AppProcessState state_ = AppProcessState::NONE;
    std::vector<std::string> bundleNames;
};
}
namespace AAFwk {
class AppScheduler {
    DECLARE_DELAYED_SINGLETON(AppScheduler);
public:
    inline void GetRunningProcessInfoByPid(int32_t pid, AppExecFwk::RunningProcessInfo& processInfo)
    {
        processInfo.state_ = state_;
        processInfo.bundleNames = bundleNames_;
    }

    AppExecFwk::AppProcessState state_ = AppExecFwk::AppProcessState::NONE;
    std::vector<std::string> bundleNames_;
};
}
}

#endif