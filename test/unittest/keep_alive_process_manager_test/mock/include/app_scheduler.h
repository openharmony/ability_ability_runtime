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

#ifndef OHOS_ABILITY_RUNTIME_APP_SCHEDULER_H
#define OHOS_ABILITY_RUNTIME_APP_SCHEDULER_H

#include <cstdint>
#include <string>
#include <vector>

#include "app_mgr_client.h"
#include "singleton.h"

namespace OHOS {
namespace AAFwk {
struct AppData {
    std::string appName;
    int32_t uid;
};

enum class AppState {
    BEGIN = 0,
    READY,
    FOREGROUND,
    FOCUS,
    BACKGROUND,
    TERMINATED,
    END,
    SUSPENDED,
    COLD_START = 99,
};

struct AppInfo {
    std::vector<AppData> appData;
    std::string processName;
    AppState state;
    pid_t pid = 0;
    int32_t appIndex = 0;
    std::string instanceKey = "";
    std::string bundleName = "";
};

/**
 * @class AppScheduler
 * AppScheduler , access app manager service.
 */
class AppScheduler {
    DECLARE_DELAYED_SINGLETON(AppScheduler)
public:
    /**
     * Get bundleName by pid.
     *
     * @param pid process id.
     * @param bundleName Output parameters, return bundleName.
     * @param uid Output parameters, return userId.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t GetBundleNameByPid(const int pid, std::string &bundleName, int32_t &uid);

public:
    static int32_t getBundleNameByPidResult;
    static std::string bundleNameValue;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APP_SCHEDULER_H
