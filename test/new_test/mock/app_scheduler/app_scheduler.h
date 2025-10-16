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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_APP_SCHEDULER_H
#define MOCK_OHOS_ABILITY_RUNTIME_APP_SCHEDULER_H

#include <memory>
#include <unordered_set>

#include "ability_info.h"
#include "app_debug_listener_interface.h"
#include "application_info.h"
#include "app_mgr_client.h"
#include "bundle_info.h"
#include "configuration.h"
#include "iremote_object.h"
#include "last_exit_detail_info.h"
#include "refbase.h"
#include "running_process_info.h"
#include "singleton.h"
#include "user_callback.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
struct LoadParam;
}
namespace AAFwk {
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

struct AppData {
    std::string appName;
    int32_t uid;
};

struct AppInfo {
    std::vector<AppData> appData;
    std::string processName;
    AppState state;
    pid_t pid = 0;
    int32_t appIndex = 0;
    std::string instanceKey = "";
    std::string bundleName = "";
    int32_t userId = -1;
};

class AppStateCallback {};

class AppScheduler : virtual RefBase {
    DECLARE_DELAYED_SINGLETON(AppScheduler)
public:
    bool Init(const std::weak_ptr<AppStateCallback> &callback)
    {
        return false;
    }

    int UpdateConfiguration(const AppExecFwk::Configuration &config)
    {
        return 0;
    }

    int GetConfiguration(AppExecFwk::Configuration &config)
    {
        return 0;
    }

    int GetApplicationInfoByProcessID(const int pid, AppExecFwk::ApplicationInfo &application, bool &debug)
    {
        return 0;
    }

    int32_t GetBundleNameByPid(const int pid, std::string &bundleName, int32_t &uid)
    {
        return 0;
    }

    int32_t RegisterAppDebugListener(const sptr<AppExecFwk::IAppDebugListener> &listener)
    {
        return 0;
    }

    int32_t UnregisterAppDebugListener(const sptr<AppExecFwk::IAppDebugListener> &listener)
    {
        return 0;
    }

    int32_t AttachAppDebug(const std::string &bundleName, bool isDebugFromLocal)
    {
        return 0;
    }

    int32_t DetachAppDebug(const std::string &bundleName)
    {
        return 0;
    }

    virtual bool IsMemorySizeSufficient() const
    {
        return false;
    }

    bool IsProcessContainsOnlyUIAbility(const pid_t pid)
    {
        return false;
    }

    void KillProcessesByUserId(int32_t userId, bool isNeedSendAppSpawnMsg = false,
        sptr<AAFwk::IUserCallback> callback = nullptr) {}
};
}  // namespace AAFwk
}  // namespace OHOS
#endif