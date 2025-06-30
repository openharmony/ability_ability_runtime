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

#ifndef MOCK_OHOS_ABILITY_RUNTIME_APP_MGR_CLIENT_H
#define MOCK_OHOS_ABILITY_RUNTIME_APP_MGR_CLIENT_H

#include <string>
#include "app_mgr_constants.h"

namespace OHOS {
namespace JsEnv {
struct ErrorObject {
    std::string name;
    std::string message;
    std::string stack;
};
}
namespace AppExecFwk {
enum class FaultDataType {
    UNKNOWN = -1,
    CPP_CRASH,
    JS_ERROR,
    CJ_ERROR,
    APP_FREEZE,
    PERFORMANCE_CONTROL,
    RESOURCE_CONTROL
};

struct AppFaultDataBySA {
    JsEnv::ErrorObject errorObject;
    FaultDataType faultType = FaultDataType::UNKNOWN;
    int32_t pid = -1;
};

class AppMgrClient {
public:
    virtual ~AppMgrClient() {}

    static AppMgrClient *GetInstance()
    {
        static AppMgrClient* instance = new AppMgrClient();
        return instance;
    }
    virtual AppMgrResultCode KillApplicationSelf(const bool clearPageStack = false,
        const std::string& reason = "KillApplicationSelf")
    {
        return RESULT_OK;
    }
    void SetKeepAliveEnableState(const std::string &bundleName, bool enable, int32_t uid) {}
    int32_t NotifyAppFaultBySA(const AppFaultDataBySA &faultData)
    {
        return 0;
    }
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APP_MGR_CLIENT_H