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

#ifndef OHOS_ABILITY_RUNTIME_APP_EXCEPTION_MANAGER_H
#define OHOS_ABILITY_RUNTIME_APP_EXCEPTION_MANAGER_H

#include "iapp_exception_callback.h"

namespace OHOS {
namespace AppExecFwk {
class AppExceptionManager {
public:
    static AppExceptionManager &GetInstance();
    AppExceptionManager(AppExceptionManager &) = delete;
    void operator=(AppExceptionManager &) = delete;

    void LaunchAbilityFailed(sptr<IRemoteObject> token, const std::string &msg);
    void ForegroundAppFailed(sptr<IRemoteObject> token, const std::string &msg);
    void ForegroundAppWait(sptr<IRemoteObject> token, const std::string &msg);

    void NotifyLifecycleException(LifecycleException type, sptr<IRemoteObject> token);
    void SetExceptionCallback(sptr<IAppExceptionCallback> exceptionCallback);
    sptr<IAppExceptionCallback> GetExceptionCallback() const;
private:
    AppExceptionManager() = default;
    mutable std::mutex exceptionCallbackMutex_;
    sptr<IAppExceptionCallback> exceptionCallback_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APP_EXCEPTION_MANAGER_H
