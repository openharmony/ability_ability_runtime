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

#ifndef OHOS_ABILITY_RUNTIME_APP_MGR_CLIENT_H
#define OHOS_ABILITY_RUNTIME_APP_MGR_CLIENT_H

#include <string>

#include "ability_manager_errors.h"

namespace OHOS {
namespace AppExecFwk {
class AppMgrClient {
public:
    AppMgrClient();
    virtual ~AppMgrClient();

    /**
     * KillApplication, call KillApplication() through proxy object, kill the application.
     *
     * @param  bundleName, bundle name in Application record.
     * @return ERR_OK, return back success, others fail.
     */
    int32_t KillApplication(const std::string &bundleName, bool clearPageStack = false,
        int32_t appIndex = 0);

    /**
     * Check whether the process of the application under the specified user exists.
     *
     * @param bundleName Indicates the bundle name of the bundle.
     * @param userId the userId of the bundle.
     * @param isRunning Obtain the running status of the application, the result is true if running, false otherwise.
     * @return Return ERR_OK if success, others fail.
     */
    int32_t IsAppRunningByBundleNameAndUserId(const std::string &bundleName, int32_t userId,
        bool &isRunning);

    /**
     * @brief Set non-resident keep-alive process status.
     * @param bundleName The application bundle name.
     * @param enable The current updated enable status.
     * @param uid indicates user, 0 for all users
     */
    void SetKeepAliveDkv(const std::string &bundleName, bool enable, int32_t uid);

public:
    static int32_t isAppRunningReturnCode;
    static bool isAppRunningReturnValue;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_APP_MGR_CLIENT_H
