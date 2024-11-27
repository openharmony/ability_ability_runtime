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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_KEEP_ALIVE_SERVICE_H
#define OHOS_ABILITY_RUNTIME_ABILITY_KEEP_ALIVE_SERVICE_H

#include <vector>

#include "ability_manager_errors.h"
#include "keep_alive_info.h"
#include "singleton.h"

namespace OHOS {
namespace AbilityRuntime {
class AbilityKeepAliveService {
public:
    static AbilityKeepAliveService &GetInstance();
    /**
     * @brief Set every application keep alive state.
     * @param info The keep-alive info,include bundle name, module name, ability name.
     * @param flag Indicates whether to keep alive for application.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t SetApplicationKeepAlive(KeepAliveInfo &info, bool flag);

    /**
     * @brief Query keep-alive applications.
     * @param userId User id.
     * @param appType App type.
     * @param infoList Output parameters, return keep-alive info list.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t QueryKeepAliveApplications(int32_t userId, int32_t appType, std::vector<KeepAliveInfo> &infoList);

    /**
     * @brief Query if bundle is keep-alive.
     * @param bundleName The bundle name.
     * @param userId User id.
     * @return Returns true on app keep alive, false otherwise.
     */
    bool IsKeepAliveApp(const std::string &bundleName, int32_t userId);

    /**
     * @brief Get keep-alive applications without permissions.
     * @param userId User id.
     * @param infoList Output parameters, return keep-alive info list.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t GetKeepAliveApplications(int32_t userId, std::vector<KeepAliveInfo> &infoList);

    /**
     * @brief Query if bundle is keep-alive.
     * @param bundleName The bundle name.
     * @param userId User id.
     * @param isByEDM The flag indicates whether it's user or system who sets the flag.
     * @param isKeepAlive The return flag indicates whether the bundle is keep-alive.
     * @return Returns ERR_OK on success, others on failure.
     */
    bool CanSetKeepAlive(const std::string &bundleName, int32_t userId, bool isByEDM, bool &isKeepAlive);

public:
    static int32_t callSetResult;
    static int32_t callQueryResult;
    static bool callIsKeepAliveResult;
    static int32_t callGetResult;

private:
    AbilityKeepAliveService();
    ~AbilityKeepAliveService();

    DISALLOW_COPY_AND_MOVE(AbilityKeepAliveService);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ABILITY_KEEP_ALIVE_SERVICE_H