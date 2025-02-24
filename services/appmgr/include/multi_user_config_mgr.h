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

#ifndef OHOS_ABILITY_RUNTIME_MULTI_USER_CONFIG_MGR_H
#define OHOS_ABILITY_RUNTIME_MULTI_USER_CONFIG_MGR_H

#include <map>
#include <mutex>
#include <memory>

#include "configuration.h"

namespace OHOS {
namespace AppExecFwk {

class MultiUserConfigurationMgr {
public:
    MultiUserConfigurationMgr();
    std::shared_ptr<AppExecFwk::Configuration> GetConfigurationByUserId(const int32_t userId);
    void InitConfiguration(std::shared_ptr<AppExecFwk::Configuration> config);
    void HandleConfiguration(const int32_t userId, const Configuration& config, std::vector<std::string>& changeKeyV,
        bool &isNotifyUser0);

private:
    void UpdateMultiUserConfiguration(const Configuration& config);
    void UpdateMultiUserConfigurationForGlobal(const Configuration& globalConfig);
    void SetOrUpdateConfigByUserId(const int32_t userId, const Configuration& config,
        std::vector<std::string>& changeKeyV);

    std::map<int32_t, Configuration> multiUserConfiguration_;
    std::mutex multiUserConfigurationMutex_;
    std::shared_ptr<AppExecFwk::Configuration> globalConfiguration_;
    static int32_t GetForegroundOsAccountLocalId();
};
} // namespace AppExecFwk
} // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_MULTI_USER_CONFIG_MGR_H
