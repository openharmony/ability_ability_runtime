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

#ifndef OHOS_ABILITY_RUNTIME_DEFAULT_RECOVERY_CONFIG_H
#define OHOS_ABILITY_RUNTIME_DEFAULT_RECOVERY_CONFIG_H

#include <nlohmann/json.hpp>
#include <string>
#include <unordered_set>

#include "singleton.h"

namespace OHOS {
namespace AbilityRuntime {
namespace DefaultRecoveryConstants {
constexpr int32_t RESERVE_NUMBER_INVALID = 0;
constexpr int32_t TIMEOUT_DELETE_TIME_INVALID = 0;
} // namespace DefaultRecoveryConstants

class DefaultRecoveryConfig {
public:
    static DefaultRecoveryConfig &GetInstance()
    {
        static DefaultRecoveryConfig instance;
        return instance;
    }

    ~DefaultRecoveryConfig() = default;
    bool LoadConfiguration();
    bool IsBundleDefaultRecoveryEnabled(const std::string &bundleName);
    int32_t GetReserveNumber();
    int32_t GetTimeoutDeleteTime();

private:
    std::string GetConfigPath();
    bool ReadFileInfoJson(const std::string &filePath, nlohmann::json &jsonBuf);
    bool LoadDefaultRecovery(const nlohmann::json &object);
    DefaultRecoveryConfig() = default;
    DISALLOW_COPY_AND_MOVE(DefaultRecoveryConfig);

private:
    // It was set in Init() of abilityms.
    std::unordered_set<std::string> bundleNameList_;
    int32_t reserveNumber_ = DefaultRecoveryConstants::RESERVE_NUMBER_INVALID;
    int32_t timeoutDeleteTime_ = DefaultRecoveryConstants::TIMEOUT_DELETE_TIME_INVALID;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_DEFAULT_RECOVERY_CONFIG_H