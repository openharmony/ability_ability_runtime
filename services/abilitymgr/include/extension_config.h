/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_EXTENSION_CONFIG_H
#define OHOS_ABILITY_RUNTIME_EXTENSION_CONFIG_H

#include <map>
#include <mutex>
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <unordered_set>

#include "extension_ability_info.h"
#include "singleton.h"

namespace OHOS {
namespace AAFwk {
constexpr static int32_t DEFAULT_EXTENSION_AUTO_DISCONNECT_TIME = -1;
constexpr static bool EXTENSION_NETWORK_ENABLE_FLAG_DEFAULT = true;
constexpr static bool EXTENSION_SA_ENABLE_FLAG_DEFAULT = true;
constexpr static bool EXTENSION_THIRD_PARTY_APP_ENABLE_FLAG_DEFAULT = true;
constexpr static bool EXTENSION_START_SERVICE_ENABLE_FLAG_DEFAULT = true;

struct ExtensionConfigItem {
    bool networkEnableFlag = EXTENSION_NETWORK_ENABLE_FLAG_DEFAULT;
    bool saEnableFlag = EXTENSION_SA_ENABLE_FLAG_DEFAULT;
    bool thirdPartyAppEnableFlag = EXTENSION_THIRD_PARTY_APP_ENABLE_FLAG_DEFAULT;
    bool serviceEnableFlag = EXTENSION_START_SERVICE_ENABLE_FLAG_DEFAULT;
    int32_t extensionAutoDisconnectTime = DEFAULT_EXTENSION_AUTO_DISCONNECT_TIME;
    std::unordered_set<std::string> serviceBlockedList;
};

class ExtensionConfig : public DelayedSingleton<ExtensionConfig> {
public:
    explicit ExtensionConfig() = default;
    virtual ~ExtensionConfig() = default;
    void LoadExtensionConfiguration();
    int32_t GetExtensionAutoDisconnectTime(const std::string &extensionTypeName);
    bool IsExtensionStartThirdPartyAppEnable(const std::string &extensionTypeName);
    bool IsExtensionStartServiceEnable(const std::string &extensionTypeName, const std::string &targetUri);
    bool IsExtensionNetworkEnable(const std::string &extensionTypeName);
    bool IsExtensionSAEnable(const std::string &extensionTypeName);
private:
    void LoadExtensionConfig(const nlohmann::json &object);
    bool ReadFileInfoJson(const std::string &filePath, nlohmann::json &jsonBuf);

    std::string GetExtensionConfigPath() const;
    void LoadExtensionAutoDisconnectTime(const nlohmann::json &object, std::string extensionTypeName);
    void LoadExtensionThirdPartyAppBlockedList(const nlohmann::json &object, std::string extensionTypeName);
    void LoadExtensionServiceBlockedList(const nlohmann::json &object, std::string extensionTypeNameobject);
    void LoadExtensionNetworkEnable(const nlohmann::json &object, const std::string &extensionTypeName);
    void LoadExtensionSAEnable(const nlohmann::json &object, const std::string &extensionTypeName);

    bool CheckServiceExtensionUriValid(const std::string &uri);

    std::unordered_map<std::string, ExtensionConfigItem> configMap_;
    std::mutex configMapMutex_;
};
} // OHOS
} // AAFwk

#endif // OHOS_ABILITY_RUNTIME_EXTENSION_CONFIG_H