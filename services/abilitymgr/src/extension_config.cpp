/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <fstream>
#include <sstream>
#include <unistd.h>

#include "extension_config.h"
#include "hilog_wrapper.h"

namespace OHOS {
namespace AAFwk {
namespace {
constexpr const char* AMS_EXTENSION_CONFIG = "/etc/ams_extension_config.json";

const std::string EXTENSION_AUTO_DISCONNECT_TIME_NAME = "amsExtensionConfig";
const std::string EXTENSION_TYPE = "type";
const std::string EXTENSION_AUTO_DISCONNECT_TIME = "auto_disconnect_time";

const int32_t DEFAULT_EXTENSION_AUTO_DISCONNECT_TIME = 60000;
}

int32_t ExtensionConfig::GetExtensionAutoDisconnectTime(const AppExecFwk::ExtensionAbilityType &type)
{
    if (extensionAutoDisconnectTimeMap_.find(type) != extensionAutoDisconnectTimeMap_.end()) {
        return extensionAutoDisconnectTimeMap_[type];
    }
    return DEFAULT_EXTENSION_AUTO_DISCONNECT_TIME;
}

int32_t ExtensionConfig::LoadExtensionAutoDisconnectTime(nlohmann::json &object)
{
    if (object.contains(EXTENSION_AUTO_DISCONNECT_TIME_NAME)) {
        for (auto item : object.at(EXTENSION_AUTO_DISCONNECT_TIME_NAME).items()) {
            nlohmann::json& jsonObject = item.value();
            if (!jsonObject.contains(EXTENSION_TYPE) || !jsonObject.at(EXTENSION_TYPE).is_number()) {
                continue;
            }
            if (!jsonObject.contains(EXTENSION_AUTO_DISCONNECT_TIME) ||
                !jsonObject.at(EXTENSION_AUTO_DISCONNECT_TIME).is_number()) {
                continue;
            }
            AppExecFwk::ExtensionAbilityType type = static_cast<AppExecFwk::ExtensionAbilityType>(
                jsonObject.at(EXTENSION_TYPE).get<int32_t>());
            int32_t extensionAutoDisconnectTime = jsonObject.at(EXTENSION_AUTO_DISCONNECT_TIME).get<int32_t>();
            extensionAutoDisconnectTimeMap_[type] = extensionAutoDisconnectTime;
        }
    }
    return AmsConfigurationParameter::READ_OK;
}

int32_t ExtensionConfig::LoadExtensionConfiguration()
{
    HILOG_DEBUG("call");
    nlohmann::json jsonBuf;
    if (!ReadFileInfoJson(AMS_EXTENSION_CONFIG, jsonBuf)) {
        HILOG_ERROR("Parse file failed.");
        return AmsConfigurationParameter::READ_JSON_FAIL;
    }

    LoadExtensionAutoDisconnectTime(jsonBuf);

    return AmsConfigurationParameter::READ_OK;
}

bool ExtensionConfig::ReadFileInfoJson(const std::string &filePath, nlohmann::json &jsonBuf)
{
    if (access(filePath.c_str(), F_OK) != 0) {
        HILOG_DEBUG("%{public}s, not existed", filePath.c_str());
        return false;
    }

    std::fstream in;
    char errBuf[256];
    errBuf[0] = '\0';
    in.open(filePath, std::ios_base::in);
    if (!in.is_open()) {
        strerror_r(errno, errBuf, sizeof(errBuf));
        HILOG_ERROR("the file cannot be open due to  %{public}s", errBuf);
        return false;
    }

    in.seekg(0, std::ios::end);
    int64_t size = in.tellg();
    if (size <= 0) {
        HILOG_ERROR("the file is an empty file");
        in.close();
        return false;
    }

    in.seekg(0, std::ios::beg);
    jsonBuf = nlohmann::json::parse(in, nullptr, false);
    in.close();
    if (jsonBuf.is_discarded()) {
        HILOG_ERROR("bad profile file");
        return false;
    }

    return true;
}
}
}