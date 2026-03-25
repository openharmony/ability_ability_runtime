/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License")_;
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

#include <sstream>

#include "modular_object_rdb_data_mgr.h"
#include "modular_object_rdb_storage_mgr.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* MODULAR_OBJECT_EXTENSION_INFO = "ModularObjectExtensionInfo";
}
ModularObjectExtensionRdbStorageMgr::ModularObjectExtensionRdbStorageMgr()
{
}

ModularObjectExtensionRdbStorageMgr::~ModularObjectExtensionRdbStorageMgr()
{
    TAG_LOGD(AAFwkTag::EXT, "ModularObjectExtensionRdbStorageMgr is deleted");
}

int32_t ModularObjectExtensionRdbStorageMgr::InsertData(
    const std::string& key, const std::vector<AAFwk::ModularObjectExtensionInfo> &infos)
{
    if (infos.empty()) {
        return DelayedSingleton<ModularObjectExtensionRdbDataMgr>::GetInstance()->DeleteData(key);
    }
    std::string jsonString = ToJsonString(infos);
    return DelayedSingleton<ModularObjectExtensionRdbDataMgr>::GetInstance()->InsertData(key, jsonString);
}
int32_t ModularObjectExtensionRdbStorageMgr::UpdateData(
    const std::string& key, const std::vector<AAFwk::ModularObjectExtensionInfo> &infos)
{
    std::string jsonString = ToJsonString(infos);
    return DelayedSingleton<ModularObjectExtensionRdbDataMgr>::GetInstance()->UpdateData(key, jsonString);
}

int32_t ModularObjectExtensionRdbStorageMgr::DeleteData(const std::string& key)
{
    return DelayedSingleton<ModularObjectExtensionRdbDataMgr>::GetInstance()->DeleteData(key);
}

int32_t ModularObjectExtensionRdbStorageMgr::QueryData(const std::string& key,
    std::vector<AAFwk::ModularObjectExtensionInfo> &infos)
{
    std::string jsonString;
    auto ret = DelayedSingleton<ModularObjectExtensionRdbDataMgr>::GetInstance()->QueryData(key, jsonString);
    if (ret != NativeRdb::E_OK) {
        return ret;
    }
    FromJsonString(jsonString, infos);
    return NativeRdb::E_OK;
}

std::string ModularObjectExtensionRdbStorageMgr::ToJsonString(
    const std::vector<AAFwk::ModularObjectExtensionInfo> &infos)
{
    nlohmann::json jsonNodes = nlohmann::json::array();
    auto size = infos.size();
    for (size_t i = 0; i < size; i++) {
        jsonNodes.emplace_back(infos[i].ToJsonString());
    }
    nlohmann::json jsonObject {
        {MODULAR_OBJECT_EXTENSION_INFO, jsonNodes},
    };
    return jsonObject.dump();
}

void ModularObjectExtensionRdbStorageMgr::FromJsonString(const std::string& jsonStr,
    std::vector<AAFwk::ModularObjectExtensionInfo> &infos)
{
    nlohmann::json jsonObject = nlohmann::json::parse(jsonStr, nullptr, false);
    if (jsonObject.is_discarded()) {
        return;
    }
    if (jsonObject.contains(MODULAR_OBJECT_EXTENSION_INFO) && jsonObject[MODULAR_OBJECT_EXTENSION_INFO].is_array()) {
        auto size = jsonObject[MODULAR_OBJECT_EXTENSION_INFO].size();
        for (size_t i = 0; i < size; i++) {
            if (jsonObject[MODULAR_OBJECT_EXTENSION_INFO][i].is_string()) {
                AAFwk::ModularObjectExtensionInfo info;
                info.FromJsonString(jsonObject[MODULAR_OBJECT_EXTENSION_INFO][i]);
                infos.emplace_back(info);
            }
        }
    }
}
} // namespace AbilityRuntime
} // namespace OHOS
