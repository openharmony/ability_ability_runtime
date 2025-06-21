/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "module_info.h"

#include "hilog_tag_wrapper.h"
#include "json_util.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string MODULE_INFO_MODULE_SOURCE_DIR = "moduleSourceDir";
const std::string MODULE_INFO_PRELOADS = "preloads";
}

bool to_json(cJSON *&jsonObject, const ModuleInfo &moduleInfo)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, Constants::MODULE_NAME, moduleInfo.moduleName.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_INFO_MODULE_SOURCE_DIR.c_str(), moduleInfo.moduleSourceDir.c_str());

    cJSON *preloadsItem = nullptr;
    if (!to_json(preloadsItem, moduleInfo.preloads)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json preloads failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, MODULE_INFO_PRELOADS.c_str(), preloadsItem);
    return true;
}

void from_json(const cJSON *jsonObject, ModuleInfo &moduleInfo)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, Constants::MODULE_NAME, moduleInfo.moduleName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_INFO_MODULE_SOURCE_DIR, moduleInfo.moduleSourceDir, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, MODULE_INFO_PRELOADS, moduleInfo.preloads, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "read module moduleInfo error:%{public}d", parseResult);
    }
}
} // namespace AppExecFwk
} // namespace OHOS
