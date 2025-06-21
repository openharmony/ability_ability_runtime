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

#include "extension_ability_info.h"

#include <fcntl.h>
#include <string>
#include <unistd.h>

#include "bundle_constants.h"
#include "hilog_tag_wrapper.h"
#include "json_util.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string NAME = "name";
const std::string SRC_ENTRANCE = "srcEntrance";
const std::string ICON = "icon";
const std::string ICON_ID = "iconId";
const std::string LABEL = "label";
const std::string LABEL_ID = "labelId";
const std::string DESCRIPTION = "description";
const std::string DESCRIPTION_ID = "descriptionId";
const std::string PRIORITY = "priority";
const std::string TYPE = "type";
const std::string PERMISSIONS = "permissions";
const std::string READ_PERMISSION = "readPermission";
const std::string WRITE_PERMISSION = "writePermission";
const std::string URI = "uri";
const std::string VISIBLE = "visible";
const std::string META_DATA = "metadata";
const std::string RESOURCE_PATH = "resourcePath";
const std::string ENABLED = "enabled";
const std::string PROCESS = "process";
const std::string COMPILE_MODE = "compileMode";
const std::string UID = "uid";
}; // namespace

bool to_json(cJSON *&jsonObject, const ExtensionAbilityInfo &extensionInfo)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "called");
    jsonObject = cJSON_CreateArray();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, Constants::BUNDLE_NAME, extensionInfo.bundleName.c_str());
    cJSON_AddStringToObject(jsonObject, Constants::MODULE_NAME, extensionInfo.moduleName.c_str());
    cJSON_AddStringToObject(jsonObject, NAME.c_str(), extensionInfo.name.c_str());
    cJSON_AddStringToObject(jsonObject, SRC_ENTRANCE.c_str(), extensionInfo.srcEntrance.c_str());
    cJSON_AddStringToObject(jsonObject, ICON.c_str(), extensionInfo.icon.c_str());
    cJSON_AddNumberToObject(jsonObject, ICON_ID.c_str(), static_cast<double>(extensionInfo.iconId));
    cJSON_AddStringToObject(jsonObject, LABEL.c_str(), extensionInfo.label.c_str());
    cJSON_AddNumberToObject(jsonObject, LABEL_ID.c_str(), static_cast<double>(extensionInfo.labelId));
    cJSON_AddStringToObject(jsonObject, DESCRIPTION.c_str(), extensionInfo.description.c_str());
    cJSON_AddNumberToObject(jsonObject, DESCRIPTION_ID.c_str(), static_cast<double>(extensionInfo.descriptionId));
    cJSON_AddNumberToObject(jsonObject, PRIORITY.c_str(), static_cast<double>(extensionInfo.priority));
    cJSON_AddNumberToObject(jsonObject, TYPE.c_str(), static_cast<double>(extensionInfo.type));
    cJSON_AddStringToObject(jsonObject, READ_PERMISSION.c_str(), extensionInfo.readPermission.c_str());
    cJSON_AddStringToObject(jsonObject, WRITE_PERMISSION.c_str(), extensionInfo.writePermission.c_str());
    cJSON_AddStringToObject(jsonObject, URI.c_str(), extensionInfo.uri.c_str());

    cJSON *permissionsItem = nullptr;
    if (!to_json(permissionsItem, extensionInfo.permissions)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json permissions failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, PERMISSIONS.c_str(), permissionsItem);

    cJSON_AddBoolToObject(jsonObject, VISIBLE.c_str(), extensionInfo.visible);

    cJSON *metadataItem = nullptr;
    if (!to_json(metadataItem, extensionInfo.metadata)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json metadata failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, META_DATA.c_str(), metadataItem);

    cJSON_AddStringToObject(jsonObject, RESOURCE_PATH.c_str(), extensionInfo.resourcePath.c_str());
    cJSON_AddStringToObject(jsonObject, Constants::HAP_PATH, extensionInfo.hapPath.c_str());
    cJSON_AddBoolToObject(jsonObject, ENABLED.c_str(), extensionInfo.enabled);
    cJSON_AddStringToObject(jsonObject, PROCESS.c_str(), extensionInfo.process.c_str());
    cJSON_AddNumberToObject(jsonObject, COMPILE_MODE.c_str(), static_cast<double>(extensionInfo.compileMode));
    cJSON_AddNumberToObject(jsonObject, UID.c_str(), static_cast<double>(extensionInfo.uid));
    return true;
}

void from_json(const cJSON *jsonObject, ExtensionAbilityInfo &extensionInfo)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "called");
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, Constants::BUNDLE_NAME, extensionInfo.bundleName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, Constants::MODULE_NAME, extensionInfo.moduleName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, NAME, extensionInfo.name, false, parseResult);
    GetStringValueIfFindKey(jsonObject, SRC_ENTRANCE, extensionInfo.srcEntrance, false, parseResult);
    GetStringValueIfFindKey(jsonObject, ICON, extensionInfo.icon, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, ICON_ID, extensionInfo.iconId, false, parseResult);
    GetStringValueIfFindKey(jsonObject, LABEL, extensionInfo.label, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, LABEL_ID, extensionInfo.labelId, false, parseResult);
    GetStringValueIfFindKey(jsonObject, DESCRIPTION, extensionInfo.description, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, DESCRIPTION_ID, extensionInfo.descriptionId, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, PRIORITY, extensionInfo.priority, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, TYPE, extensionInfo.type, false, parseResult);
    GetStringValueIfFindKey(jsonObject, READ_PERMISSION, extensionInfo.readPermission, false, parseResult);
    GetStringValueIfFindKey(jsonObject, WRITE_PERMISSION, extensionInfo.writePermission, false, parseResult);
    GetStringValueIfFindKey(jsonObject, URI, extensionInfo.uri, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, PERMISSIONS, extensionInfo.permissions, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, VISIBLE, extensionInfo.visible, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, META_DATA, extensionInfo.metadata, false, parseResult);
    GetStringValueIfFindKey(jsonObject, RESOURCE_PATH, extensionInfo.resourcePath, false, parseResult);
    GetStringValueIfFindKey(jsonObject, Constants::HAP_PATH, extensionInfo.hapPath, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, ENABLED, extensionInfo.enabled, false, parseResult);
    GetStringValueIfFindKey(jsonObject, PROCESS, extensionInfo.process, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, COMPILE_MODE, extensionInfo.compileMode, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, UID, extensionInfo.uid, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "ExtensionAbilityInfo error:%{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS