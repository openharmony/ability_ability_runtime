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

#include "ability_info.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "bundle_constants.h"
#include "hilog_tag_wrapper.h"
#include "json_util.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string JSON_KEY_PACKAGE = "package";
const std::string JSON_KEY_NAME = "name";
const std::string JSON_KEY_APPLICATION_NAME = "applicationName";
const std::string JSON_KEY_LABEL = "label";
const std::string JSON_KEY_DESCRIPTION = "description";
const std::string JSON_KEY_ICON_PATH = "iconPath";
const std::string JSON_KEY_THEME = "theme";
const std::string JSON_KEY_VISIBLE = "visible";
const std::string JSON_KEY_KIND = "kind";
const std::string JSON_KEY_TYPE = "type";
const std::string JSON_KEY_EXTENSION_ABILITY_TYPE = "extensionAbilityType";
const std::string JSON_KEY_ORIENTATION = "orientation";
const std::string JSON_KEY_LAUNCH_MODE = "launchMode";
const std::string JSON_KEY_CODE_PATH = "codePath";
const std::string JSON_KEY_RESOURCE_PATH = "resourcePath";
const std::string JSON_KEY_PERMISSIONS = "permissions";
const std::string JSON_KEY_PROCESS = "process";
const std::string JSON_KEY_DEVICE_TYPES = "deviceTypes";
const std::string JSON_KEY_DEVICE_CAPABILITIES = "deviceCapabilities";
const std::string JSON_KEY_URI = "uri";
const std::string JSON_KEY_IS_LAUNCHER_ABILITY = "isLauncherAbility";
const std::string JSON_KEY_REMOVE_MISSION_AFTER_TERMINATE = "removeMissionAfterTerminate";
const std::string JSON_KEY_IS_NATIVE_ABILITY = "isNativeAbility";
const std::string JSON_KEY_ENABLED = "enabled";
const std::string JSON_KEY_SUPPORT_PIP_MODE = "supportPipMode";
const std::string JSON_KEY_TARGET_ABILITY = "targetAbility";
const std::string JSON_KEY_READ_PERMISSION = "readPermission";
const std::string JSON_KEY_WRITE_PERMISSION = "writePermission";
const std::string JSON_KEY_CONFIG_CHANGES = "configChanges";
const std::string JSON_KEY_FORM = "form";
const std::string JSON_KEY_FORM_ENTITY = "formEntity";
const std::string JSON_KEY_MIN_FORM_HEIGHT = "minFormHeight";
const std::string JSON_KEY_DEFAULT_FORM_HEIGHT = "defaultFormHeight";
const std::string JSON_KEY_MIN_FORM_WIDTH = "minFormWidth";
const std::string JSON_KEY_DEFAULT_FORM_WIDTH = "defaultFormWidth";
const std::string JSON_KEY_BACKGROUND_MODES = "backgroundModes";
const std::string JSON_KEY_CUSTOMIZE_DATA = "customizeData";
const std::string JSON_KEY_META_DATA = "metaData";
const std::string JSON_KEY_META_VALUE = "value";
const std::string JSON_KEY_META_EXTRA = "extra";
const std::string JSON_KEY_LABEL_ID = "labelId";
const std::string JSON_KEY_DESCRIPTION_ID = "descriptionId";
const std::string JSON_KEY_ICON_ID = "iconId";
const std::string JSON_KEY_FORM_ENABLED = "formEnabled";
const std::string JSON_KEY_SRC_PATH = "srcPath";
const std::string JSON_KEY_SRC_LANGUAGE = "srcLanguage";
const std::string JSON_KEY_START_WINDOW = "startWindow";
const std::string JSON_KEY_START_WINDOW_ID = "startWindowId";
const std::string JSON_KEY_START_WINDOW_RESOURCE = "startWindowResource";
const std::string JSON_KEY_START_WINDOW_ICON = "startWindowIcon";
const std::string JSON_KEY_START_WINDOW_ICON_ID = "startWindowIconId";
const std::string JSON_KEY_START_WINDOW_BACKGROUND = "startWindowBackground";
const std::string JSON_KEY_START_WINDOW_BACKGROUND_ID = "startWindowBackgroundId";
const std::string JSON_KEY_COMPILE_MODE = "compileMode";
const std::string META_DATA = "metadata";
const std::string META_DATA_VALUEID = "valueId";
const std::string META_DATA_NAME = "name";
const std::string META_DATA_VALUE = "value";
const std::string META_DATA_RESOURCE = "resource";
const std::string SRC_ENTRANCE = "srcEntrance";
const std::string IS_MODULE_JSON = "isModuleJson";
const std::string IS_STAGE_BASED_MODEL = "isStageBasedModel";
const std::string CONTINUABLE = "continuable";
const std::string PRIORITY = "priority";
const std::string JOSN_KEY_SUPPORT_WINDOW_MODE = "supportWindowMode";
const std::string JOSN_KEY_MAX_WINDOW_RATIO = "maxWindowRatio";
const std::string JOSN_KEY_MIN_WINDOW_RATIO = "minWindowRatio";
const std::string JOSN_KEY_MAX_WINDOW_WIDTH = "maxWindowWidth";
const std::string JOSN_KEY_MIN_WINDOW_WIDTH = "minWindowWidth";
const std::string JOSN_KEY_MAX_WINDOW_HEIGHT = "maxWindowHeight";
const std::string JOSN_KEY_MIN_WINDOW_HEIGHT = "minWindowHeight";
const std::string JOSN_KEY_UID = "uid";
const std::string JOSN_KEY_EXCLUDE_FROM_MISSIONS = "excludeFromMissions";
const std::string JOSN_KEY_UNCLEARABLE_MISSION = "unclearableMission";
const std::string JSON_KEY_EXCLUDE_FROM_DOCK_MISSION = "excludeFromDock";
const std::string JSON_KEY_PREFER_MULTI_WINDOW_ORIENTATION_MISSION = "preferMultiWindowOrientation";
const std::string JSON_KEY_RECOVERABLE = "recoverable";
const std::string JSON_KEY_SUPPORT_EXT_NAMES = "supportExtNames";
const std::string JSON_KEY_SUPPORT_MIME_TYPES = "supportMimeTypes";
const std::string JSON_KEY_ISOLATION_PROCESS = "isolationProcess";
const std::string JSON_KEY_ORIENTATION_ID = "orientationId";
const std::string JSON_KEY_CONTINUE_BUNDLE_NAME = "continueBundleName";
const std::string JSON_KEY_CONTINUE_TYPE = "continueType";
const std::string JSON_KEY_APP_INDEX = "appIndex";
const std::string START_WINDOW_APP_ICON_ID = "startWindowAppIconId";
const std::string START_WINDOW_ILLUSTRATION_ID = "startWindowIllustrationId";
const std::string START_WINDOW_BRANDING_IMAGE_ID = "startWindowBrandingImageId";
const std::string START_WINDOW_BACKGROUND_COLOR_ID = "startWindowBackgroundColorId";
const std::string START_WINDOW_BACKGROUND_IMAGE_ID = "startWindowBackgroundImageId";
const std::string START_WINDOW_BACKGROUND_IMAGE_FIT = "startWindowBackgroundImageFit";
} // namespace
bool to_json(cJSON *&jsonObject, const std::string &value)
{
    jsonObject = cJSON_CreateString(value.c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create string json failed");
        return false;
    }
    return true;
}

bool to_json(cJSON *&jsonObject, const bool &value)
{
    jsonObject = cJSON_CreateBool(value);
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create bool json failed");
        return false;
    }
    return true;
}

bool to_json(cJSON *&jsonObject, const OHOS::AppExecFwk::SupportWindowMode &value)
{
    jsonObject = cJSON_CreateNumber(static_cast<double>(value));
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create number json failed");
        return false;
    }
    return true;
}

void from_json(const cJSON *jsonObject, std::string &value)
{
    if (jsonObject == nullptr || !cJSON_IsString(jsonObject)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "type not string");
        return;
    }
    if (std::string(jsonObject->valuestring).length() > Constants::MAX_JSON_ELEMENT_LENGTH) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "string length over");
        return;
    }
    value = jsonObject->valuestring;
}

void from_json(const cJSON *jsonObject, bool &value)
{
    if (jsonObject == nullptr || !cJSON_IsBool(jsonObject)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "type not bool");
        return;
    }
    value = jsonObject->type == cJSON_True;
}

bool to_json(cJSON *&jsonObject, const CustomizeData &customizeData)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, JSON_KEY_NAME.c_str(), customizeData.name.c_str());
    cJSON_AddStringToObject(jsonObject, JSON_KEY_META_VALUE.c_str(), customizeData.value.c_str());
    cJSON_AddStringToObject(jsonObject, JSON_KEY_META_EXTRA.c_str(), customizeData.extra.c_str());
    return true;
}

bool to_json(cJSON *&jsonObject, const MetaData &metaData)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON *customizeDatasItem = nullptr;
    if (!to_json(customizeDatasItem, metaData.customizeData)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json customizeData failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, JSON_KEY_CUSTOMIZE_DATA.c_str(), customizeDatasItem);
    return true;
}

bool to_json(cJSON *&jsonObject, const Metadata &metadata)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddNumberToObject(jsonObject, META_DATA_VALUEID.c_str(), metadata.valueId);
    cJSON_AddStringToObject(jsonObject, META_DATA_NAME.c_str(), metadata.name.c_str());
    cJSON_AddStringToObject(jsonObject, META_DATA_VALUE.c_str(), metadata.value.c_str());
    cJSON_AddStringToObject(jsonObject, META_DATA_RESOURCE.c_str(), metadata.resource.c_str());
    return true;
}

bool to_json(cJSON *&jsonObject, const StartWindowResource &startWindowResource)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddNumberToObject(jsonObject, START_WINDOW_APP_ICON_ID.c_str(),
        static_cast<double>(startWindowResource.startWindowAppIconId));
    cJSON_AddNumberToObject(jsonObject, START_WINDOW_ILLUSTRATION_ID.c_str(),
        static_cast<double>(startWindowResource.startWindowIllustrationId));
    cJSON_AddNumberToObject(jsonObject, START_WINDOW_BRANDING_IMAGE_ID.c_str(),
        static_cast<double>(startWindowResource.startWindowBrandingImageId));
    cJSON_AddNumberToObject(jsonObject, START_WINDOW_BACKGROUND_COLOR_ID.c_str(),
        static_cast<double>(startWindowResource.startWindowBackgroundColorId));
    cJSON_AddNumberToObject(jsonObject, START_WINDOW_BACKGROUND_IMAGE_ID.c_str(),
        static_cast<double>(startWindowResource.startWindowBackgroundImageId));
    cJSON_AddStringToObject(jsonObject, START_WINDOW_BACKGROUND_IMAGE_FIT.c_str(),
        startWindowResource.startWindowBackgroundImageFit.c_str());
    return true;
}

bool to_json(cJSON *&jsonObject, const AbilityInfo &abilityInfo)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, JSON_KEY_NAME.c_str(), abilityInfo.name.c_str());
    cJSON_AddStringToObject(jsonObject, JSON_KEY_LABEL.c_str(), abilityInfo.label.c_str());
    cJSON_AddStringToObject(jsonObject, JSON_KEY_DESCRIPTION.c_str(), abilityInfo.description.c_str());
    cJSON_AddStringToObject(jsonObject, JSON_KEY_ICON_PATH.c_str(), abilityInfo.iconPath.c_str());
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_LABEL_ID.c_str(), static_cast<double>(abilityInfo.labelId));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_DESCRIPTION_ID.c_str(),
        static_cast<double>(abilityInfo.descriptionId));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_ICON_ID.c_str(), static_cast<double>(abilityInfo.iconId));
    cJSON_AddStringToObject(jsonObject, JSON_KEY_THEME.c_str(), abilityInfo.theme.c_str());
    cJSON_AddBoolToObject(jsonObject, JSON_KEY_VISIBLE.c_str(), abilityInfo.visible);
    cJSON_AddStringToObject(jsonObject, JSON_KEY_KIND.c_str(), abilityInfo.kind.c_str());
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_TYPE.c_str(), static_cast<double>(abilityInfo.type));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_EXTENSION_ABILITY_TYPE.c_str(),
        static_cast<double>(abilityInfo.extensionAbilityType));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_ORIENTATION.c_str(), static_cast<double>(abilityInfo.orientation));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_LAUNCH_MODE.c_str(), static_cast<double>(abilityInfo.launchMode));
    cJSON_AddStringToObject(jsonObject, JSON_KEY_SRC_PATH.c_str(), abilityInfo.srcPath.c_str());
    cJSON_AddStringToObject(jsonObject, JSON_KEY_SRC_LANGUAGE.c_str(), abilityInfo.srcLanguage.c_str());

    cJSON *permissionsItem = nullptr;
    if (!to_json(permissionsItem, abilityInfo.permissions)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json permissions failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, JSON_KEY_PERMISSIONS.c_str(), permissionsItem);

    cJSON_AddStringToObject(jsonObject, JSON_KEY_PROCESS.c_str(), abilityInfo.process.c_str());

    cJSON *deviceTypesItem = nullptr;
    if (!to_json(deviceTypesItem, abilityInfo.deviceTypes)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json deviceTypes failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, JSON_KEY_DEVICE_TYPES.c_str(), deviceTypesItem);

    cJSON *deviceCapabilitiesItem = nullptr;
    if (!to_json(deviceCapabilitiesItem, abilityInfo.deviceCapabilities)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json deviceCapabilities failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, JSON_KEY_DEVICE_CAPABILITIES.c_str(), deviceCapabilitiesItem);

    cJSON_AddStringToObject(jsonObject, JSON_KEY_URI.c_str(), abilityInfo.uri.c_str());
    cJSON_AddStringToObject(jsonObject, JSON_KEY_TARGET_ABILITY.c_str(), abilityInfo.targetAbility.c_str());
    cJSON_AddBoolToObject(jsonObject, JSON_KEY_IS_LAUNCHER_ABILITY.c_str(), abilityInfo.isLauncherAbility);
    cJSON_AddBoolToObject(jsonObject, JSON_KEY_IS_NATIVE_ABILITY.c_str(), abilityInfo.isNativeAbility);
    cJSON_AddBoolToObject(jsonObject, JSON_KEY_ENABLED.c_str(), abilityInfo.enabled);
    cJSON_AddBoolToObject(jsonObject, JSON_KEY_SUPPORT_PIP_MODE.c_str(), abilityInfo.supportPipMode);
    cJSON_AddBoolToObject(jsonObject, JSON_KEY_FORM_ENABLED.c_str(), abilityInfo.formEnabled);
    cJSON_AddStringToObject(jsonObject, JSON_KEY_READ_PERMISSION.c_str(), abilityInfo.readPermission.c_str());
    cJSON_AddStringToObject(jsonObject, JSON_KEY_WRITE_PERMISSION.c_str(), abilityInfo.writePermission.c_str());

    cJSON *configChangesItem = nullptr;
    if (!to_json(configChangesItem, abilityInfo.configChanges)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json configChanges failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, JSON_KEY_CONFIG_CHANGES.c_str(), configChangesItem);

    cJSON_AddNumberToObject(jsonObject, JSON_KEY_FORM_ENTITY.c_str(), static_cast<double>(abilityInfo.formEntity));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_MIN_FORM_HEIGHT.c_str(),
        static_cast<double>(abilityInfo.minFormHeight));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_DEFAULT_FORM_HEIGHT.c_str(),
        static_cast<double>(abilityInfo.defaultFormHeight));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_MIN_FORM_WIDTH.c_str(), static_cast<double>(abilityInfo.minFormWidth));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_DEFAULT_FORM_WIDTH.c_str(),
        static_cast<double>(abilityInfo.defaultFormWidth));

    cJSON *metaDataItem = nullptr;
    if (!to_json(metaDataItem, abilityInfo.metaData)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json metaData failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, JSON_KEY_META_DATA.c_str(), metaDataItem);

    cJSON_AddNumberToObject(jsonObject, JSON_KEY_BACKGROUND_MODES.c_str(),
        static_cast<double>(abilityInfo.backgroundModes));
    cJSON_AddStringToObject(jsonObject, JSON_KEY_PACKAGE.c_str(), abilityInfo.package.c_str());
    cJSON_AddStringToObject(jsonObject, Constants::BUNDLE_NAME, abilityInfo.bundleName.c_str());
    cJSON_AddStringToObject(jsonObject, Constants::MODULE_NAME, abilityInfo.moduleName.c_str());
    cJSON_AddStringToObject(jsonObject, JSON_KEY_APPLICATION_NAME.c_str(), abilityInfo.applicationName.c_str());
    cJSON_AddStringToObject(jsonObject, JSON_KEY_CODE_PATH.c_str(), abilityInfo.codePath.c_str());
    cJSON_AddStringToObject(jsonObject, JSON_KEY_RESOURCE_PATH.c_str(), abilityInfo.resourcePath.c_str());
    cJSON_AddStringToObject(jsonObject, Constants::HAP_PATH, abilityInfo.hapPath.c_str());
    cJSON_AddStringToObject(jsonObject, SRC_ENTRANCE.c_str(), abilityInfo.srcEntrance.c_str());

    cJSON *metadataItem = nullptr;
    if (!to_json(metadataItem, abilityInfo.metadata)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json metadata failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, META_DATA.c_str(), metadataItem);

    cJSON_AddBoolToObject(jsonObject, IS_MODULE_JSON.c_str(), abilityInfo.isModuleJson);
    cJSON_AddBoolToObject(jsonObject, IS_STAGE_BASED_MODEL.c_str(), abilityInfo.isStageBasedModel);
    cJSON_AddBoolToObject(jsonObject, CONTINUABLE.c_str(), abilityInfo.continuable);
    cJSON_AddNumberToObject(jsonObject, PRIORITY.c_str(), static_cast<double>(abilityInfo.priority));
    cJSON_AddStringToObject(jsonObject, JSON_KEY_START_WINDOW.c_str(), abilityInfo.startWindow.c_str());
    cJSON_AddStringToObject(jsonObject, JSON_KEY_START_WINDOW_ICON.c_str(), abilityInfo.startWindowIcon.c_str());
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_START_WINDOW_ICON_ID.c_str(),
        static_cast<double>(abilityInfo.startWindowIconId));
    cJSON_AddStringToObject(jsonObject, JSON_KEY_START_WINDOW_BACKGROUND.c_str(),
        abilityInfo.startWindowBackground.c_str());
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_START_WINDOW_BACKGROUND_ID.c_str(),
        static_cast<double>(abilityInfo.startWindowBackgroundId));
    cJSON_AddBoolToObject(jsonObject, JSON_KEY_REMOVE_MISSION_AFTER_TERMINATE.c_str(),
        abilityInfo.removeMissionAfterTerminate);
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_COMPILE_MODE.c_str(), static_cast<double>(abilityInfo.compileMode));

    cJSON *windowModesItem = nullptr;
    if (!to_json(windowModesItem, abilityInfo.windowModes)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json windowModes failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, JOSN_KEY_SUPPORT_WINDOW_MODE.c_str(), windowModesItem);

    cJSON_AddNumberToObject(jsonObject, JOSN_KEY_MAX_WINDOW_WIDTH.c_str(),
        static_cast<double>(abilityInfo.maxWindowWidth));
    cJSON_AddNumberToObject(jsonObject, JOSN_KEY_MIN_WINDOW_WIDTH.c_str(),
        static_cast<double>(abilityInfo.minWindowWidth));
    cJSON_AddNumberToObject(jsonObject, JOSN_KEY_MAX_WINDOW_HEIGHT.c_str(),
        static_cast<double>(abilityInfo.maxWindowHeight));
    cJSON_AddNumberToObject(jsonObject, JOSN_KEY_MIN_WINDOW_HEIGHT.c_str(),
        static_cast<double>(abilityInfo.minWindowHeight));
    cJSON_AddNumberToObject(jsonObject, JOSN_KEY_UID.c_str(), static_cast<double>(abilityInfo.uid));
    cJSON_AddBoolToObject(jsonObject, JOSN_KEY_EXCLUDE_FROM_MISSIONS.c_str(), abilityInfo.excludeFromMissions);
    cJSON_AddBoolToObject(jsonObject, JOSN_KEY_UNCLEARABLE_MISSION.c_str(), abilityInfo.unclearableMission);
    cJSON_AddBoolToObject(jsonObject, JSON_KEY_RECOVERABLE.c_str(), abilityInfo.recoverable);

    cJSON *supportExtNamesItem = nullptr;
    if (!to_json(supportExtNamesItem, abilityInfo.supportExtNames)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json supportExtNames failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, JSON_KEY_SUPPORT_EXT_NAMES.c_str(), supportExtNamesItem);

    cJSON *supportMimeTypesItem = nullptr;
    if (!to_json(supportMimeTypesItem, abilityInfo.supportMimeTypes)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json supportMimeTypes failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, JSON_KEY_SUPPORT_MIME_TYPES.c_str(), supportMimeTypesItem);

    cJSON_AddBoolToObject(jsonObject, JSON_KEY_ISOLATION_PROCESS.c_str(), abilityInfo.isolationProcess);

    cJSON *continueTypeItem = nullptr;
    if (!to_json(continueTypeItem, abilityInfo.continueType)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json continueType failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, JSON_KEY_CONTINUE_TYPE.c_str(), continueTypeItem);

    cJSON *continueBundleNamesItem = nullptr;
    if (!to_json(continueBundleNamesItem, abilityInfo.continueBundleNames)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json continueBundleNames failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, JSON_KEY_CONTINUE_BUNDLE_NAME.c_str(), continueBundleNamesItem);

    cJSON_AddNumberToObject(jsonObject, JSON_KEY_APP_INDEX.c_str(), static_cast<double>(abilityInfo.appIndex));
    cJSON_AddNumberToObject(jsonObject, JSON_KEY_ORIENTATION_ID.c_str(),
        static_cast<double>(abilityInfo.orientationId));

    cJSON *startWindowResourceItem = nullptr;
    if (!to_json(startWindowResourceItem, abilityInfo.startWindowResource)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json startWindowResource failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, JSON_KEY_START_WINDOW_RESOURCE.c_str(), startWindowResourceItem);

    cJSON_AddNumberToObject(jsonObject, JOSN_KEY_MAX_WINDOW_RATIO.c_str(),
        static_cast<double>(abilityInfo.maxWindowRatio == 0 ? 0 : abilityInfo.maxWindowRatio));
    cJSON_AddNumberToObject(jsonObject, JOSN_KEY_MIN_WINDOW_RATIO.c_str(),
        static_cast<double>(abilityInfo.minWindowRatio == 0 ? 0 : abilityInfo.minWindowRatio));
    return true;
}

void from_json(const cJSON *jsonObject, CustomizeData &customizeData)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, JSON_KEY_NAME, customizeData.name, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_META_VALUE, customizeData.value, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_META_EXTRA, customizeData.extra, false, parseResult);
}

void from_json(const cJSON *jsonObject, MetaData &metaData)
{
    int32_t parseResult = ERR_OK;
    GetObjectValuesIfFindKey(jsonObject, JSON_KEY_CUSTOMIZE_DATA, metaData.customizeData, false, parseResult);
}

void from_json(const cJSON *jsonObject, Metadata &metadata)
{
    int32_t parseResult = ERR_OK;
    GetNumberValueIfFindKey(jsonObject, META_DATA_VALUEID, metadata.valueId, false, parseResult);
    GetStringValueIfFindKey(jsonObject, META_DATA_NAME, metadata.name, false, parseResult);
    GetStringValueIfFindKey(jsonObject, META_DATA_VALUE, metadata.value, false, parseResult);
    GetStringValueIfFindKey(jsonObject, META_DATA_RESOURCE, metadata.resource, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "read Ability Metadata error:%{public}d", parseResult);
    }
}

void from_json(const cJSON *jsonObject, StartWindowResource &startWindowResource)
{
    int32_t parseResult = ERR_OK;
    GetNumberValueIfFindKey(jsonObject, START_WINDOW_APP_ICON_ID,
        startWindowResource.startWindowAppIconId, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, START_WINDOW_ILLUSTRATION_ID,
        startWindowResource.startWindowIllustrationId, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, START_WINDOW_BRANDING_IMAGE_ID,
        startWindowResource.startWindowBrandingImageId, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, START_WINDOW_BACKGROUND_COLOR_ID,
        startWindowResource.startWindowBackgroundColorId, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, START_WINDOW_BACKGROUND_IMAGE_ID,
        startWindowResource.startWindowBackgroundImageId, false, parseResult);
    GetStringValueIfFindKey(jsonObject, START_WINDOW_BACKGROUND_IMAGE_FIT,
        startWindowResource.startWindowBackgroundImageFit, false, parseResult);
}

void from_json(const cJSON *jsonObject, AbilityInfo &abilityInfo)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, JSON_KEY_NAME, abilityInfo.name, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_LABEL, abilityInfo.label, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_DESCRIPTION, abilityInfo.description, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_ICON_PATH, abilityInfo.iconPath, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_LABEL_ID, abilityInfo.labelId, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_DESCRIPTION_ID, abilityInfo.descriptionId, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_ICON_ID, abilityInfo.iconId, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_THEME, abilityInfo.theme, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, JSON_KEY_VISIBLE, abilityInfo.visible, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_KIND, abilityInfo.kind, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_TYPE, abilityInfo.type, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_EXTENSION_ABILITY_TYPE, abilityInfo.extensionAbilityType, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_ORIENTATION, abilityInfo.orientation, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_LAUNCH_MODE, abilityInfo.launchMode, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_SRC_PATH, abilityInfo.srcPath, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_SRC_LANGUAGE, abilityInfo.srcLanguage, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, JSON_KEY_PERMISSIONS, abilityInfo.permissions, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_PROCESS, abilityInfo.process, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, JSON_KEY_DEVICE_TYPES, abilityInfo.deviceTypes, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, JSON_KEY_DEVICE_CAPABILITIES, abilityInfo.deviceCapabilities, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_URI, abilityInfo.uri, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_TARGET_ABILITY, abilityInfo.targetAbility, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, JSON_KEY_IS_LAUNCHER_ABILITY, abilityInfo.isLauncherAbility, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, JSON_KEY_IS_NATIVE_ABILITY, abilityInfo.isNativeAbility, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, JSON_KEY_ENABLED, abilityInfo.enabled, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, JSON_KEY_SUPPORT_PIP_MODE, abilityInfo.supportPipMode, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, JSON_KEY_FORM_ENABLED, abilityInfo.formEnabled, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_READ_PERMISSION, abilityInfo.readPermission, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_WRITE_PERMISSION, abilityInfo.writePermission, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, JSON_KEY_CONFIG_CHANGES, abilityInfo.configChanges, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_FORM_ENTITY, abilityInfo.formEntity, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_MIN_FORM_HEIGHT, abilityInfo.minFormHeight, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_DEFAULT_FORM_HEIGHT, abilityInfo.defaultFormHeight, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_MIN_FORM_WIDTH, abilityInfo.minFormWidth, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_DEFAULT_FORM_WIDTH, abilityInfo.defaultFormWidth, false, parseResult);
    GetObjectValueIfFindKey(jsonObject, JSON_KEY_META_DATA, abilityInfo.metaData, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_BACKGROUND_MODES, abilityInfo.backgroundModes, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_PACKAGE, abilityInfo.package, false, parseResult);
    GetStringValueIfFindKey(jsonObject, Constants::BUNDLE_NAME, abilityInfo.bundleName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, Constants::MODULE_NAME, abilityInfo.moduleName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_APPLICATION_NAME, abilityInfo.applicationName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_CODE_PATH, abilityInfo.codePath, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_RESOURCE_PATH, abilityInfo.resourcePath, false, parseResult);
    GetStringValueIfFindKey(jsonObject, Constants::HAP_PATH, abilityInfo.hapPath, false, parseResult);
    GetStringValueIfFindKey(jsonObject, SRC_ENTRANCE, abilityInfo.srcEntrance, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, META_DATA, abilityInfo.metadata, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, IS_MODULE_JSON, abilityInfo.isModuleJson, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, IS_STAGE_BASED_MODEL, abilityInfo.isStageBasedModel, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, CONTINUABLE, abilityInfo.continuable, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, PRIORITY, abilityInfo.priority, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_START_WINDOW_ICON, abilityInfo.startWindowIcon, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_START_WINDOW_ICON_ID, abilityInfo.startWindowIconId, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_START_WINDOW_BACKGROUND, abilityInfo.startWindowBackground, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_START_WINDOW_BACKGROUND_ID, abilityInfo.startWindowBackgroundId, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, JSON_KEY_REMOVE_MISSION_AFTER_TERMINATE, abilityInfo.removeMissionAfterTerminate,
        false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_COMPILE_MODE, abilityInfo.compileMode, false, parseResult);
    GetNumberValuesIfFindKey(jsonObject, JOSN_KEY_SUPPORT_WINDOW_MODE, abilityInfo.windowModes, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JOSN_KEY_MAX_WINDOW_RATIO, abilityInfo.maxWindowRatio, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JOSN_KEY_MIN_WINDOW_RATIO, abilityInfo.minWindowRatio, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JOSN_KEY_MAX_WINDOW_WIDTH, abilityInfo.maxWindowWidth, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JOSN_KEY_MIN_WINDOW_WIDTH, abilityInfo.minWindowWidth, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JOSN_KEY_MAX_WINDOW_HEIGHT, abilityInfo.maxWindowHeight, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JOSN_KEY_MIN_WINDOW_HEIGHT, abilityInfo.minWindowHeight, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JOSN_KEY_UID, abilityInfo.uid, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, JOSN_KEY_EXCLUDE_FROM_MISSIONS, abilityInfo.excludeFromMissions, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, JOSN_KEY_UNCLEARABLE_MISSION, abilityInfo.unclearableMission, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, JSON_KEY_RECOVERABLE, abilityInfo.recoverable, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, JSON_KEY_SUPPORT_EXT_NAMES, abilityInfo.supportExtNames, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, JSON_KEY_SUPPORT_MIME_TYPES, abilityInfo.supportMimeTypes, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, JSON_KEY_ISOLATION_PROCESS, abilityInfo.isolationProcess, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, JSON_KEY_CONTINUE_TYPE, abilityInfo.continueType, false, parseResult);
    GetUnorderedSetValuesIfFindKey(jsonObject, JSON_KEY_CONTINUE_BUNDLE_NAME, abilityInfo.continueBundleNames, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_APP_INDEX, abilityInfo.appIndex, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_ORIENTATION_ID, abilityInfo.orientationId, false, parseResult);
    GetStringValueIfFindKey(jsonObject, JSON_KEY_START_WINDOW, abilityInfo.startWindow, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, JSON_KEY_START_WINDOW_ID, abilityInfo.startWindowId, false, parseResult);
    GetObjectValueIfFindKey(jsonObject, JSON_KEY_START_WINDOW_RESOURCE, abilityInfo.startWindowResource, false,
        parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "AbilityInfo from_json error:%{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
