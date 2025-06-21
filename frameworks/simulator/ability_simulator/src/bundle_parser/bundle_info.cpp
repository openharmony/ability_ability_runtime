/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "bundle_info.h"

#include <cstdint>

#include "hilog_tag_wrapper.h"
#include "json_util.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* BUNDLE_INFO_NAME = "name";
const char* BUNDLE_INFO_LABEL = "label";
const char* BUNDLE_INFO_DESCRIPTION = "description";
const char* BUNDLE_INFO_VENDOR = "vendor";
const char* BUNDLE_INFO_IS_KEEP_ALIVE = "isKeepAlive";
const char* BUNDLE_INFO_SINGLETON = "singleton";
const char* BUNDLE_INFO_IS_NATIVE_APP = "isNativeApp";
const char* BUNDLE_INFO_IS_PREINSTALL_APP = "isPreInstallApp";
const char* BUNDLE_INFO_IS_DIFFERENT_NAME = "isDifferentName";
const char* BUNDLE_INFO_ABILITY_INFOS = "abilityInfos";
const char* BUNDLE_INFO_HAP_MODULE_INFOS = "hapModuleInfos";
const char* BUNDLE_INFO_EXTENSION_ABILITY_INFOS = "extensionAbilityInfo";
const char* BUNDLE_INFO_JOINT_USERID = "jointUserId";
const char* BUNDLE_INFO_VERSION_CODE = "versionCode";
const char* BUNDLE_INFO_MIN_COMPATIBLE_VERSION_CODE = "minCompatibleVersionCode";
const char* BUNDLE_INFO_VERSION_NAME = "versionName";
const char* BUNDLE_INFO_MIN_SDK_VERSION = "minSdkVersion";
const char* BUNDLE_INFO_MAX_SDK_VERSION = "maxSdkVersion";
const char* BUNDLE_INFO_MAIN_ENTRY = "mainEntry";
const char* BUNDLE_INFO_CPU_ABI = "cpuAbi";
const char* BUNDLE_INFO_APPID = "appId";
const char* BUNDLE_INFO_COMPATIBLE_VERSION = "compatibleVersion";
const char* BUNDLE_INFO_TARGET_VERSION = "targetVersion";
const char* BUNDLE_INFO_RELEASE_TYPE = "releaseType";
const char* BUNDLE_INFO_UID = "uid";
const char* BUNDLE_INFO_GID = "gid";
const char* BUNDLE_INFO_SEINFO = "seInfo";
const char* BUNDLE_INFO_INSTALL_TIME = "installTime";
const char* BUNDLE_INFO_UPDATE_TIME = "updateTime";
const char* BUNDLE_INFO_FIRST_INSTALL_TIME = "firstInstallTime";
const char* BUNDLE_INFO_ENTRY_MODULE_NAME = "entryModuleName";
const char* BUNDLE_INFO_ENTRY_INSTALLATION_FREE = "entryInstallationFree";
const char* BUNDLE_INFO_REQ_PERMISSIONS = "reqPermissions";
const char* BUNDLE_INFO_REQ_PERMISSION_STATES = "reqPermissionStates";
const char* BUNDLE_INFO_REQ_PERMISSION_DETAILS = "reqPermissionDetails";
const char* BUNDLE_INFO_DEF_PERMISSIONS = "defPermissions";
const char* BUNDLE_INFO_HAP_MODULE_NAMES = "hapModuleNames";
const char* BUNDLE_INFO_MODULE_NAMES = "moduleNames";
const char* BUNDLE_INFO_MODULE_PUBLIC_DIRS = "modulePublicDirs";
const char* BUNDLE_INFO_MODULE_DIRS = "moduleDirs";
const char* BUNDLE_INFO_MODULE_RES_PATHS = "moduleResPaths";
const char* REQUESTPERMISSION_NAME = "name";
const char* REQUESTPERMISSION_REASON = "reason";
const char* REQUESTPERMISSION_REASON_ID = "reasonId";
const char* REQUESTPERMISSION_USEDSCENE = "usedScene";
const char* REQUESTPERMISSION_ABILITIES = "abilities";
const char* REQUESTPERMISSION_ABILITY = "ability";
const char* REQUESTPERMISSION_WHEN = "when";
const char* REQUESTPERMISSION_MODULE_NAME = "moduleName";
const char* SIGNATUREINFO_APPID = "appId";
const char* SIGNATUREINFO_FINGERPRINT = "fingerprint";
const char* BUNDLE_INFO_APP_INDEX = "appIndex";
const char* BUNDLE_INFO_ERROR_CODE = "errorCode";
const char* BUNDLE_INFO_SIGNATURE_INFO = "signatureInfo";
const char* OVERLAY_TYPE = "overlayType";
const char* OVERLAY_BUNDLE_INFO = "overlayBundleInfos";
const char* APP_IDENTIFIER = "appIdentifier";
const char* BUNDLE_INFO_OLD_APPIDS = "oldAppIds";
const char* BUNDLE_INFO_ROUTER_ARRAY = "routerArray";
const char* BUNDLE_INFO_IS_NEW_VERSION = "isNewVersion";
const char* BUNDLE_INFO_HAS_PLUGIN = "hasPlugin";
const uint32_t BUNDLE_CAPACITY = 204800; // 200K
}

bool to_json(cJSON *&jsonObject, const RequestPermissionUsedScene &usedScene)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON *abilitiesItem = nullptr;
    if (!to_json(abilitiesItem, usedScene.abilities)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json abilities failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, REQUESTPERMISSION_ABILITIES, abilitiesItem);
    cJSON_AddStringToObject(jsonObject, REQUESTPERMISSION_WHEN, usedScene.when.c_str());
    return true;
}

bool to_json(cJSON *&jsonObject, const RequestPermission &requestPermission)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, REQUESTPERMISSION_NAME, requestPermission.name.c_str());
    cJSON_AddStringToObject(jsonObject, REQUESTPERMISSION_REASON, requestPermission.reason.c_str());
    cJSON_AddNumberToObject(jsonObject, REQUESTPERMISSION_REASON_ID, requestPermission.reasonId);
    cJSON *usedSceneItem = nullptr;
    if (!to_json(usedSceneItem, requestPermission.usedScene)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json usedScene failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, REQUESTPERMISSION_USEDSCENE, usedSceneItem);
    cJSON_AddStringToObject(jsonObject, REQUESTPERMISSION_MODULE_NAME, requestPermission.moduleName.c_str());
    return true;
}

bool to_json(cJSON *&jsonObject, const SignatureInfo &signatureInfo)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, SIGNATUREINFO_APPID, signatureInfo.appId.c_str());
    cJSON_AddStringToObject(jsonObject, SIGNATUREINFO_FINGERPRINT, signatureInfo.fingerprint.c_str());
    cJSON_AddStringToObject(jsonObject, APP_IDENTIFIER, signatureInfo.appIdentifier.c_str());
    return true;
}

void from_json(const cJSON *jsonObject, RequestPermissionUsedScene &usedScene)
{
    int32_t parseResult = ERR_OK;
    GetStringValuesIfFindKey(jsonObject, REQUESTPERMISSION_ABILITIES, usedScene.abilities, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, REQUESTPERMISSION_ABILITY, usedScene.abilities, false, parseResult);
    GetStringValueIfFindKey(jsonObject, REQUESTPERMISSION_WHEN, usedScene.when, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "read RequestPermissionUsedScene error : %{public}d", parseResult);
    }
}

void from_json(const cJSON *jsonObject, RequestPermission &requestPermission)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, REQUESTPERMISSION_NAME, requestPermission.name, false, parseResult);
    GetStringValueIfFindKey(jsonObject, REQUESTPERMISSION_REASON, requestPermission.reason, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, REQUESTPERMISSION_REASON_ID, requestPermission.reasonId, false, parseResult);
    GetObjectValueIfFindKey(jsonObject, REQUESTPERMISSION_USEDSCENE, requestPermission.usedScene, false, parseResult);
    GetStringValueIfFindKey(jsonObject, REQUESTPERMISSION_MODULE_NAME, requestPermission.moduleName, false,
        parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "read RequestPermission error : %{public}d", parseResult);
    }
}

void from_json(const cJSON *jsonObject, SignatureInfo &signatureInfo)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, SIGNATUREINFO_APPID, signatureInfo.appId, false, parseResult);
    GetStringValueIfFindKey(jsonObject, SIGNATUREINFO_FINGERPRINT, signatureInfo.fingerprint, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APP_IDENTIFIER, signatureInfo.appIdentifier, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "read SignatureInfo error : %{public}d", parseResult);
    }
}

bool to_json(cJSON *&jsonObject, const BundleInfo &bundleInfo)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, BUNDLE_INFO_NAME, bundleInfo.name.c_str());
    cJSON_AddStringToObject(jsonObject, BUNDLE_INFO_LABEL, bundleInfo.label.c_str());
    cJSON_AddStringToObject(jsonObject, BUNDLE_INFO_DESCRIPTION, bundleInfo.description.c_str());
    cJSON_AddStringToObject(jsonObject, BUNDLE_INFO_VENDOR, bundleInfo.vendor.c_str());
    cJSON_AddBoolToObject(jsonObject, BUNDLE_INFO_IS_KEEP_ALIVE, bundleInfo.isKeepAlive);
    cJSON_AddBoolToObject(jsonObject, BUNDLE_INFO_IS_NATIVE_APP, bundleInfo.isNativeApp);
    cJSON_AddBoolToObject(jsonObject, BUNDLE_INFO_IS_PREINSTALL_APP, bundleInfo.isPreInstallApp);
    cJSON_AddBoolToObject(jsonObject, BUNDLE_INFO_IS_DIFFERENT_NAME, bundleInfo.isDifferentName);

    cJSON *abilityInfosItem = nullptr;
    if (!to_json(abilityInfosItem, bundleInfo.abilityInfos)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json abilityInfos failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_ABILITY_INFOS, abilityInfosItem);

    cJSON *hapModuleInfosItem = nullptr;
    if (!to_json(hapModuleInfosItem, bundleInfo.hapModuleInfos)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json hapModuleInfos failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_HAP_MODULE_INFOS, hapModuleInfosItem);

    cJSON *extensionInfosItem = nullptr;
    if (!to_json(extensionInfosItem, bundleInfo.extensionInfos)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json extensionInfos failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_EXTENSION_ABILITY_INFOS, extensionInfosItem);

    cJSON_AddStringToObject(jsonObject, BUNDLE_INFO_JOINT_USERID, bundleInfo.jointUserId.c_str());
    cJSON_AddNumberToObject(jsonObject, BUNDLE_INFO_VERSION_CODE, static_cast<double>(bundleInfo.versionCode));
    cJSON_AddNumberToObject(jsonObject, BUNDLE_INFO_MIN_COMPATIBLE_VERSION_CODE,
        static_cast<double>(bundleInfo.minCompatibleVersionCode));
    cJSON_AddStringToObject(jsonObject, BUNDLE_INFO_VERSION_NAME, bundleInfo.versionName.c_str());
    cJSON_AddNumberToObject(jsonObject, BUNDLE_INFO_MIN_SDK_VERSION, static_cast<double>(bundleInfo.minSdkVersion));
    cJSON_AddNumberToObject(jsonObject, BUNDLE_INFO_MAX_SDK_VERSION, static_cast<double>(bundleInfo.maxSdkVersion));
    cJSON_AddStringToObject(jsonObject, BUNDLE_INFO_MAIN_ENTRY, bundleInfo.mainEntry.c_str());
    cJSON_AddStringToObject(jsonObject, BUNDLE_INFO_CPU_ABI, bundleInfo.cpuAbi.c_str());
    cJSON_AddStringToObject(jsonObject, BUNDLE_INFO_APPID, bundleInfo.appId.c_str());
    cJSON_AddNumberToObject(jsonObject, BUNDLE_INFO_COMPATIBLE_VERSION,
        static_cast<double>(bundleInfo.compatibleVersion));
    cJSON_AddNumberToObject(jsonObject, BUNDLE_INFO_TARGET_VERSION, static_cast<double>(bundleInfo.targetVersion));
    cJSON_AddStringToObject(jsonObject, BUNDLE_INFO_RELEASE_TYPE, bundleInfo.releaseType.c_str());
    cJSON_AddNumberToObject(jsonObject, BUNDLE_INFO_UID, static_cast<double>(bundleInfo.uid));
    cJSON_AddNumberToObject(jsonObject, BUNDLE_INFO_GID, static_cast<double>(bundleInfo.gid));
    cJSON_AddStringToObject(jsonObject, BUNDLE_INFO_SEINFO, bundleInfo.seInfo.c_str());
    cJSON_AddNumberToObject(jsonObject, BUNDLE_INFO_INSTALL_TIME, static_cast<double>(bundleInfo.installTime));
    cJSON_AddNumberToObject(jsonObject, BUNDLE_INFO_UPDATE_TIME, static_cast<double>(bundleInfo.updateTime));
    cJSON_AddNumberToObject(jsonObject, BUNDLE_INFO_FIRST_INSTALL_TIME,
        static_cast<double>(bundleInfo.firstInstallTime));
    cJSON_AddStringToObject(jsonObject, BUNDLE_INFO_ENTRY_MODULE_NAME, bundleInfo.entryModuleName.c_str());
    cJSON_AddBoolToObject(jsonObject, BUNDLE_INFO_ENTRY_INSTALLATION_FREE, bundleInfo.entryInstallationFree);

    cJSON *reqPermissionsItem = nullptr;
    if (!to_json(reqPermissionsItem, bundleInfo.reqPermissions)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json reqPermissions failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_REQ_PERMISSIONS, reqPermissionsItem);

    cJSON *reqPermissionStatesItem = nullptr;
    if (!to_json(reqPermissionStatesItem, bundleInfo.reqPermissionStates)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json reqPermissionStates failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_REQ_PERMISSION_STATES, reqPermissionStatesItem);

    cJSON *reqPermissionDetailsItem = nullptr;
    if (!to_json(reqPermissionDetailsItem, bundleInfo.reqPermissionDetails)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json reqPermissionDetails failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_REQ_PERMISSION_DETAILS, reqPermissionDetailsItem);

    cJSON *defPermissionsItem = nullptr;
    if (!to_json(defPermissionsItem, bundleInfo.defPermissions)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json defPermissions failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_DEF_PERMISSIONS, defPermissionsItem);

    cJSON *hapModuleNamesItem = nullptr;
    if (!to_json(hapModuleNamesItem, bundleInfo.hapModuleNames)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json hapModuleNames failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_HAP_MODULE_NAMES, hapModuleNamesItem);

    cJSON *moduleNamesItem = nullptr;
    if (!to_json(moduleNamesItem, bundleInfo.moduleNames)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json moduleNames failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_MODULE_NAMES, moduleNamesItem);

    cJSON *modulePublicDirsItem = nullptr;
    if (!to_json(modulePublicDirsItem, bundleInfo.modulePublicDirs)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json modulePublicDirs failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_MODULE_PUBLIC_DIRS, modulePublicDirsItem);

    cJSON *moduleDirsItem = nullptr;
    if (!to_json(moduleDirsItem, bundleInfo.moduleDirs)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json moduleDirs failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_MODULE_DIRS, moduleDirsItem);

    cJSON *moduleResPathsItem = nullptr;
    if (!to_json(moduleResPathsItem, bundleInfo.moduleResPaths)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json moduleResPaths failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_MODULE_RES_PATHS, moduleResPathsItem);

    cJSON_AddBoolToObject(jsonObject, BUNDLE_INFO_SINGLETON, bundleInfo.singleton);
    cJSON_AddNumberToObject(jsonObject, BUNDLE_INFO_APP_INDEX, static_cast<double>(bundleInfo.appIndex));

    cJSON *signatureInfoItem = nullptr;
    if (!to_json(signatureInfoItem, bundleInfo.signatureInfo)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json signatureInfo failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_SIGNATURE_INFO, signatureInfoItem);

    cJSON_AddNumberToObject(jsonObject, OVERLAY_TYPE, static_cast<double>(bundleInfo.overlayType));

    cJSON *overlayBundleInfosItem = nullptr;
    if (!to_json(overlayBundleInfosItem, bundleInfo.overlayBundleInfos)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json overlayBundleInfos failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, OVERLAY_BUNDLE_INFO, overlayBundleInfosItem);

    cJSON *oldAppIdsItem = nullptr;
    if (!to_json(oldAppIdsItem, bundleInfo.oldAppIds)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json oldAppIds failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_OLD_APPIDS, oldAppIdsItem);

    cJSON *routerArrayItem = nullptr;
    if (!to_json(routerArrayItem, bundleInfo.routerArray)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json routerArray failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_INFO_OLD_APPIDS, routerArrayItem);

    cJSON_AddBoolToObject(jsonObject, BUNDLE_INFO_IS_NEW_VERSION, bundleInfo.isNewVersion);
    cJSON_AddBoolToObject(jsonObject, BUNDLE_INFO_HAS_PLUGIN, bundleInfo.hasPlugin);

    return true;
}

void from_json(const cJSON *jsonObject, BundleInfo &bundleInfo)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, BUNDLE_INFO_NAME, bundleInfo.name, false, parseResult);
    GetStringValueIfFindKey(jsonObject, BUNDLE_INFO_LABEL, bundleInfo.label, false, parseResult);
    GetStringValueIfFindKey(jsonObject, BUNDLE_INFO_DESCRIPTION, bundleInfo.description, false, parseResult);
    GetStringValueIfFindKey(jsonObject, BUNDLE_INFO_VENDOR, bundleInfo.vendor, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, BUNDLE_INFO_IS_KEEP_ALIVE, bundleInfo.isKeepAlive, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, BUNDLE_INFO_IS_NATIVE_APP, bundleInfo.isNativeApp, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, BUNDLE_INFO_IS_PREINSTALL_APP, bundleInfo.isPreInstallApp, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, BUNDLE_INFO_IS_DIFFERENT_NAME, bundleInfo.isDifferentName, false, parseResult);
    GetObjectValueIfFindKey(jsonObject, BUNDLE_INFO_ABILITY_INFOS, bundleInfo.abilityInfos, false, parseResult);
    GetObjectValueIfFindKey(jsonObject, BUNDLE_INFO_HAP_MODULE_INFOS, bundleInfo.hapModuleInfos, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_INFO_VERSION_CODE, bundleInfo.versionCode, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_INFO_MIN_COMPATIBLE_VERSION_CODE, bundleInfo.minCompatibleVersionCode,
        false, parseResult);
    GetStringValueIfFindKey(jsonObject, BUNDLE_INFO_VERSION_NAME, bundleInfo.versionName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, BUNDLE_INFO_JOINT_USERID, bundleInfo.jointUserId, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_INFO_MIN_SDK_VERSION, bundleInfo.minSdkVersion, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_INFO_MAX_SDK_VERSION, bundleInfo.maxSdkVersion, false, parseResult);
    GetStringValueIfFindKey(jsonObject, BUNDLE_INFO_MAIN_ENTRY, bundleInfo.mainEntry, false, parseResult);
    GetStringValueIfFindKey(jsonObject, BUNDLE_INFO_CPU_ABI, bundleInfo.cpuAbi, false, parseResult);
    GetStringValueIfFindKey(jsonObject, BUNDLE_INFO_APPID, bundleInfo.appId, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_INFO_COMPATIBLE_VERSION, bundleInfo.compatibleVersion, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_INFO_TARGET_VERSION, bundleInfo.targetVersion, false, parseResult);
    GetStringValueIfFindKey(jsonObject, BUNDLE_INFO_RELEASE_TYPE, bundleInfo.releaseType, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_INFO_UID, bundleInfo.uid, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_INFO_GID, bundleInfo.gid, false, parseResult);
    GetStringValueIfFindKey(jsonObject, BUNDLE_INFO_SEINFO, bundleInfo.seInfo, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_INFO_INSTALL_TIME, bundleInfo.installTime, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_INFO_UPDATE_TIME, bundleInfo.updateTime, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_INFO_FIRST_INSTALL_TIME, bundleInfo.firstInstallTime, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, BUNDLE_INFO_ENTRY_MODULE_NAME, bundleInfo.entryModuleName, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, BUNDLE_INFO_ENTRY_INSTALLATION_FREE, bundleInfo.entryInstallationFree, false,
        parseResult);
    GetStringValuesIfFindKey(jsonObject, BUNDLE_INFO_REQ_PERMISSIONS, bundleInfo.reqPermissions, false, parseResult);
    GetNumberValuesIfFindKey(jsonObject, BUNDLE_INFO_REQ_PERMISSION_STATES, bundleInfo.reqPermissionStates, false,
        parseResult);
    GetObjectValuesIfFindKey(jsonObject, BUNDLE_INFO_REQ_PERMISSION_DETAILS, bundleInfo.reqPermissionDetails, false,
        parseResult);
    GetStringValuesIfFindKey(jsonObject, BUNDLE_INFO_DEF_PERMISSIONS, bundleInfo.defPermissions, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, BUNDLE_INFO_HAP_MODULE_NAMES, bundleInfo.hapModuleNames, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, BUNDLE_INFO_MODULE_NAMES, bundleInfo.moduleNames, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, BUNDLE_INFO_MODULE_PUBLIC_DIRS, bundleInfo.modulePublicDirs, false,
        parseResult);
    GetStringValuesIfFindKey(jsonObject, BUNDLE_INFO_MODULE_DIRS, bundleInfo.moduleDirs, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, BUNDLE_INFO_MODULE_RES_PATHS, bundleInfo.moduleResPaths, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, BUNDLE_INFO_SINGLETON, bundleInfo.singleton, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, BUNDLE_INFO_EXTENSION_ABILITY_INFOS, bundleInfo.extensionInfos, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_INFO_APP_INDEX, bundleInfo.appIndex, false, parseResult);
    GetObjectValueIfFindKey(jsonObject, BUNDLE_INFO_SIGNATURE_INFO, bundleInfo.signatureInfo, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, OVERLAY_TYPE, bundleInfo.overlayType, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, OVERLAY_BUNDLE_INFO, bundleInfo.overlayBundleInfos, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, BUNDLE_INFO_OLD_APPIDS, bundleInfo.oldAppIds, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, BUNDLE_INFO_ROUTER_ARRAY, bundleInfo.routerArray, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, BUNDLE_INFO_IS_NEW_VERSION, bundleInfo.isNewVersion, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, BUNDLE_INFO_HAS_PLUGIN, bundleInfo.hasPlugin, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "BundleInfo from_json error %{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
