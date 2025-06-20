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

#include "application_info.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <set>
#include <unistd.h>

#include "bundle_constants.h"
#include "hilog_tag_wrapper.h"
#include "json_serializer.h"
#include "json_util.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string APPLICATION_NAME = "name";
const std::string APPLICATION_VERSION_CODE = "versionCode";
const std::string APPLICATION_VERSION_NAME = "versionName";
const std::string APPLICATION_MIN_COMPATIBLE_VERSION_CODE = "minCompatibleVersionCode";
const std::string APPLICATION_API_COMPATIBLE_VERSION = "apiCompatibleVersion";
const std::string APPLICATION_API_TARGET_VERSION = "apiTargetVersion";
const std::string APPLICATION_ICON_PATH = "iconPath";
const std::string APPLICATION_ICON_ID = "iconId";
const std::string APPLICATION_LABEL = "label";
const std::string APPLICATION_LABEL_ID = "labelId";
const std::string APPLICATION_DESCRIPTION = "description";
const std::string APPLICATION_DESCRIPTION_ID = "descriptionId";
const std::string APPLICATION_KEEP_ALIVE = "keepAlive";
const std::string APPLICATION_REMOVABLE = "removable";
const std::string APPLICATION_SINGLETON = "singleton";
const std::string APPLICATION_USER_DATA_CLEARABLE = "userDataClearable";
const std::string ALLOW_APP_RUN_WHEN_DEVICE_FIRST_LOCKED = "allowAppRunWhenDeviceFirstLocked";
const std::string APPLICATION_IS_SYSTEM_APP = "isSystemApp";
const std::string APPLICATION_IS_LAUNCHER_APP = "isLauncherApp";
const std::string APPLICATION_IS_FREEINSTALL_APP = "isFreeInstallApp";
const std::string APPLICATION_RUNNING_RESOURCES_APPLY = "runningResourcesApply";
const std::string APPLICATION_ASSOCIATED_WAKE_UP = "associatedWakeUp";
const std::string APPLICATION_HIDE_DESKTOP_ICON = "hideDesktopIcon";
const std::string APPLICATION_FORM_VISIBLE_NOTIFY = "formVisibleNotify";
const std::string APPLICATION_ALLOW_COMMON_EVENT = "allowCommonEvent";
const std::string APPLICATION_CODE_PATH = "codePath";
const std::string APPLICATION_DATA_DIR = "dataDir";
const std::string APPLICATION_DATA_BASE_DIR = "dataBaseDir";
const std::string APPLICATION_CACHE_DIR = "cacheDir";
const std::string APPLICATION_ENTRY_DIR = "entryDir";
const std::string APPLICATION_API_RELEASETYPE = "apiReleaseType";
const std::string APPLICATION_DEBUG = "debug";
const std::string APPLICATION_DEVICE_ID = "deviceId";
const std::string APPLICATION_DISTRIBUTED_NOTIFICATION_ENABLED = "distributedNotificationEnabled";
const std::string APPLICATION_INSTALLED_FOR_ALL_USER = "installedForAllUser";
const std::string APPLICATION_ENTITY_TYPE = "entityType";
const std::string APPLICATION_PROCESS = "process";
const std::string APPLICATION_SUPPORTED_MODES = "supportedModes";
const std::string APPLICATION_VENDOR = "vendor";
const std::string APPLICATION_ACCESSIBLE = "accessible";
const std::string APPLICATION_PRIVILEGE_LEVEL = "appPrivilegeLevel";
const std::string APPLICATION_ACCESSTOKEN_ID = "accessTokenId";
const std::string APPLICATION_ACCESSTOKEN_ID_EX = "accessTokenIdEx";
const std::string APPLICATION_ENABLED = "enabled";
const std::string APPLICATION_UID = "uid";
const std::string APPLICATION_PERMISSIONS = "permissions";
const std::string APPLICATION_MODULE_SOURCE_DIRS = "moduleSourceDirs";
const std::string APPLICATION_MODULE_INFOS = "moduleInfos";
const std::string APPLICATION_META_DATA_CONFIG_JSON = "metaData";
const std::string APPLICATION_META_DATA_MODULE_JSON = "metadata";
const std::string APPLICATION_FINGERPRINT = "fingerprint";
const std::string APPLICATION_ICON = "icon";
const std::string APPLICATION_FLAGS = "flags";
const std::string APPLICATION_ENTRY_MODULE_NAME = "entryModuleName";
const std::string APPLICATION_NATIVE_LIBRARY_PATH = "nativeLibraryPath";
const std::string APPLICATION_CPU_ABI = "cpuAbi";
const std::string APPLICATION_ARK_NATIVE_FILE_PATH = "arkNativeFilePath";
const std::string APPLICATION_ARK_NATIVE_FILE_ABI = "arkNativeFileAbi";
const std::string APPLICATION_IS_COMPRESS_NATIVE_LIBS = "isCompressNativeLibs";
const std::string APPLICATION_SIGNATURE_KEY = "signatureKey";
const std::string APPLICATION_TARGETBUNDLELIST = "targetBundleList";
const std::string APPLICATION_APP_DISTRIBUTION_TYPE = "appDistributionType";
const std::string APPLICATION_APP_PROVISION_TYPE = "appProvisionType";
const std::string APPLICATION_ICON_RESOURCE = "iconResource";
const std::string APPLICATION_LABEL_RESOURCE = "labelResource";
const std::string APPLICATION_DESCRIPTION_RESOURCE = "descriptionResource";
const std::string APPLICATION_MULTI_PROJECTS = "multiProjects";
const std::string APPLICATION_CROWDTEST_DEADLINE = "crowdtestDeadline";
const std::string APPLICATION_APP_QUICK_FIX = "appQuickFix";
const std::string RESOURCE_ID = "id";
const std::string APPLICATION_NEED_APP_DETAIL = "needAppDetail";
const std::string APPLICATION_APP_DETAIL_ABILITY_LIBRARY_PATH = "appDetailAbilityLibraryPath";
const std::string APPLICATION_APP_TARGET_BUNDLE_NAME = "targetBundleName";
const std::string APPLICATION_APP_TARGET_PRIORITY = "targetPriority";
const std::string APPLICATION_APP_OVERLAY_STATE = "overlayState";
const std::string APPLICATION_ASAN_ENABLED = "asanEnabled";
const std::string APPLICATION_ASAN_LOG_PATH = "asanLogPath";
const std::string APPLICATION_APP_TYPE = "bundleType";
const std::string APPLICATION_COMPILE_SDK_VERSION = "compileSdkVersion";
const std::string APPLICATION_COMPILE_SDK_TYPE = "compileSdkType";
const std::string APPLICATION_RESOURCES_APPLY = "resourcesApply";
const std::string APPLICATION_MAX_CHILD_PROCESS = "maxChildProcess";
const std::string APPLICATION_APP_INDEX = "appIndex";
const std::string APPLICATION_ALLOW_ENABLE_NOTIFICATION = "allowEnableNotification";
const std::string APPLICATION_GWP_ASAN_ENABLED = "GWPAsanEnabled";
const std::string APPLICATION_APPLICATION_FLAGS = "applicationFlags";
const std::string APPLICATION_ALLOW_MULTI_PROCESS = "allowMultiProcess";
const std::string APPLICATION_ASSET_ACCESS_GROUPS = "assetAccessGroups";
const std::string APPLICATION_HAS_PLUGIN = "hasPlugin";
const std::string APPLICATION_ORGANIZATION = "organization";
const std::string APPLICATION_INSTALL_SOURCE = "installSource";
const std::string APPLICATION_HWASAN_ENABLED = "hwasanEnabled";
const std::string APPLICATION_CONFIGURATION = "configuration";
const std::string APPLICATION_CLOUD_FILE_SYNC_ENABLED = "cloudFileSyncEnabled";
const std::string APPLICATION_UBSAN_ENABLED = "ubsanEnabled";
const std::string APPLICATION_HNP_PACKAGES = "hnpPackages";
const std::string APPLICATION_HNP_PACKAGES_PACKAGE = "package";
const std::string APPLICATION_HNP_PACKAGES_TYPE = "type";
const std::string APPLICATION_TSAN_ENABLED = "tsanEnabled";
const std::string APPLICATION_APP_ENVIRONMENTS = "appEnvironments";
const std::string APPLICATION_RESERVED_FLAG = "applicationReservedFlag";
const std::string APPLICATION_MULTI_APP_MODE = "multiAppMode";
const std::string APPLICATION_MULTI_APP_MODE_TYPE = "multiAppModeType";
const std::string APPLICATION_MULTI_APP_MODE_MAX_ADDITIONAL_NUMBER = "maxCount";
const std::string APP_ENVIRONMENTS_NAME = "name";
const std::string APP_ENVIRONMENTS_VALUE = "value";
const std::string APP_QUICK_FIX_VERSION_CODE = "versionCode";
const std::string APP_QUICK_FIX_VERSION_NAME = "versionName";
const std::string APP_QUICK_FIX_DEPLOYED_APP_QF_INFO = "deployedAppqfInfo";
const std::string APP_QUICK_FIX_DEPLOYING_APP_QF_INFO = "deployingAppqfInfo";
const std::string APP_QF_INFO_VERSION_CODE = "versionCode";
const std::string APP_QF_INFO_VERSION_NAME = "versionName";
const std::string APP_QF_INFO_CPU_ABI = "cpuAbi";
const std::string APP_QF_INFO_NATIVE_LIBRARY_PATH = "nativeLibraryPath";
const std::string APP_QF_INFO_HQF_INFOS = "hqfInfos";
const std::string APP_QF_INFO_TYPE = "type";
const std::string HQF_INFO_HAP_SHA256 = "hapSha256";
const std::string HQF_INFO_HQF_FILE_PATH = "hqfFilePath";
const std::string HQF_INFO_TYPE = "type";
const std::string HQF_INFO_CPU_ABI = "cpuAbi";
const std::string HQF_INFO_NATIVE_LIBRARY_PATH = "nativeLibraryPath";
}

bool to_json(cJSON *&jsonObject, const Resource &resource)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, Constants::BUNDLE_NAME, resource.bundleName.c_str());
    cJSON_AddStringToObject(jsonObject, Constants::MODULE_NAME, resource.moduleName.c_str());
    cJSON_AddNumberToObject(jsonObject, RESOURCE_ID.c_str(), static_cast<double>(resource.id));
    return true;
}

void from_json(const cJSON *jsonObject, Resource &resource)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, Constants::BUNDLE_NAME, resource.bundleName, true, parseResult);
    GetStringValueIfFindKey(jsonObject, Constants::MODULE_NAME, resource.moduleName, true, parseResult);
    GetNumberValueIfFindKey(jsonObject, RESOURCE_ID, resource.id, true, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "read Resource from database error,:%{public}d", parseResult);
    }
}

bool to_json(cJSON *&jsonObject, const HnpPackage &hnpPackage)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, APPLICATION_HNP_PACKAGES_PACKAGE.c_str(), hnpPackage.package.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_HNP_PACKAGES_TYPE.c_str(), hnpPackage.type.c_str());
    return true;
}

void from_json(const cJSON *jsonObject, HnpPackage &hnpPackage)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, APPLICATION_HNP_PACKAGES_PACKAGE, hnpPackage.package, true, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_HNP_PACKAGES_TYPE, hnpPackage.type, true, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "read Resource error %{public}d", parseResult);
    }
}

bool to_json(cJSON *&jsonObject, const MultiAppModeData &multiAppMode)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddNumberToObject(jsonObject, APPLICATION_MULTI_APP_MODE_TYPE.c_str(),
        static_cast<double>(multiAppMode.multiAppModeType));
    cJSON_AddNumberToObject(jsonObject, APPLICATION_MULTI_APP_MODE_MAX_ADDITIONAL_NUMBER.c_str(),
        static_cast<double>(multiAppMode.maxCount));
    return true;
}

void from_json(const cJSON *jsonObject, MultiAppModeData &multiAppMode)
{
    int32_t parseResult = ERR_OK;
    GetNumberValueIfFindKey(jsonObject, APPLICATION_MULTI_APP_MODE_TYPE, multiAppMode.multiAppModeType, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_MULTI_APP_MODE_MAX_ADDITIONAL_NUMBER, multiAppMode.maxCount, false,
        parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "from_json error : %{public}d", parseResult);
    }
}

bool to_json(cJSON *&jsonObject, const ApplicationEnvironment &applicationEnvironment)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, APP_ENVIRONMENTS_NAME.c_str(), applicationEnvironment.name.c_str());
    cJSON_AddStringToObject(jsonObject, APP_ENVIRONMENTS_VALUE.c_str(), applicationEnvironment.value.c_str());
    return true;
}

void from_json(const cJSON *jsonObject, ApplicationEnvironment &applicationEnvironment)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, APP_ENVIRONMENTS_NAME, applicationEnvironment.name, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APP_ENVIRONMENTS_VALUE, applicationEnvironment.value, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "read database error : %{public}d", parseResult);
    }
}

bool to_json(cJSON *&jsonObject, const HqfInfo &hqfInfo)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, Constants::MODULE_NAME, hqfInfo.moduleName.c_str());
    cJSON_AddStringToObject(jsonObject, HQF_INFO_HAP_SHA256.c_str(), hqfInfo.hapSha256.c_str());
    cJSON_AddStringToObject(jsonObject, HQF_INFO_HQF_FILE_PATH.c_str(), hqfInfo.hqfFilePath.c_str());
    cJSON_AddNumberToObject(jsonObject, HQF_INFO_TYPE.c_str(), static_cast<double>(hqfInfo.type));
    cJSON_AddStringToObject(jsonObject, HQF_INFO_CPU_ABI.c_str(), hqfInfo.cpuAbi.c_str());
    cJSON_AddStringToObject(jsonObject, HQF_INFO_NATIVE_LIBRARY_PATH.c_str(), hqfInfo.nativeLibraryPath.c_str());
    return true;
}

void from_json(const cJSON *jsonObject, HqfInfo &hqfInfo)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, Constants::MODULE_NAME, hqfInfo.moduleName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HQF_INFO_HAP_SHA256, hqfInfo.hapSha256, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HQF_INFO_HQF_FILE_PATH, hqfInfo.hqfFilePath, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, HQF_INFO_TYPE, hqfInfo.type, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HQF_INFO_CPU_ABI, hqfInfo.cpuAbi, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HQF_INFO_NATIVE_LIBRARY_PATH, hqfInfo.nativeLibraryPath, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "read module hqfInfo from jsonObject error, error code : %{public}d",
            parseResult);
    }
}

bool to_json(cJSON *&jsonObject, const AppqfInfo &appqfInfo)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddNumberToObject(jsonObject, APP_QF_INFO_VERSION_CODE.c_str(), static_cast<double>(appqfInfo.versionCode));
    cJSON_AddStringToObject(jsonObject, APP_QF_INFO_VERSION_NAME.c_str(), appqfInfo.versionName.c_str());
    cJSON_AddStringToObject(jsonObject, APP_QF_INFO_CPU_ABI.c_str(), appqfInfo.cpuAbi.c_str());
    cJSON_AddStringToObject(jsonObject, APP_QF_INFO_NATIVE_LIBRARY_PATH.c_str(), appqfInfo.nativeLibraryPath.c_str());
    cJSON_AddNumberToObject(jsonObject, APP_QF_INFO_TYPE.c_str(), static_cast<double>(appqfInfo.type));
    cJSON *hqfInfosItem = nullptr;
    if (!to_json(hqfInfosItem, appqfInfo.hqfInfos)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json hqfInfos failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APP_QF_INFO_HQF_INFOS.c_str(), hqfInfosItem);
    return true;
}

void from_json(const cJSON *jsonObject, AppqfInfo &appqfInfo)
{
    int32_t parseResult = ERR_OK;
    GetNumberValueIfFindKey(jsonObject, APP_QF_INFO_VERSION_CODE, appqfInfo.versionCode, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APP_QF_INFO_VERSION_NAME, appqfInfo.versionName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APP_QF_INFO_CPU_ABI, appqfInfo.cpuAbi, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APP_QF_INFO_NATIVE_LIBRARY_PATH, appqfInfo.nativeLibraryPath, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, APP_QF_INFO_TYPE, appqfInfo.type, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, APP_QF_INFO_HQF_INFOS, appqfInfo.hqfInfos, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "read module appqfInfo from jsonObject error, error code : %{public}d",
            parseResult);
    }
}

bool to_json(cJSON *&jsonObject, const AppQuickFix &appQuickFix)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, Constants::BUNDLE_NAME, appQuickFix.bundleName.c_str());
    cJSON_AddNumberToObject(jsonObject, APP_QUICK_FIX_VERSION_CODE.c_str(),
        static_cast<double>(appQuickFix.versionCode));
    cJSON_AddStringToObject(jsonObject, APP_QUICK_FIX_VERSION_NAME.c_str(), appQuickFix.versionName.c_str());

    cJSON *deployedAppqfInfoItem = nullptr;
    if (!to_json(deployedAppqfInfoItem, appQuickFix.deployedAppqfInfo)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json deployedAppqfInfo failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APP_QUICK_FIX_DEPLOYED_APP_QF_INFO.c_str(), deployedAppqfInfoItem);

    cJSON *deployingAppqfInfoItem = nullptr;
    if (!to_json(deployingAppqfInfoItem, appQuickFix.deployingAppqfInfo)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json deployingAppqfInfo failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APP_QUICK_FIX_DEPLOYING_APP_QF_INFO.c_str(), deployingAppqfInfoItem);
    return true;
}

void from_json(const cJSON *jsonObject, AppQuickFix &appQuickFix)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, Constants::BUNDLE_NAME, appQuickFix.bundleName, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APP_QUICK_FIX_VERSION_CODE, appQuickFix.versionCode, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APP_QUICK_FIX_VERSION_NAME, appQuickFix.versionName, false, parseResult);
    GetObjectValueIfFindKey(jsonObject, APP_QUICK_FIX_DEPLOYED_APP_QF_INFO, appQuickFix.deployedAppqfInfo, false,
        parseResult);
    GetObjectValueIfFindKey(jsonObject, APP_QUICK_FIX_DEPLOYING_APP_QF_INFO, appQuickFix.deployingAppqfInfo, false,
        parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "read module appQuickFix from jsonObject error, error code : %{public}d",
            parseResult);
    }
}

bool to_json(cJSON *&jsonObject, const ApplicationInfo &applicationInfo)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, APPLICATION_NAME.c_str(), applicationInfo.name.c_str());
    cJSON_AddStringToObject(jsonObject, Constants::BUNDLE_NAME, applicationInfo.bundleName.c_str());
    cJSON_AddNumberToObject(jsonObject, APPLICATION_VERSION_CODE.c_str(),
        static_cast<double>(applicationInfo.versionCode));
    cJSON_AddStringToObject(jsonObject, APPLICATION_VERSION_NAME.c_str(), applicationInfo.versionName.c_str());
    cJSON_AddNumberToObject(jsonObject, APPLICATION_MIN_COMPATIBLE_VERSION_CODE.c_str(),
        static_cast<double>(applicationInfo.minCompatibleVersionCode));
    cJSON_AddNumberToObject(jsonObject, APPLICATION_API_COMPATIBLE_VERSION.c_str(),
        static_cast<double>(applicationInfo.apiCompatibleVersion));
    cJSON_AddNumberToObject(jsonObject, APPLICATION_API_TARGET_VERSION.c_str(),
        static_cast<double>(applicationInfo.apiTargetVersion));
    cJSON_AddStringToObject(jsonObject, APPLICATION_ICON_PATH.c_str(), applicationInfo.iconPath.c_str());
    cJSON_AddNumberToObject(jsonObject, APPLICATION_ICON_ID.c_str(), static_cast<double>(applicationInfo.iconId));
    cJSON_AddStringToObject(jsonObject, APPLICATION_LABEL.c_str(), applicationInfo.label.c_str());
    cJSON_AddNumberToObject(jsonObject, APPLICATION_LABEL_ID.c_str(), static_cast<double>(applicationInfo.labelId));
    cJSON_AddStringToObject(jsonObject, APPLICATION_DESCRIPTION.c_str(), applicationInfo.description.c_str());
    cJSON_AddNumberToObject(jsonObject, APPLICATION_DESCRIPTION_ID.c_str(),
        static_cast<double>(applicationInfo.descriptionId));
    cJSON_AddBoolToObject(jsonObject, APPLICATION_KEEP_ALIVE.c_str(), applicationInfo.keepAlive);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_REMOVABLE.c_str(), applicationInfo.removable);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_SINGLETON.c_str(), applicationInfo.singleton);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_USER_DATA_CLEARABLE.c_str(), applicationInfo.userDataClearable);
    cJSON_AddBoolToObject(jsonObject, ALLOW_APP_RUN_WHEN_DEVICE_FIRST_LOCKED.c_str(),
        applicationInfo.allowAppRunWhenDeviceFirstLocked);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_ACCESSIBLE.c_str(), applicationInfo.accessible);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_IS_SYSTEM_APP.c_str(), applicationInfo.isSystemApp);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_IS_LAUNCHER_APP.c_str(), applicationInfo.isLauncherApp);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_IS_FREEINSTALL_APP.c_str(), applicationInfo.isFreeInstallApp);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_RUNNING_RESOURCES_APPLY.c_str(),
        applicationInfo.runningResourcesApply);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_ASSOCIATED_WAKE_UP.c_str(), applicationInfo.associatedWakeUp);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_HIDE_DESKTOP_ICON.c_str(), applicationInfo.hideDesktopIcon);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_FORM_VISIBLE_NOTIFY.c_str(), applicationInfo.formVisibleNotify);

    cJSON *allowCommonEventItem = nullptr;
    if (!to_json(allowCommonEventItem, applicationInfo.allowCommonEvent)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json allowCommonEvent failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APPLICATION_ALLOW_COMMON_EVENT.c_str(), allowCommonEventItem);

    cJSON_AddStringToObject(jsonObject, APPLICATION_CODE_PATH.c_str(), applicationInfo.codePath.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_DATA_DIR.c_str(), applicationInfo.dataDir.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_DATA_BASE_DIR.c_str(), applicationInfo.dataBaseDir.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_CACHE_DIR.c_str(), applicationInfo.cacheDir.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_ENTRY_DIR.c_str(), applicationInfo.entryDir.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_API_RELEASETYPE.c_str(), applicationInfo.apiReleaseType.c_str());
    cJSON_AddBoolToObject(jsonObject, APPLICATION_DEBUG.c_str(), applicationInfo.debug);
    cJSON_AddStringToObject(jsonObject, APPLICATION_DEVICE_ID.c_str(), applicationInfo.deviceId.c_str());
    cJSON_AddBoolToObject(jsonObject, APPLICATION_DISTRIBUTED_NOTIFICATION_ENABLED.c_str(),
        applicationInfo.distributedNotificationEnabled);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_INSTALLED_FOR_ALL_USER.c_str(), applicationInfo.installedForAllUser);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_ALLOW_ENABLE_NOTIFICATION.c_str(),
        applicationInfo.allowEnableNotification);
    cJSON_AddStringToObject(jsonObject, APPLICATION_ENTITY_TYPE.c_str(), applicationInfo.entityType.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_PROCESS.c_str(), applicationInfo.process.c_str());
    cJSON_AddNumberToObject(jsonObject, APPLICATION_SUPPORTED_MODES.c_str(),
        static_cast<double>(applicationInfo.supportedModes));
    cJSON_AddStringToObject(jsonObject, APPLICATION_VENDOR.c_str(), applicationInfo.vendor.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_PRIVILEGE_LEVEL.c_str(), applicationInfo.appPrivilegeLevel.c_str());
    cJSON_AddNumberToObject(jsonObject, APPLICATION_ACCESSTOKEN_ID.c_str(),
        static_cast<double>(applicationInfo.accessTokenId));
    cJSON_AddNumberToObject(jsonObject, APPLICATION_ACCESSTOKEN_ID_EX.c_str(),
        static_cast<double>(applicationInfo.accessTokenIdEx));
    cJSON_AddBoolToObject(jsonObject, APPLICATION_ENABLED.c_str(), applicationInfo.enabled);
    cJSON_AddNumberToObject(jsonObject, APPLICATION_UID.c_str(), static_cast<double>(applicationInfo.uid));

    cJSON *permissionsItem = nullptr;
    if (!to_json(permissionsItem, applicationInfo.permissions)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json permissions failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APPLICATION_PERMISSIONS.c_str(), permissionsItem);

    cJSON *moduleSourceDirsItem = nullptr;
    if (!to_json(moduleSourceDirsItem, applicationInfo.moduleSourceDirs)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json moduleSourceDirs failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APPLICATION_MODULE_SOURCE_DIRS.c_str(), moduleSourceDirsItem);

    cJSON *moduleInfosItem = nullptr;
    if (!to_json(moduleInfosItem, applicationInfo.moduleInfos)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json moduleInfos failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APPLICATION_MODULE_INFOS.c_str(), moduleInfosItem);

    cJSON *metaDataItem = nullptr;
    if (!to_json(metaDataItem, applicationInfo.metaData)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json metaData failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APPLICATION_META_DATA_CONFIG_JSON.c_str(), metaDataItem);

    cJSON *metadataItem = nullptr;
    if (!to_json(metadataItem, applicationInfo.metadata)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json metadata failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APPLICATION_META_DATA_MODULE_JSON.c_str(), metadataItem);

    cJSON_AddStringToObject(jsonObject, APPLICATION_FINGERPRINT.c_str(), applicationInfo.fingerprint.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_ICON.c_str(), applicationInfo.icon.c_str());
    cJSON_AddNumberToObject(jsonObject, APPLICATION_FLAGS.c_str(), static_cast<double>(applicationInfo.flags));
    cJSON_AddStringToObject(jsonObject, APPLICATION_ENTRY_MODULE_NAME.c_str(), applicationInfo.entryModuleName.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_NATIVE_LIBRARY_PATH.c_str(),
        applicationInfo.nativeLibraryPath.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_CPU_ABI.c_str(), applicationInfo.cpuAbi.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_ARK_NATIVE_FILE_PATH.c_str(),
        applicationInfo.arkNativeFilePath.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_ARK_NATIVE_FILE_ABI.c_str(),
        applicationInfo.arkNativeFileAbi.c_str());
    cJSON_AddBoolToObject(jsonObject, APPLICATION_IS_COMPRESS_NATIVE_LIBS.c_str(),
        applicationInfo.isCompressNativeLibs);
    cJSON_AddStringToObject(jsonObject, APPLICATION_SIGNATURE_KEY.c_str(), applicationInfo.signatureKey.c_str());

    cJSON *targetBundleListItem = nullptr;
    if (!to_json(targetBundleListItem, applicationInfo.targetBundleList)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json targetBundleList failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APPLICATION_TARGETBUNDLELIST.c_str(), targetBundleListItem);

    cJSON_AddStringToObject(jsonObject, APPLICATION_APP_DISTRIBUTION_TYPE.c_str(),
        applicationInfo.appDistributionType.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_APP_PROVISION_TYPE.c_str(),
        applicationInfo.appProvisionType.c_str());

    cJSON *iconResourceItem = nullptr;
    if (!to_json(iconResourceItem, applicationInfo.iconResource)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json iconResource failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APPLICATION_ICON_RESOURCE.c_str(), iconResourceItem);

    cJSON *labelResourceItem = nullptr;
    if (!to_json(labelResourceItem, applicationInfo.labelResource)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json labelResource failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APPLICATION_LABEL_RESOURCE.c_str(), labelResourceItem);

    cJSON *descriptionResourceItem = nullptr;
    if (!to_json(descriptionResourceItem, applicationInfo.descriptionResource)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json descriptionResource failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APPLICATION_DESCRIPTION_RESOURCE.c_str(), descriptionResourceItem);

    cJSON_AddBoolToObject(jsonObject, APPLICATION_MULTI_PROJECTS.c_str(), applicationInfo.multiProjects);
    cJSON_AddNumberToObject(jsonObject, APPLICATION_CROWDTEST_DEADLINE.c_str(),
        static_cast<double>(applicationInfo.crowdtestDeadline));
    cJSON_AddNumberToObject(jsonObject, APPLICATION_NEED_APP_DETAIL.c_str(),
        static_cast<double>(applicationInfo.needAppDetail));
    cJSON_AddStringToObject(jsonObject, APPLICATION_APP_DETAIL_ABILITY_LIBRARY_PATH.c_str(),
        applicationInfo.appDetailAbilityLibraryPath.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_APP_TARGET_BUNDLE_NAME.c_str(),
        applicationInfo.targetBundleName.c_str());
    cJSON_AddNumberToObject(jsonObject, APPLICATION_APP_TARGET_PRIORITY.c_str(),
        static_cast<double>(applicationInfo.targetPriority));
    cJSON_AddNumberToObject(jsonObject, APPLICATION_APP_OVERLAY_STATE.c_str(),
        static_cast<double>(applicationInfo.overlayState));
    cJSON_AddBoolToObject(jsonObject, APPLICATION_ASAN_ENABLED.c_str(), applicationInfo.asanEnabled);
    cJSON_AddStringToObject(jsonObject, APPLICATION_ASAN_LOG_PATH.c_str(), applicationInfo.asanLogPath.c_str());
    cJSON_AddNumberToObject(jsonObject, APPLICATION_APP_TYPE.c_str(), static_cast<double>(applicationInfo.bundleType));
    cJSON_AddStringToObject(jsonObject, APPLICATION_COMPILE_SDK_VERSION.c_str(),
        applicationInfo.compileSdkVersion.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_COMPILE_SDK_TYPE.c_str(), applicationInfo.compileSdkType.c_str());

    cJSON *resourcesApplyItem = nullptr;
    if (!to_json(resourcesApplyItem, applicationInfo.resourcesApply)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json resourcesApply failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APPLICATION_RESOURCES_APPLY.c_str(), resourcesApplyItem);

    cJSON_AddBoolToObject(jsonObject, APPLICATION_GWP_ASAN_ENABLED.c_str(), applicationInfo.gwpAsanEnabled);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_HWASAN_ENABLED.c_str(), applicationInfo.hwasanEnabled);
    cJSON_AddNumberToObject(jsonObject, APPLICATION_RESERVED_FLAG.c_str(),
        static_cast<double>(applicationInfo.applicationReservedFlag));
    cJSON_AddBoolToObject(jsonObject, APPLICATION_TSAN_ENABLED.c_str(), applicationInfo.tsanEnabled);

    cJSON *appEnvironmentsItem = nullptr;
    if (!to_json(appEnvironmentsItem, applicationInfo.appEnvironments)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json appEnvironments failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APPLICATION_APP_ENVIRONMENTS.c_str(), appEnvironmentsItem);
    
    cJSON_AddStringToObject(jsonObject, APPLICATION_ORGANIZATION.c_str(), applicationInfo.organization.c_str());

    cJSON *multiAppModeItem = nullptr;
    if (!to_json(multiAppModeItem, applicationInfo.multiAppMode)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json multiAppMode failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APPLICATION_MULTI_APP_MODE.c_str(), multiAppModeItem);

    cJSON_AddNumberToObject(jsonObject, APPLICATION_MAX_CHILD_PROCESS.c_str(),
        static_cast<double>(applicationInfo.maxChildProcess));
    cJSON_AddNumberToObject(jsonObject, APPLICATION_APP_INDEX.c_str(), static_cast<double>(applicationInfo.appIndex));
    cJSON_AddStringToObject(jsonObject, APPLICATION_INSTALL_SOURCE.c_str(), applicationInfo.installSource.c_str());
    cJSON_AddStringToObject(jsonObject, APPLICATION_CONFIGURATION.c_str(), applicationInfo.configuration.c_str());
    cJSON_AddBoolToObject(jsonObject, APPLICATION_CLOUD_FILE_SYNC_ENABLED.c_str(),
        applicationInfo.cloudFileSyncEnabled);
    cJSON_AddNumberToObject(jsonObject, APPLICATION_APPLICATION_FLAGS.c_str(),
        static_cast<double>(applicationInfo.applicationFlags));
    cJSON_AddBoolToObject(jsonObject, APPLICATION_UBSAN_ENABLED.c_str(), applicationInfo.ubsanEnabled);
    cJSON_AddBoolToObject(jsonObject, APPLICATION_ALLOW_MULTI_PROCESS.c_str(), applicationInfo.allowMultiProcess);

    cJSON *assetAccessGroupsItem = nullptr;
    if (!to_json(assetAccessGroupsItem, applicationInfo.assetAccessGroups)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json assetAccessGroups failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, APPLICATION_ASSET_ACCESS_GROUPS.c_str(), assetAccessGroupsItem);

    cJSON_AddBoolToObject(jsonObject, APPLICATION_HAS_PLUGIN.c_str(), applicationInfo.hasPlugin);

    return true;
}

void from_json(const cJSON *jsonObject, ApplicationInfo &applicationInfo)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, APPLICATION_NAME, applicationInfo.name, false, parseResult);
    GetStringValueIfFindKey(jsonObject, Constants::BUNDLE_NAME, applicationInfo.bundleName, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_VERSION_CODE, applicationInfo.versionCode, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_VERSION_NAME, applicationInfo.versionName, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_MIN_COMPATIBLE_VERSION_CODE,
        applicationInfo.minCompatibleVersionCode, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_API_COMPATIBLE_VERSION,
        applicationInfo.apiCompatibleVersion, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_API_TARGET_VERSION,
        applicationInfo.apiTargetVersion, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_ICON_PATH, applicationInfo.iconPath, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_ICON_ID, applicationInfo.iconId, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_LABEL, applicationInfo.label, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_LABEL_ID, applicationInfo.labelId, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_DESCRIPTION, applicationInfo.description, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_DESCRIPTION_ID, applicationInfo.descriptionId, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_KEEP_ALIVE, applicationInfo.keepAlive, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_REMOVABLE, applicationInfo.removable, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_SINGLETON, applicationInfo.singleton, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_USER_DATA_CLEARABLE,
        applicationInfo.userDataClearable, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, ALLOW_APP_RUN_WHEN_DEVICE_FIRST_LOCKED,
        applicationInfo.allowAppRunWhenDeviceFirstLocked, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_ACCESSIBLE, applicationInfo.accessible, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_IS_SYSTEM_APP, applicationInfo.isSystemApp, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_IS_LAUNCHER_APP, applicationInfo.isLauncherApp, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_IS_FREEINSTALL_APP,
        applicationInfo.isFreeInstallApp, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_RUNNING_RESOURCES_APPLY,
        applicationInfo.runningResourcesApply, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_ASSOCIATED_WAKE_UP,
        applicationInfo.associatedWakeUp, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_HIDE_DESKTOP_ICON,
        applicationInfo.hideDesktopIcon, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_FORM_VISIBLE_NOTIFY,
        applicationInfo.formVisibleNotify, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, APPLICATION_ALLOW_COMMON_EVENT,
        applicationInfo.allowCommonEvent, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_CODE_PATH, applicationInfo.codePath, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_DATA_DIR, applicationInfo.dataDir, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_DATA_BASE_DIR, applicationInfo.dataBaseDir, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_CACHE_DIR, applicationInfo.cacheDir, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_ENTRY_DIR, applicationInfo.entryDir, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_API_RELEASETYPE, applicationInfo.apiReleaseType, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_DEBUG, applicationInfo.debug, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_DEVICE_ID, applicationInfo.deviceId, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_DISTRIBUTED_NOTIFICATION_ENABLED,
        applicationInfo.distributedNotificationEnabled, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_INSTALLED_FOR_ALL_USER, applicationInfo.installedForAllUser, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_ALLOW_ENABLE_NOTIFICATION, applicationInfo.allowEnableNotification,
        false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_ENTITY_TYPE, applicationInfo.entityType, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_PROCESS, applicationInfo.process, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_SUPPORTED_MODES, applicationInfo.supportedModes, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_VENDOR, applicationInfo.vendor, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_PRIVILEGE_LEVEL, applicationInfo.appPrivilegeLevel, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_ACCESSTOKEN_ID, applicationInfo.accessTokenId, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_ACCESSTOKEN_ID_EX, applicationInfo.accessTokenIdEx, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_ENABLED, applicationInfo.enabled, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_UID, applicationInfo.uid, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, APPLICATION_PERMISSIONS, applicationInfo.permissions, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, APPLICATION_MODULE_SOURCE_DIRS, applicationInfo.moduleSourceDirs, false,
        parseResult);
    GetObjectValuesIfFindKey(jsonObject, APPLICATION_MODULE_INFOS, applicationInfo.moduleInfos, false, parseResult);
    GetObjectValuesMapIfFindKey(jsonObject, APPLICATION_META_DATA_CONFIG_JSON, applicationInfo.metaData, false,
        parseResult);
    GetObjectValuesMapIfFindKey(jsonObject, APPLICATION_META_DATA_MODULE_JSON, applicationInfo.metadata, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_FINGERPRINT, applicationInfo.fingerprint, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_ICON, applicationInfo.icon, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_FLAGS, applicationInfo.flags, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_ENTRY_MODULE_NAME, applicationInfo.entryModuleName, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_NATIVE_LIBRARY_PATH, applicationInfo.nativeLibraryPath, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_CPU_ABI, applicationInfo.cpuAbi, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_ARK_NATIVE_FILE_PATH, applicationInfo.arkNativeFilePath, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_ARK_NATIVE_FILE_ABI, applicationInfo.arkNativeFileAbi, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_IS_COMPRESS_NATIVE_LIBS, applicationInfo.isCompressNativeLibs, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_SIGNATURE_KEY, applicationInfo.signatureKey, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, APPLICATION_TARGETBUNDLELIST, applicationInfo.targetBundleList, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_APP_DISTRIBUTION_TYPE, applicationInfo.appDistributionType, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_APP_PROVISION_TYPE, applicationInfo.appProvisionType, false,
        parseResult);
    GetObjectValueIfFindKey(jsonObject, APPLICATION_ICON_RESOURCE, applicationInfo.iconResource, false, parseResult);
    GetObjectValueIfFindKey(jsonObject, APPLICATION_LABEL_RESOURCE, applicationInfo.labelResource, false, parseResult);
    GetObjectValueIfFindKey(jsonObject, APPLICATION_DESCRIPTION_RESOURCE, applicationInfo.descriptionResource, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_MULTI_PROJECTS, applicationInfo.multiProjects, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_CROWDTEST_DEADLINE, applicationInfo.crowdtestDeadline, false,
        parseResult);
    GetObjectValueIfFindKey(jsonObject, APPLICATION_APP_QUICK_FIX, applicationInfo.appQuickFix, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_NEED_APP_DETAIL, applicationInfo.needAppDetail, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_APP_DETAIL_ABILITY_LIBRARY_PATH,
        applicationInfo.appDetailAbilityLibraryPath, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_APP_TARGET_BUNDLE_NAME, applicationInfo.targetBundleName, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_APP_TARGET_PRIORITY, applicationInfo.targetPriority, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_APP_OVERLAY_STATE, applicationInfo.overlayState, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_ASAN_ENABLED, applicationInfo.asanEnabled, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_ASAN_LOG_PATH, applicationInfo.asanLogPath, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_APP_TYPE, applicationInfo.bundleType, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_COMPILE_SDK_VERSION, applicationInfo.compileSdkVersion, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_COMPILE_SDK_TYPE, applicationInfo.compileSdkType, false,
        parseResult);
    GetNumberValuesIfFindKey(jsonObject, APPLICATION_RESOURCES_APPLY, applicationInfo.resourcesApply, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_GWP_ASAN_ENABLED, applicationInfo.gwpAsanEnabled, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_RESERVED_FLAG, applicationInfo.applicationReservedFlag, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_TSAN_ENABLED, applicationInfo.tsanEnabled, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_ORGANIZATION, applicationInfo.organization, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, APPLICATION_APP_ENVIRONMENTS, applicationInfo.appEnvironments, false,
        parseResult);
    GetObjectValueIfFindKey(jsonObject, APPLICATION_MULTI_APP_MODE, applicationInfo.multiAppMode, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_APP_INDEX, applicationInfo.appIndex, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_MAX_CHILD_PROCESS, applicationInfo.maxChildProcess, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_INSTALL_SOURCE, applicationInfo.installSource, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_HWASAN_ENABLED, applicationInfo.hwasanEnabled, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APPLICATION_CONFIGURATION, applicationInfo.configuration, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_CLOUD_FILE_SYNC_ENABLED, applicationInfo.cloudFileSyncEnabled, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, APPLICATION_APPLICATION_FLAGS, applicationInfo.applicationFlags, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_UBSAN_ENABLED, applicationInfo.ubsanEnabled, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_ALLOW_MULTI_PROCESS, applicationInfo.allowMultiProcess, false,
        parseResult);
    GetStringValuesIfFindKey(jsonObject, APPLICATION_ASSET_ACCESS_GROUPS, applicationInfo.assetAccessGroups, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, APPLICATION_HAS_PLUGIN, applicationInfo.hasPlugin, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "from_json error:%{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
