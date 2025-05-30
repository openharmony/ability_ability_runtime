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
#include "nlohmann/json.hpp"
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
void to_json(nlohmann::json &jsonObject, const Resource &resource)
{
    jsonObject = nlohmann::json {
        {Constants::BUNDLE_NAME, resource.bundleName},
        {Constants::MODULE_NAME, resource.moduleName},
        {RESOURCE_ID, resource.id}
    };
}

void from_json(const nlohmann::json &jsonObject, Resource &resource)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        resource.bundleName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        resource.moduleName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        RESOURCE_ID,
        resource.id,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "read Resource from database error,:%{public}d", parseResult);
    }
}


void to_json(nlohmann::json &jsonObject, const HnpPackage &hnpPackage)
{
    jsonObject = nlohmann::json {
        {APPLICATION_HNP_PACKAGES_PACKAGE, hnpPackage.package},
        {APPLICATION_HNP_PACKAGES_TYPE, hnpPackage.type},
    };
}

void from_json(const nlohmann::json &jsonObject, HnpPackage &hnpPackage)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_HNP_PACKAGES_PACKAGE,
        hnpPackage.package,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_HNP_PACKAGES_TYPE,
        hnpPackage.type,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "read Resource error %{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const MultiAppModeData &multiAppMode)
{
    jsonObject = nlohmann::json {
        {APPLICATION_MULTI_APP_MODE_TYPE, multiAppMode.multiAppModeType},
        {APPLICATION_MULTI_APP_MODE_MAX_ADDITIONAL_NUMBER, multiAppMode.maxCount},
    };
}

void from_json(const nlohmann::json &jsonObject, MultiAppModeData &multiAppMode)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<MultiAppModeType>(jsonObject, jsonObjectEnd, APPLICATION_MULTI_APP_MODE_TYPE,
        multiAppMode.multiAppModeType, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject, jsonObjectEnd, APPLICATION_MULTI_APP_MODE_MAX_ADDITIONAL_NUMBER,
        multiAppMode.maxCount, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "from_json error : %{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const ApplicationEnvironment &applicationEnvironment)
{
    jsonObject = nlohmann::json {
        {APP_ENVIRONMENTS_NAME, applicationEnvironment.name},
        {APP_ENVIRONMENTS_VALUE, applicationEnvironment.value}
    };
}

void from_json(const nlohmann::json &jsonObject, ApplicationEnvironment &applicationEnvironment)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_ENVIRONMENTS_NAME,
        applicationEnvironment.name,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_ENVIRONMENTS_VALUE,
        applicationEnvironment.value,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "read database error : %{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const HqfInfo &hqfInfo)
{
    jsonObject = nlohmann::json {
        {Constants::MODULE_NAME, hqfInfo.moduleName},
        {HQF_INFO_HAP_SHA256, hqfInfo.hapSha256},
        {HQF_INFO_HQF_FILE_PATH, hqfInfo.hqfFilePath},
        {HQF_INFO_TYPE, hqfInfo.type},
        {HQF_INFO_CPU_ABI, hqfInfo.cpuAbi},
        {HQF_INFO_NATIVE_LIBRARY_PATH, hqfInfo.nativeLibraryPath}
    };
}

void from_json(const nlohmann::json &jsonObject, HqfInfo &hqfInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        hqfInfo.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HQF_INFO_HAP_SHA256,
        hqfInfo.hapSha256,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HQF_INFO_HQF_FILE_PATH,
        hqfInfo.hqfFilePath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<QuickFixType>(jsonObject,
        jsonObjectEnd,
        HQF_INFO_TYPE,
        hqfInfo.type,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HQF_INFO_CPU_ABI,
        hqfInfo.cpuAbi,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HQF_INFO_NATIVE_LIBRARY_PATH,
        hqfInfo.nativeLibraryPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "read module hqfInfo from jsonObject error, error code : %{public}d",
            parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const AppqfInfo &appqfInfo)
{
    jsonObject = nlohmann::json {
        {APP_QF_INFO_VERSION_CODE, appqfInfo.versionCode},
        {APP_QF_INFO_VERSION_NAME, appqfInfo.versionName},
        {APP_QF_INFO_CPU_ABI, appqfInfo.cpuAbi},
        {APP_QF_INFO_NATIVE_LIBRARY_PATH, appqfInfo.nativeLibraryPath},
        {APP_QF_INFO_TYPE, appqfInfo.type},
        {APP_QF_INFO_HQF_INFOS, appqfInfo.hqfInfos}
    };
}

void from_json(const nlohmann::json &jsonObject, AppqfInfo &appqfInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        APP_QF_INFO_VERSION_CODE,
        appqfInfo.versionCode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_QF_INFO_VERSION_NAME,
        appqfInfo.versionName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_QF_INFO_CPU_ABI,
        appqfInfo.cpuAbi,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_QF_INFO_NATIVE_LIBRARY_PATH,
        appqfInfo.nativeLibraryPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<QuickFixType>(jsonObject,
        jsonObjectEnd,
        APP_QF_INFO_TYPE,
        appqfInfo.type,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<std::vector<HqfInfo>>(jsonObject,
        jsonObjectEnd,
        APP_QF_INFO_HQF_INFOS,
        appqfInfo.hqfInfos,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "read module appqfInfo from jsonObject error, error code : %{public}d",
            parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const AppQuickFix &appQuickFix)
{
    jsonObject = nlohmann::json {
        {Constants::BUNDLE_NAME, appQuickFix.bundleName},
        {APP_QUICK_FIX_VERSION_CODE, appQuickFix.versionCode},
        {APP_QUICK_FIX_VERSION_NAME, appQuickFix.versionName},
        {APP_QUICK_FIX_DEPLOYED_APP_QF_INFO, appQuickFix.deployedAppqfInfo},
        {APP_QUICK_FIX_DEPLOYING_APP_QF_INFO, appQuickFix.deployingAppqfInfo}
    };
}

void from_json(const nlohmann::json &jsonObject, AppQuickFix &appQuickFix)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        appQuickFix.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        APP_QUICK_FIX_VERSION_CODE,
        appQuickFix.versionCode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_QUICK_FIX_VERSION_NAME,
        appQuickFix.versionName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<AppqfInfo>(jsonObject,
        jsonObjectEnd,
        APP_QUICK_FIX_DEPLOYED_APP_QF_INFO,
        appQuickFix.deployedAppqfInfo,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);

    GetValueIfFindKey<AppqfInfo>(jsonObject,
        jsonObjectEnd,
        APP_QUICK_FIX_DEPLOYING_APP_QF_INFO,
        appQuickFix.deployingAppqfInfo,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "read module appQuickFix from jsonObject error, error code : %{public}d",
            parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const ApplicationInfo &applicationInfo)
{
    jsonObject = nlohmann::json {
        {APPLICATION_NAME, applicationInfo.name},
        {Constants::BUNDLE_NAME, applicationInfo.bundleName},
        {APPLICATION_VERSION_CODE, applicationInfo.versionCode},
        {APPLICATION_VERSION_NAME, applicationInfo.versionName},
        {APPLICATION_MIN_COMPATIBLE_VERSION_CODE, applicationInfo.minCompatibleVersionCode},
        {APPLICATION_API_COMPATIBLE_VERSION, applicationInfo.apiCompatibleVersion},
        {APPLICATION_API_TARGET_VERSION, applicationInfo.apiTargetVersion},
        {APPLICATION_ICON_PATH, applicationInfo.iconPath},
        {APPLICATION_ICON_ID, applicationInfo.iconId},
        {APPLICATION_LABEL, applicationInfo.label},
        {APPLICATION_LABEL_ID, applicationInfo.labelId},
        {APPLICATION_DESCRIPTION, applicationInfo.description},
        {APPLICATION_DESCRIPTION_ID, applicationInfo.descriptionId},
        {APPLICATION_KEEP_ALIVE, applicationInfo.keepAlive},
        {APPLICATION_REMOVABLE, applicationInfo.removable},
        {APPLICATION_SINGLETON, applicationInfo.singleton},
        {APPLICATION_USER_DATA_CLEARABLE, applicationInfo.userDataClearable},
        {ALLOW_APP_RUN_WHEN_DEVICE_FIRST_LOCKED, applicationInfo.allowAppRunWhenDeviceFirstLocked},
        {APPLICATION_ACCESSIBLE, applicationInfo.accessible},
        {APPLICATION_IS_SYSTEM_APP, applicationInfo.isSystemApp},
        {APPLICATION_IS_LAUNCHER_APP, applicationInfo.isLauncherApp},
        {APPLICATION_IS_FREEINSTALL_APP, applicationInfo.isFreeInstallApp},
        {APPLICATION_RUNNING_RESOURCES_APPLY, applicationInfo.runningResourcesApply},
        {APPLICATION_ASSOCIATED_WAKE_UP, applicationInfo.associatedWakeUp},
        {APPLICATION_HIDE_DESKTOP_ICON, applicationInfo.hideDesktopIcon},
        {APPLICATION_FORM_VISIBLE_NOTIFY, applicationInfo.formVisibleNotify},
        {APPLICATION_ALLOW_COMMON_EVENT, applicationInfo.allowCommonEvent},
        {APPLICATION_CODE_PATH, applicationInfo.codePath},
        {APPLICATION_DATA_DIR, applicationInfo.dataDir},
        {APPLICATION_DATA_BASE_DIR, applicationInfo.dataBaseDir},
        {APPLICATION_CACHE_DIR, applicationInfo.cacheDir},
        {APPLICATION_ENTRY_DIR, applicationInfo.entryDir},
        {APPLICATION_API_RELEASETYPE, applicationInfo.apiReleaseType},
        {APPLICATION_DEBUG, applicationInfo.debug},
        {APPLICATION_DEVICE_ID, applicationInfo.deviceId},
        {APPLICATION_DISTRIBUTED_NOTIFICATION_ENABLED, applicationInfo.distributedNotificationEnabled},
        {APPLICATION_INSTALLED_FOR_ALL_USER, applicationInfo.installedForAllUser},
        {APPLICATION_ALLOW_ENABLE_NOTIFICATION, applicationInfo.allowEnableNotification},
        {APPLICATION_ENTITY_TYPE, applicationInfo.entityType},
        {APPLICATION_PROCESS, applicationInfo.process},
        {APPLICATION_SUPPORTED_MODES, applicationInfo.supportedModes},
        {APPLICATION_VENDOR, applicationInfo.vendor},
        {APPLICATION_PRIVILEGE_LEVEL, applicationInfo.appPrivilegeLevel},
        {APPLICATION_ACCESSTOKEN_ID, applicationInfo.accessTokenId},
        {APPLICATION_ACCESSTOKEN_ID_EX, applicationInfo.accessTokenIdEx},
        {APPLICATION_ENABLED, applicationInfo.enabled},
        {APPLICATION_UID, applicationInfo.uid},
        {APPLICATION_PERMISSIONS, applicationInfo.permissions},
        {APPLICATION_MODULE_SOURCE_DIRS, applicationInfo.moduleSourceDirs},
        {APPLICATION_MODULE_INFOS, applicationInfo.moduleInfos},
        {APPLICATION_META_DATA_CONFIG_JSON, applicationInfo.metaData},
        {APPLICATION_META_DATA_MODULE_JSON, applicationInfo.metadata},
        {APPLICATION_FINGERPRINT, applicationInfo.fingerprint},
        {APPLICATION_ICON, applicationInfo.icon},
        {APPLICATION_FLAGS, applicationInfo.flags},
        {APPLICATION_ENTRY_MODULE_NAME, applicationInfo.entryModuleName},
        {APPLICATION_NATIVE_LIBRARY_PATH, applicationInfo.nativeLibraryPath},
        {APPLICATION_CPU_ABI, applicationInfo.cpuAbi},
        {APPLICATION_ARK_NATIVE_FILE_PATH, applicationInfo.arkNativeFilePath},
        {APPLICATION_ARK_NATIVE_FILE_ABI, applicationInfo.arkNativeFileAbi},
        {APPLICATION_IS_COMPRESS_NATIVE_LIBS, applicationInfo.isCompressNativeLibs},
        {APPLICATION_SIGNATURE_KEY, applicationInfo.signatureKey},
        {APPLICATION_TARGETBUNDLELIST, applicationInfo.targetBundleList},
        {APPLICATION_APP_DISTRIBUTION_TYPE, applicationInfo.appDistributionType},
        {APPLICATION_APP_PROVISION_TYPE, applicationInfo.appProvisionType},
        {APPLICATION_ICON_RESOURCE, applicationInfo.iconResource},
        {APPLICATION_LABEL_RESOURCE, applicationInfo.labelResource},
        {APPLICATION_DESCRIPTION_RESOURCE, applicationInfo.descriptionResource},
        {APPLICATION_MULTI_PROJECTS, applicationInfo.multiProjects},
        {APPLICATION_CROWDTEST_DEADLINE, applicationInfo.crowdtestDeadline},
        {APPLICATION_NEED_APP_DETAIL, applicationInfo.needAppDetail},
        {APPLICATION_APP_DETAIL_ABILITY_LIBRARY_PATH, applicationInfo.appDetailAbilityLibraryPath},
        {APPLICATION_APP_TARGET_BUNDLE_NAME, applicationInfo.targetBundleName},
        {APPLICATION_APP_TARGET_PRIORITY, applicationInfo.targetPriority},
        {APPLICATION_APP_OVERLAY_STATE, applicationInfo.overlayState},
        {APPLICATION_ASAN_ENABLED, applicationInfo.asanEnabled},
        {APPLICATION_ASAN_LOG_PATH, applicationInfo.asanLogPath},
        {APPLICATION_APP_TYPE, applicationInfo.bundleType},
        {APPLICATION_COMPILE_SDK_VERSION, applicationInfo.compileSdkVersion},
        {APPLICATION_COMPILE_SDK_TYPE, applicationInfo.compileSdkType},
        {APPLICATION_RESOURCES_APPLY, applicationInfo.resourcesApply},
        {APPLICATION_GWP_ASAN_ENABLED, applicationInfo.gwpAsanEnabled},
        {APPLICATION_HWASAN_ENABLED, applicationInfo.hwasanEnabled},
        {APPLICATION_RESERVED_FLAG, applicationInfo.applicationReservedFlag},
        {APPLICATION_TSAN_ENABLED, applicationInfo.tsanEnabled},
        {APPLICATION_APP_ENVIRONMENTS, applicationInfo.appEnvironments},
        {APPLICATION_ORGANIZATION, applicationInfo.organization},
        {APPLICATION_MULTI_APP_MODE, applicationInfo.multiAppMode},
        {APPLICATION_MAX_CHILD_PROCESS, applicationInfo.maxChildProcess},
        {APPLICATION_APP_INDEX, applicationInfo.appIndex},
        {APPLICATION_INSTALL_SOURCE, applicationInfo.installSource},
        {APPLICATION_CONFIGURATION, applicationInfo.configuration},
        {APPLICATION_CLOUD_FILE_SYNC_ENABLED, applicationInfo.cloudFileSyncEnabled},
        {APPLICATION_APPLICATION_FLAGS, applicationInfo.applicationFlags},
        {APPLICATION_UBSAN_ENABLED, applicationInfo.ubsanEnabled},
        {APPLICATION_ALLOW_MULTI_PROCESS, applicationInfo.allowMultiProcess},
        {APPLICATION_ASSET_ACCESS_GROUPS, applicationInfo.assetAccessGroups},
        {APPLICATION_HAS_PLUGIN, applicationInfo.hasPlugin}
    };
}

void from_json(const nlohmann::json &jsonObject, ApplicationInfo &applicationInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_NAME,
        applicationInfo.name,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        applicationInfo.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        APPLICATION_VERSION_CODE,
        applicationInfo.versionCode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_VERSION_NAME,
        applicationInfo.versionName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APPLICATION_MIN_COMPATIBLE_VERSION_CODE,
        applicationInfo.minCompatibleVersionCode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APPLICATION_API_COMPATIBLE_VERSION,
        applicationInfo.apiCompatibleVersion,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APPLICATION_API_TARGET_VERSION,
        applicationInfo.apiTargetVersion,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ICON_PATH,
        applicationInfo.iconPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ICON_ID,
        applicationInfo.iconId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_LABEL,
        applicationInfo.label,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APPLICATION_LABEL_ID,
        applicationInfo.labelId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_DESCRIPTION,
        applicationInfo.description,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APPLICATION_DESCRIPTION_ID,
        applicationInfo.descriptionId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_KEEP_ALIVE,
        applicationInfo.keepAlive,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_REMOVABLE,
        applicationInfo.removable,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_SINGLETON,
        applicationInfo.singleton,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_USER_DATA_CLEARABLE,
        applicationInfo.userDataClearable,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        ALLOW_APP_RUN_WHEN_DEVICE_FIRST_LOCKED,
        applicationInfo.allowAppRunWhenDeviceFirstLocked,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ACCESSIBLE,
        applicationInfo.accessible,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_IS_SYSTEM_APP,
        applicationInfo.isSystemApp,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_IS_LAUNCHER_APP,
        applicationInfo.isLauncherApp,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_IS_FREEINSTALL_APP,
        applicationInfo.isFreeInstallApp,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_RUNNING_RESOURCES_APPLY,
        applicationInfo.runningResourcesApply,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ASSOCIATED_WAKE_UP,
        applicationInfo.associatedWakeUp,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_HIDE_DESKTOP_ICON,
        applicationInfo.hideDesktopIcon,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_FORM_VISIBLE_NOTIFY,
        applicationInfo.formVisibleNotify,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ALLOW_COMMON_EVENT,
        applicationInfo.allowCommonEvent,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_CODE_PATH,
        applicationInfo.codePath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_DATA_DIR,
        applicationInfo.dataDir,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_DATA_BASE_DIR,
        applicationInfo.dataBaseDir,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_CACHE_DIR,
        applicationInfo.cacheDir,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ENTRY_DIR,
        applicationInfo.entryDir,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_API_RELEASETYPE,
        applicationInfo.apiReleaseType,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_DEBUG,
        applicationInfo.debug,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_DEVICE_ID,
        applicationInfo.deviceId,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_DISTRIBUTED_NOTIFICATION_ENABLED,
        applicationInfo.distributedNotificationEnabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_INSTALLED_FOR_ALL_USER,
        applicationInfo.installedForAllUser,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ALLOW_ENABLE_NOTIFICATION,
        applicationInfo.allowEnableNotification,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ENTITY_TYPE,
        applicationInfo.entityType,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_PROCESS,
        applicationInfo.process,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        APPLICATION_SUPPORTED_MODES,
        applicationInfo.supportedModes,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_VENDOR,
        applicationInfo.vendor,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_PRIVILEGE_LEVEL,
        applicationInfo.appPrivilegeLevel,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ACCESSTOKEN_ID,
        applicationInfo.accessTokenId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint64_t>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ACCESSTOKEN_ID_EX,
        applicationInfo.accessTokenIdEx,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ENABLED,
        applicationInfo.enabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        APPLICATION_UID,
        applicationInfo.uid,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        APPLICATION_PERMISSIONS,
        applicationInfo.permissions,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        APPLICATION_MODULE_SOURCE_DIRS,
        applicationInfo.moduleSourceDirs,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<ModuleInfo>>(jsonObject,
        jsonObjectEnd,
        APPLICATION_MODULE_INFOS,
        applicationInfo.moduleInfos,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::map<std::string, std::vector<CustomizeData>>>(jsonObject,
        jsonObjectEnd,
        APPLICATION_META_DATA_CONFIG_JSON,
        applicationInfo.metaData,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, std::vector<Metadata>>>(jsonObject,
        jsonObjectEnd,
        APPLICATION_META_DATA_MODULE_JSON,
        applicationInfo.metadata,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_FINGERPRINT,
        applicationInfo.fingerprint,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ICON,
        applicationInfo.icon,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        APPLICATION_FLAGS,
        applicationInfo.flags,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ENTRY_MODULE_NAME,
        applicationInfo.entryModuleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_NATIVE_LIBRARY_PATH,
        applicationInfo.nativeLibraryPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_CPU_ABI,
        applicationInfo.cpuAbi,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ARK_NATIVE_FILE_PATH,
        applicationInfo.arkNativeFilePath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ARK_NATIVE_FILE_ABI,
        applicationInfo.arkNativeFileAbi,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_IS_COMPRESS_NATIVE_LIBS,
        applicationInfo.isCompressNativeLibs,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_SIGNATURE_KEY,
        applicationInfo.signatureKey,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        APPLICATION_TARGETBUNDLELIST,
        applicationInfo.targetBundleList,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_APP_DISTRIBUTION_TYPE,
        applicationInfo.appDistributionType,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_APP_PROVISION_TYPE,
        applicationInfo.appProvisionType,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<Resource>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ICON_RESOURCE,
        applicationInfo.iconResource,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<Resource>(jsonObject,
        jsonObjectEnd,
        APPLICATION_LABEL_RESOURCE,
        applicationInfo.labelResource,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<Resource>(jsonObject,
        jsonObjectEnd,
        APPLICATION_DESCRIPTION_RESOURCE,
        applicationInfo.descriptionResource,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_MULTI_PROJECTS,
        applicationInfo.multiProjects,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int64_t>(jsonObject,
        jsonObjectEnd,
        APPLICATION_CROWDTEST_DEADLINE,
        applicationInfo.crowdtestDeadline,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<AppQuickFix>(jsonObject,
        jsonObjectEnd,
        APPLICATION_APP_QUICK_FIX,
        applicationInfo.appQuickFix,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_NEED_APP_DETAIL,
        applicationInfo.needAppDetail,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_APP_DETAIL_ABILITY_LIBRARY_PATH,
        applicationInfo.appDetailAbilityLibraryPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_APP_TARGET_BUNDLE_NAME,
        applicationInfo.targetBundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        APPLICATION_APP_TARGET_PRIORITY,
        applicationInfo.targetPriority,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        APPLICATION_APP_OVERLAY_STATE,
        applicationInfo.overlayState,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ASAN_ENABLED,
        applicationInfo.asanEnabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ASAN_LOG_PATH,
        applicationInfo.asanLogPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<BundleType>(jsonObject,
        jsonObjectEnd,
        APPLICATION_APP_TYPE,
        applicationInfo.bundleType,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_COMPILE_SDK_VERSION,
        applicationInfo.compileSdkVersion,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_COMPILE_SDK_TYPE,
        applicationInfo.compileSdkType,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<int32_t>>(jsonObject,
        jsonObjectEnd,
        APPLICATION_RESOURCES_APPLY,
        applicationInfo.resourcesApply,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::NUMBER);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_GWP_ASAN_ENABLED,
        applicationInfo.gwpAsanEnabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject,
        jsonObjectEnd,
        APPLICATION_RESERVED_FLAG,
        applicationInfo.applicationReservedFlag,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_TSAN_ENABLED,
        applicationInfo.tsanEnabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ORGANIZATION,
        applicationInfo.organization,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<ApplicationEnvironment>>(jsonObject,
        jsonObjectEnd,
        APPLICATION_APP_ENVIRONMENTS,
        applicationInfo.appEnvironments,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<MultiAppModeData>(jsonObject,
        jsonObjectEnd,
        APPLICATION_MULTI_APP_MODE,
        applicationInfo.multiAppMode,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APPLICATION_APP_INDEX,
        applicationInfo.appIndex,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APPLICATION_MAX_CHILD_PROCESS,
        applicationInfo.maxChildProcess,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_INSTALL_SOURCE,
        applicationInfo.installSource,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_HWASAN_ENABLED,
        applicationInfo.hwasanEnabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APPLICATION_CONFIGURATION,
        applicationInfo.configuration,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_CLOUD_FILE_SYNC_ENABLED,
        applicationInfo.cloudFileSyncEnabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        APPLICATION_APPLICATION_FLAGS,
        applicationInfo.applicationFlags,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_UBSAN_ENABLED,
        applicationInfo.ubsanEnabled,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ALLOW_MULTI_PROCESS,
        applicationInfo.allowMultiProcess,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        APPLICATION_ASSET_ACCESS_GROUPS,
        applicationInfo.assetAccessGroups,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        APPLICATION_HAS_PLUGIN,
        applicationInfo.hasPlugin,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "from_json error:%{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
