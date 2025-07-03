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

#include "hap_module_info.h"

#include "bundle_constants.h"
#include "hilog_tag_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string HAP_MODULE_INFO_NAME = "name";
const std::string HAP_MODULE_INFO_PACKAGE = "package";
const std::string HAP_MODULE_INFO_DESCRIPTION = "description";
const std::string HAP_MODULE_INFO_DESCRIPTION_ID = "descriptionId";
const std::string HAP_MODULE_INFO_ICON_PATH = "iconPath";
const std::string HAP_MODULE_INFO_ICON_ID = "iconId";
const std::string HAP_MODULE_INFO_LABEL = "label";
const std::string HAP_MODULE_INFO_LABEL_ID = "labelId";
const std::string HAP_MODULE_INFO_BACKGROUND_IMG = "backgroundImg";
const std::string HAP_MODULE_INFO_MAIN_ABILITY = "mainAbility";
const std::string HAP_MODULE_INFO_SRC_PATH = "srcPath";
const std::string HAP_MODULE_INFO_HASH_VALUE = "hashValue";
const std::string HAP_MODULE_INFO_SUPPORTED_MODES = "supportedModes";
const std::string HAP_MODULE_INFO_REQ_CAPABILITIES = "reqCapabilities";
const std::string HAP_MODULE_INFO_DEVICE_TYPES = "deviceTypes";
const std::string HAP_MODULE_INFO_ABILITY_INFOS = "abilityInfos";
const std::string HAP_MODULE_INFO_COLOR_MODE = "colorMode";
const std::string HAP_MODULE_INFO_MAIN_ELEMENTNAME = "mainElementName";
const std::string HAP_MODULE_INFO_PAGES = "pages";
const std::string HAP_MODULE_INFO_SYSTEM_THEME = "systemTheme";
const std::string HAP_MODULE_INFO_PROCESS = "process";
const std::string HAP_MODULE_INFO_RESOURCE_PATH = "resourcePath";
const std::string HAP_MODULE_INFO_SRC_ENTRANCE = "srcEntrance";
const std::string HAP_MODULE_INFO_UI_SYNTAX = "uiSyntax";
const std::string HAP_MODULE_INFO_VIRTUAL_MACHINE = "virtualMachine";
const std::string HAP_MODULE_INFO_DELIVERY_WITH_INSTALL = "deliveryWithInstall";
const std::string HAP_MODULE_INFO_INSTALLATION_FREE = "installationFree";
const std::string HAP_MODULE_INFO_IS_MODULE_JSON = "isModuleJson";
const std::string HAP_MODULE_INFO_IS_STAGE_BASED_MODEL = "isStageBasedModel";
const std::string HAP_MODULE_INFO_IS_REMOVABLE = "isRemovable";
const std::string HAP_MODULE_INFO_MODULE_TYPE = "moduleType";
const std::string HAP_MODULE_INFO_EXTENSION_INFOS = "extensionInfos";
const std::string HAP_MODULE_INFO_META_DATA = "metadata";
const std::string HAP_MODULE_INFO_DEPENDENCIES = "dependencies";
const std::string HAP_MODULE_INFO_UPGRADE_FLAG = "upgradeFlag";
const std::string HAP_MODULE_INFO_HAP_PATH = "hapPath";
const std::string HAP_MODULE_INFO_COMPILE_MODE = "compileMode";
const std::string HAP_MODULE_INFO_HQF_INFO = "hqfInfo";
const std::string HAP_MODULE_INFO_IS_LIB_ISOLATED = "isLibIsolated";
const std::string HAP_MODULE_INFO_NATIVE_LIBRARY_PATH = "nativeLibraryPath";
const std::string HAP_MODULE_INFO_CPU_ABI = "cpuAbi";
const std::string HAP_MODULE_INFO_MODULE_SOURCE_DIR = "moduleSourceDir";
const std::string HAP_OVERLAY_MODULE_INFO = "overlayModuleInfos";
const std::string HAP_MODULE_INFO_ATOMIC_SERVICE_MODULE_TYPE = "atomicServiceModuleType";
const std::string HAP_MODULE_INFO_PRELOADS = "preloads";
const std::string PRELOAD_ITEM_MODULE_NAME = "moduleName";
const std::string HAP_MODULE_INFO_VERSION_CODE = "versionCode";
const std::string HAP_MODULE_INFO_PROXY_DATAS = "proxyDatas";
const std::string PROXY_DATA_URI = "uri";
const std::string PROXY_DATA_REQUIRED_READ_PERMISSION = "requiredReadPermission";
const std::string PROXY_DATA_REQUIRED_WRITE_PERMISSION = "requiredWritePermission";
const std::string PROXY_DATA_METADATA = "metadata";
const std::string HAP_MODULE_INFO_BUILD_HASH = "buildHash";
const std::string HAP_MODULE_INFO_ISOLATION_MODE = "isolationMode";
const std::string HAP_MODULE_INFO_AOT_COMPILE_STATUS = "aotCompileStatus";
const std::string HAP_MODULE_INFO_COMPRESS_NATIVE_LIBS = "compressNativeLibs";
const std::string HAP_MODULE_INFO_NATIVE_LIBRARY_FILE_NAMES = "nativeLibraryFileNames";
const std::string HAP_MODULE_INFO_FILE_CONTEXT_MENU = "fileContextMenu";
const std::string HAP_MODULE_INFO_ROUTER_MAP = "routerMap";
const std::string HAP_MODULE_INFO_ROUTER_ARRAY = "routerArray";

const std::string ROUTER_ITEM_KEY_NAME = "name";
const std::string ROUTER_ITEM_KEY_PAGE_SOURCE_FILE = "pageSourceFile";
const std::string ROUTER_ITEM_KEY_BUILD_FUNCTION = "buildFunction";
const std::string ROUTER_ITEM_KEY_DATA = "data";
const std::string ROUTER_ITEM_KEY_CUSTOM_DATA = "customData";
const std::string ROUTER_ITEM_KEY_OHMURL = "ohmurl";
const std::string ROUTER_ITEM_KEY_BUNDLE_NAME = "bundleName";
const std::string ROUTER_ITEM_KEY_MODULE_NAME = "moduleName";
const std::string HAP_MODULE_INFO_APP_ENVIRONMENTS = "appEnvironments";

const std::string APP_ENVIRONMENTS_NAME = "name";
const std::string APP_ENVIRONMENTS_VALUE = "value";
const std::string HAP_MODULE_INFO_PACKAGE_NAME = "packageName";
const std::string HAP_MODULE_ABILITY_SRC_ENTRY_DELEGATOR = "abilitySrcEntryDelegator";
const std::string HAP_MODULE_ABILITY_STAGE_SRC_ENTRY_DELEGATOR = "abilityStageSrcEntryDelegator";
const std::string HAP_MODULE_INFO_APP_STARTUP = "appStartup";

const std::string MODULE_OVERLAY_BUNDLE_NAME = "bundleName";
const std::string MODULE_OVERLAY_MODULE_NAME = "moduleName";
const std::string MODULE_OVERLAY_HAP_PATH = "hapPath";
const std::string MODULE_OVERLAY_PRIORITY = "priority";
const std::string MODULE_OVERLAY_STATE = "state";
const std::string MODULE_TARGET_MODULE_NAME = "targetModuleName";
}
void to_json(nlohmann::json &jsonObject, const PreloadItem &preloadItem)
{
    jsonObject = nlohmann::json {
        {PRELOAD_ITEM_MODULE_NAME, preloadItem.moduleName}
    };
}

void from_json(const nlohmann::json &jsonObject, PreloadItem &preloadItem)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        PRELOAD_ITEM_MODULE_NAME,
        preloadItem.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "read PreloadItem error:%{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const ProxyData &proxyData)
{
    jsonObject = nlohmann::json {
        {PROXY_DATA_URI, proxyData.uri},
        {PROXY_DATA_REQUIRED_READ_PERMISSION, proxyData.requiredReadPermission},
        {PROXY_DATA_REQUIRED_WRITE_PERMISSION, proxyData.requiredWritePermission},
        {PROXY_DATA_METADATA, proxyData.metadata}
    };
}

void from_json(const nlohmann::json &jsonObject, ProxyData &proxyData)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        PROXY_DATA_URI,
        proxyData.uri,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        PROXY_DATA_REQUIRED_READ_PERMISSION,
        proxyData.requiredReadPermission,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        PROXY_DATA_REQUIRED_WRITE_PERMISSION,
        proxyData.requiredWritePermission,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<Metadata>(jsonObject,
        jsonObjectEnd,
        PROXY_DATA_METADATA,
        proxyData.metadata,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "read ProxyData from database error:%{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const OverlayModuleInfo &overlayModuleInfo)
{
    jsonObject = nlohmann::json {
        {MODULE_OVERLAY_BUNDLE_NAME, overlayModuleInfo.bundleName},
        {MODULE_OVERLAY_MODULE_NAME, overlayModuleInfo.moduleName},
        {MODULE_TARGET_MODULE_NAME, overlayModuleInfo.targetModuleName},
        {MODULE_OVERLAY_HAP_PATH, overlayModuleInfo.hapPath},
        {MODULE_OVERLAY_PRIORITY, overlayModuleInfo.priority},
        {MODULE_OVERLAY_STATE, overlayModuleInfo.state}
    };
}

void from_json(const nlohmann::json &jsonObject, OverlayModuleInfo &overlayModuleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_OVERLAY_BUNDLE_NAME,
        overlayModuleInfo.bundleName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_OVERLAY_MODULE_NAME,
        overlayModuleInfo.moduleName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_TARGET_MODULE_NAME,
        overlayModuleInfo.targetModuleName,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        MODULE_OVERLAY_HAP_PATH,
        overlayModuleInfo.hapPath,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        MODULE_OVERLAY_PRIORITY,
        overlayModuleInfo.priority,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        MODULE_OVERLAY_STATE,
        overlayModuleInfo.state,
        JsonType::NUMBER,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "overlayModuleInfo from_json error : %{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const RouterItem &routerItem)
{
    jsonObject = nlohmann::json {
        {ROUTER_ITEM_KEY_NAME, routerItem.name},
        {ROUTER_ITEM_KEY_PAGE_SOURCE_FILE, routerItem.pageSourceFile},
        {ROUTER_ITEM_KEY_BUILD_FUNCTION, routerItem.buildFunction},
        {ROUTER_ITEM_KEY_DATA, routerItem.data},
        {ROUTER_ITEM_KEY_CUSTOM_DATA, routerItem.customData},
        {ROUTER_ITEM_KEY_OHMURL, routerItem.ohmurl},
        {ROUTER_ITEM_KEY_BUNDLE_NAME, routerItem.bundleName},
        {ROUTER_ITEM_KEY_MODULE_NAME, routerItem.moduleName}
    };
}

void from_json(const nlohmann::json &jsonObject, RouterItem &routerItem)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ROUTER_ITEM_KEY_NAME,
        routerItem.name,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ROUTER_ITEM_KEY_PAGE_SOURCE_FILE,
        routerItem.pageSourceFile,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ROUTER_ITEM_KEY_BUILD_FUNCTION,
        routerItem.buildFunction,
        JsonType::STRING,
        true,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ROUTER_ITEM_KEY_OHMURL,
        routerItem.ohmurl,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ROUTER_ITEM_KEY_BUNDLE_NAME,
        routerItem.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        ROUTER_ITEM_KEY_MODULE_NAME,
        routerItem.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, std::string>>(jsonObject,
        jsonObjectEnd,
        ROUTER_ITEM_KEY_DATA,
        routerItem.data,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "read RouterItem jsonObject error : %{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const AppEnvironment &appEnvironment)
{
    jsonObject = nlohmann::json {
        {APP_ENVIRONMENTS_NAME, appEnvironment.name},
        {APP_ENVIRONMENTS_VALUE, appEnvironment.value}
    };
}

void from_json(const nlohmann::json &jsonObject, AppEnvironment &appEnvironment)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_ENVIRONMENTS_NAME,
        appEnvironment.name,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        APP_ENVIRONMENTS_VALUE,
        appEnvironment.value,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "read AppEnvironment error : %{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const HapModuleInfo &hapModuleInfo)
{
    jsonObject = nlohmann::json {
        {HAP_MODULE_INFO_NAME, hapModuleInfo.name}, {HAP_MODULE_INFO_PACKAGE, hapModuleInfo.package},
        {Constants::MODULE_NAME, hapModuleInfo.moduleName}, {HAP_MODULE_INFO_DESCRIPTION, hapModuleInfo.description},
        {HAP_MODULE_INFO_DESCRIPTION_ID, hapModuleInfo.descriptionId},
        {HAP_MODULE_INFO_ICON_PATH, hapModuleInfo.iconPath}, {HAP_MODULE_INFO_ICON_ID, hapModuleInfo.iconId},
        {HAP_MODULE_INFO_LABEL, hapModuleInfo.label}, {HAP_MODULE_INFO_LABEL_ID, hapModuleInfo.labelId},
        {HAP_MODULE_INFO_BACKGROUND_IMG, hapModuleInfo.backgroundImg},
        {HAP_MODULE_INFO_MAIN_ABILITY, hapModuleInfo.mainAbility},
        {HAP_MODULE_INFO_SRC_PATH, hapModuleInfo.srcPath}, {HAP_MODULE_INFO_HASH_VALUE, hapModuleInfo.hashValue},
        {HAP_MODULE_INFO_HAP_PATH, hapModuleInfo.hapPath},
        {HAP_MODULE_INFO_SUPPORTED_MODES, hapModuleInfo.supportedModes},
        {HAP_MODULE_INFO_REQ_CAPABILITIES, hapModuleInfo.reqCapabilities},
        {HAP_MODULE_INFO_DEVICE_TYPES, hapModuleInfo.deviceTypes},
        {HAP_MODULE_INFO_ABILITY_INFOS, hapModuleInfo.abilityInfos},
        {HAP_MODULE_INFO_COLOR_MODE, hapModuleInfo.colorMode}, {Constants::BUNDLE_NAME, hapModuleInfo.bundleName},
        {HAP_MODULE_INFO_MAIN_ELEMENTNAME, hapModuleInfo.mainElementName}, {HAP_MODULE_INFO_PAGES, hapModuleInfo.pages},
        {HAP_MODULE_INFO_SYSTEM_THEME, hapModuleInfo.systemTheme},
        {HAP_MODULE_INFO_PROCESS, hapModuleInfo.process}, {HAP_MODULE_INFO_RESOURCE_PATH, hapModuleInfo.resourcePath},
        {HAP_MODULE_INFO_SRC_ENTRANCE, hapModuleInfo.srcEntrance}, {HAP_MODULE_INFO_UI_SYNTAX, hapModuleInfo.uiSyntax},
        {HAP_MODULE_INFO_VIRTUAL_MACHINE, hapModuleInfo.virtualMachine},
        {HAP_MODULE_INFO_DELIVERY_WITH_INSTALL, hapModuleInfo.deliveryWithInstall},
        {HAP_MODULE_INFO_INSTALLATION_FREE, hapModuleInfo.installationFree},
        {HAP_MODULE_INFO_IS_MODULE_JSON, hapModuleInfo.isModuleJson},
        {HAP_MODULE_INFO_IS_STAGE_BASED_MODEL, hapModuleInfo.isStageBasedModel},
        {HAP_MODULE_INFO_IS_REMOVABLE, hapModuleInfo.isRemovable},
        {HAP_MODULE_INFO_UPGRADE_FLAG, hapModuleInfo.upgradeFlag},
        {HAP_MODULE_INFO_MODULE_TYPE, hapModuleInfo.moduleType},
        {HAP_MODULE_INFO_EXTENSION_INFOS, hapModuleInfo.extensionInfos},
        {HAP_MODULE_INFO_META_DATA, hapModuleInfo.metadata},
        {HAP_MODULE_INFO_DEPENDENCIES, hapModuleInfo.dependencies},
        {HAP_MODULE_INFO_COMPILE_MODE, hapModuleInfo.compileMode},
        {HAP_MODULE_INFO_IS_LIB_ISOLATED, hapModuleInfo.isLibIsolated},
        {HAP_MODULE_INFO_NATIVE_LIBRARY_PATH, hapModuleInfo.nativeLibraryPath},
        {HAP_MODULE_INFO_CPU_ABI, hapModuleInfo.cpuAbi},
        {HAP_MODULE_INFO_MODULE_SOURCE_DIR, hapModuleInfo.moduleSourceDir},
        {HAP_OVERLAY_MODULE_INFO, hapModuleInfo.overlayModuleInfos},
        {HAP_MODULE_INFO_ATOMIC_SERVICE_MODULE_TYPE, hapModuleInfo.atomicServiceModuleType},
        {HAP_MODULE_INFO_PRELOADS, hapModuleInfo.preloads},
        {HAP_MODULE_INFO_PROXY_DATAS, hapModuleInfo.proxyDatas},
        {HAP_MODULE_INFO_BUILD_HASH, hapModuleInfo.buildHash},
        {HAP_MODULE_INFO_ISOLATION_MODE, hapModuleInfo.isolationMode},
        {HAP_MODULE_INFO_AOT_COMPILE_STATUS, hapModuleInfo.aotCompileStatus},
        {HAP_MODULE_INFO_COMPRESS_NATIVE_LIBS, hapModuleInfo.compressNativeLibs},
        {HAP_MODULE_INFO_NATIVE_LIBRARY_FILE_NAMES, hapModuleInfo.nativeLibraryFileNames},
        {HAP_MODULE_INFO_FILE_CONTEXT_MENU, hapModuleInfo.fileContextMenu},
        {HAP_MODULE_INFO_ROUTER_MAP, hapModuleInfo.routerMap},
        {HAP_MODULE_INFO_ROUTER_ARRAY, hapModuleInfo.routerArray},
        {HAP_MODULE_INFO_APP_ENVIRONMENTS, hapModuleInfo.appEnvironments},
        {HAP_MODULE_INFO_PACKAGE_NAME, hapModuleInfo.packageName},
        {HAP_MODULE_ABILITY_SRC_ENTRY_DELEGATOR, hapModuleInfo.abilitySrcEntryDelegator},
        {HAP_MODULE_ABILITY_STAGE_SRC_ENTRY_DELEGATOR, hapModuleInfo.abilityStageSrcEntryDelegator},
        {HAP_MODULE_INFO_APP_STARTUP, hapModuleInfo.appStartup}
    };
}

void from_json(const nlohmann::json &jsonObject, HapModuleInfo &hapModuleInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_NAME,
        hapModuleInfo.name,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_PACKAGE,
        hapModuleInfo.package,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        hapModuleInfo.moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_DESCRIPTION,
        hapModuleInfo.description,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_DESCRIPTION_ID,
        hapModuleInfo.descriptionId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_ICON_PATH,
        hapModuleInfo.iconPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_ICON_ID,
        hapModuleInfo.iconId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_LABEL,
        hapModuleInfo.label,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_LABEL_ID,
        hapModuleInfo.labelId,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_BACKGROUND_IMG,
        hapModuleInfo.backgroundImg,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_MAIN_ABILITY,
        hapModuleInfo.mainAbility,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_SRC_PATH,
        hapModuleInfo.srcPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_HASH_VALUE,
        hapModuleInfo.hashValue,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_HAP_PATH,
        hapModuleInfo.hapPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_SUPPORTED_MODES,
        hapModuleInfo.supportedModes,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_REQ_CAPABILITIES,
        hapModuleInfo.reqCapabilities,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_DEVICE_TYPES,
        hapModuleInfo.deviceTypes,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::vector<AbilityInfo>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_ABILITY_INFOS,
        hapModuleInfo.abilityInfos,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<ModuleColorMode>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_COLOR_MODE,
        hapModuleInfo.colorMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        hapModuleInfo.bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_MAIN_ELEMENTNAME,
        hapModuleInfo.mainElementName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_PAGES,
        hapModuleInfo.pages,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_SYSTEM_THEME,
        hapModuleInfo.systemTheme,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_PROCESS,
        hapModuleInfo.process,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_RESOURCE_PATH,
        hapModuleInfo.resourcePath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_SRC_ENTRANCE,
        hapModuleInfo.srcEntrance,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_UI_SYNTAX,
        hapModuleInfo.uiSyntax,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_VIRTUAL_MACHINE,
        hapModuleInfo.virtualMachine,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_DELIVERY_WITH_INSTALL,
        hapModuleInfo.deliveryWithInstall,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_INSTALLATION_FREE,
        hapModuleInfo.installationFree,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_IS_MODULE_JSON,
        hapModuleInfo.isModuleJson,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_IS_STAGE_BASED_MODEL,
        hapModuleInfo.isStageBasedModel,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::map<std::string, bool>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_IS_REMOVABLE,
        hapModuleInfo.isRemovable,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_UPGRADE_FLAG,
        hapModuleInfo.upgradeFlag,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<ModuleType>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_MODULE_TYPE,
        hapModuleInfo.moduleType,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<ExtensionAbilityInfo>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_EXTENSION_INFOS,
        hapModuleInfo.extensionInfos,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<Metadata>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_META_DATA,
        hapModuleInfo.metadata,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<Dependency>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_DEPENDENCIES,
        hapModuleInfo.dependencies,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<CompileMode>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_COMPILE_MODE,
        hapModuleInfo.compileMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<HqfInfo>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_HQF_INFO,
        hapModuleInfo.hqfInfo,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_IS_LIB_ISOLATED,
        hapModuleInfo.isLibIsolated,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_NATIVE_LIBRARY_PATH,
        hapModuleInfo.nativeLibraryPath,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_CPU_ABI,
        hapModuleInfo.cpuAbi,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_MODULE_SOURCE_DIR,
        hapModuleInfo.moduleSourceDir,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<OverlayModuleInfo>>(jsonObject,
        jsonObjectEnd,
        HAP_OVERLAY_MODULE_INFO,
        hapModuleInfo.overlayModuleInfos,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<AtomicServiceModuleType>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_ATOMIC_SERVICE_MODULE_TYPE,
        hapModuleInfo.atomicServiceModuleType,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<PreloadItem>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_PRELOADS,
        hapModuleInfo.preloads,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<ProxyData>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_PROXY_DATAS,
        hapModuleInfo.proxyDatas,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_BUILD_HASH,
        hapModuleInfo.buildHash,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<IsolationMode>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_ISOLATION_MODE,
        hapModuleInfo.isolationMode,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<AOTCompileStatus>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_AOT_COMPILE_STATUS,
        hapModuleInfo.aotCompileStatus,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_COMPRESS_NATIVE_LIBS,
        hapModuleInfo.compressNativeLibs,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_NATIVE_LIBRARY_FILE_NAMES,
        hapModuleInfo.nativeLibraryFileNames,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_FILE_CONTEXT_MENU,
        hapModuleInfo.fileContextMenu,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_ROUTER_MAP,
        hapModuleInfo.routerMap,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<RouterItem>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_ROUTER_ARRAY,
        hapModuleInfo.routerArray,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::vector<AppEnvironment>>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_APP_ENVIRONMENTS,
        hapModuleInfo.appEnvironments,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_PACKAGE_NAME,
        hapModuleInfo.packageName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_ABILITY_SRC_ENTRY_DELEGATOR,
        hapModuleInfo.abilitySrcEntryDelegator,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_ABILITY_STAGE_SRC_ENTRY_DELEGATOR,
        hapModuleInfo.abilityStageSrcEntryDelegator,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        HAP_MODULE_INFO_APP_STARTUP,
        hapModuleInfo.appStartup,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "HapModuleInfo error:%{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
