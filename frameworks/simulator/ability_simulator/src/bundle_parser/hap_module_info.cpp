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

#include "hap_module_info.h"

#include "bundle_constants.h"
#include "hilog_tag_wrapper.h"
#include "json_util.h"
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

bool to_json(cJSON *&jsonObject, const PreloadItem &preloadItem)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, PRELOAD_ITEM_MODULE_NAME.c_str(), preloadItem.moduleName.c_str());
    return true;
}

void from_json(const cJSON *jsonObject, PreloadItem &preloadItem)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, PRELOAD_ITEM_MODULE_NAME, preloadItem.moduleName, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "read PreloadItem error:%{public}d", parseResult);
    }
}

bool to_json(cJSON *&jsonObject, const ProxyData &proxyData)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, PROXY_DATA_URI.c_str(), proxyData.uri.c_str());
    cJSON_AddStringToObject(jsonObject, PROXY_DATA_REQUIRED_READ_PERMISSION.c_str(),
        proxyData.requiredReadPermission.c_str());
    cJSON_AddStringToObject(jsonObject, PROXY_DATA_REQUIRED_WRITE_PERMISSION.c_str(),
        proxyData.requiredWritePermission.c_str());
    cJSON *metadataItem = nullptr;
    if (!to_json(metadataItem, proxyData.metadata)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json metadata failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, PROXY_DATA_METADATA.c_str(), metadataItem);
    return true;
}

void from_json(const cJSON *jsonObject, ProxyData &proxyData)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, PROXY_DATA_URI, proxyData.uri, false, parseResult);
    GetStringValueIfFindKey(jsonObject, PROXY_DATA_REQUIRED_READ_PERMISSION, proxyData.requiredReadPermission, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, PROXY_DATA_REQUIRED_WRITE_PERMISSION, proxyData.requiredWritePermission, false,
        parseResult);
    GetObjectValueIfFindKey(jsonObject, PROXY_DATA_METADATA, proxyData.metadata, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "read ProxyData from database error:%{public}d", parseResult);
    }
}

bool to_json(cJSON *&jsonObject, const OverlayModuleInfo &overlayModuleInfo)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, MODULE_OVERLAY_BUNDLE_NAME.c_str(), overlayModuleInfo.bundleName.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_OVERLAY_MODULE_NAME.c_str(), overlayModuleInfo.moduleName.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_TARGET_MODULE_NAME.c_str(), overlayModuleInfo.targetModuleName.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_OVERLAY_HAP_PATH.c_str(), overlayModuleInfo.hapPath.c_str());
    cJSON_AddNumberToObject(jsonObject, MODULE_OVERLAY_PRIORITY.c_str(),
        static_cast<double>(overlayModuleInfo.priority));
    cJSON_AddNumberToObject(jsonObject, MODULE_OVERLAY_STATE.c_str(), static_cast<double>(overlayModuleInfo.state));
    return true;
}

void from_json(const cJSON *jsonObject, OverlayModuleInfo &overlayModuleInfo)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, MODULE_OVERLAY_BUNDLE_NAME, overlayModuleInfo.bundleName, true, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_OVERLAY_MODULE_NAME, overlayModuleInfo.moduleName, true, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_TARGET_MODULE_NAME, overlayModuleInfo.targetModuleName, true,
        parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_OVERLAY_HAP_PATH, overlayModuleInfo.hapPath, true, parseResult);
    GetNumberValueIfFindKey(jsonObject, MODULE_OVERLAY_PRIORITY, overlayModuleInfo.priority, true, parseResult);
    GetNumberValueIfFindKey(jsonObject, MODULE_OVERLAY_STATE, overlayModuleInfo.state, true, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "overlayModuleInfo from_json error : %{public}d", parseResult);
    }
}

bool to_json(cJSON *&jsonObject, const RouterItem &routerItem)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, ROUTER_ITEM_KEY_NAME.c_str(), routerItem.name.c_str());
    cJSON_AddStringToObject(jsonObject, ROUTER_ITEM_KEY_PAGE_SOURCE_FILE.c_str(), routerItem.pageSourceFile.c_str());
    cJSON_AddStringToObject(jsonObject, ROUTER_ITEM_KEY_BUILD_FUNCTION.c_str(), routerItem.buildFunction.c_str());

    cJSON *dataItem = nullptr;
    if (!to_json(dataItem, routerItem.data)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json data failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, ROUTER_ITEM_KEY_DATA.c_str(), dataItem);

    cJSON_AddStringToObject(jsonObject, ROUTER_ITEM_KEY_CUSTOM_DATA.c_str(), routerItem.customData.c_str());
    cJSON_AddStringToObject(jsonObject, ROUTER_ITEM_KEY_OHMURL.c_str(), routerItem.ohmurl.c_str());
    cJSON_AddStringToObject(jsonObject, ROUTER_ITEM_KEY_BUNDLE_NAME.c_str(), routerItem.bundleName.c_str());
    cJSON_AddStringToObject(jsonObject, ROUTER_ITEM_KEY_MODULE_NAME.c_str(), routerItem.moduleName.c_str());
    return true;
}

void from_json(const cJSON *jsonObject, RouterItem &routerItem)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, ROUTER_ITEM_KEY_NAME.c_str(), routerItem.name, true, parseResult);
    GetStringValueIfFindKey(jsonObject, ROUTER_ITEM_KEY_PAGE_SOURCE_FILE.c_str(), routerItem.pageSourceFile, true,
        parseResult);
    GetStringValueIfFindKey(jsonObject, ROUTER_ITEM_KEY_BUILD_FUNCTION.c_str(), routerItem.buildFunction, true,
        parseResult);
    GetStringValueIfFindKey(jsonObject, ROUTER_ITEM_KEY_OHMURL.c_str(), routerItem.ohmurl, false, parseResult);
    GetStringValueIfFindKey(jsonObject, ROUTER_ITEM_KEY_BUNDLE_NAME.c_str(), routerItem.bundleName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, ROUTER_ITEM_KEY_MODULE_NAME.c_str(), routerItem.moduleName, false, parseResult);
    GetObjectValueMapIfFindKey(jsonObject, ROUTER_ITEM_KEY_DATA.c_str(), routerItem.data, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "read RouterItem jsonObject error : %{public}d", parseResult);
    }
}

bool to_json(cJSON *&jsonObject, const AppEnvironment &appEnvironment)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, APP_ENVIRONMENTS_NAME.c_str(), appEnvironment.name.c_str());
    cJSON_AddStringToObject(jsonObject, APP_ENVIRONMENTS_VALUE.c_str(), appEnvironment.value.c_str());
    return true;
}

void from_json(const cJSON *jsonObject, AppEnvironment &appEnvironment)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, APP_ENVIRONMENTS_NAME, appEnvironment.name, false, parseResult);
    GetStringValueIfFindKey(jsonObject, APP_ENVIRONMENTS_VALUE, appEnvironment.value, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "read AppEnvironment error : %{public}d", parseResult);
    }
}

bool to_json(cJSON *&jsonObject, const HapModuleInfo &hapModuleInfo)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }

    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_NAME.c_str(), hapModuleInfo.name.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_PACKAGE.c_str(), hapModuleInfo.package.c_str());
    cJSON_AddStringToObject(jsonObject, Constants::MODULE_NAME, hapModuleInfo.moduleName.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_DESCRIPTION.c_str(), hapModuleInfo.description.c_str());
    cJSON_AddNumberToObject(jsonObject, HAP_MODULE_INFO_DESCRIPTION_ID.c_str(),
        static_cast<double>(hapModuleInfo.descriptionId));
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_ICON_PATH.c_str(), hapModuleInfo.iconPath.c_str());
    cJSON_AddNumberToObject(jsonObject, HAP_MODULE_INFO_ICON_ID.c_str(), static_cast<double>(hapModuleInfo.iconId));
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_LABEL.c_str(), hapModuleInfo.label.c_str());
    cJSON_AddNumberToObject(jsonObject, HAP_MODULE_INFO_LABEL_ID.c_str(), static_cast<double>(hapModuleInfo.labelId));
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_BACKGROUND_IMG.c_str(), hapModuleInfo.backgroundImg.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_MAIN_ABILITY.c_str(), hapModuleInfo.mainAbility.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_SRC_PATH.c_str(), hapModuleInfo.srcPath.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_HASH_VALUE.c_str(), hapModuleInfo.hashValue.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_HAP_PATH.c_str(), hapModuleInfo.hapPath.c_str());
    cJSON_AddNumberToObject(jsonObject, HAP_MODULE_INFO_SUPPORTED_MODES.c_str(),
        static_cast<double>(hapModuleInfo.supportedModes));

    cJSON *reqCapabilitiesItem = nullptr;
    if (!to_json(reqCapabilitiesItem, hapModuleInfo.reqCapabilities)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json reqCapabilities failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, HAP_MODULE_INFO_REQ_CAPABILITIES.c_str(), reqCapabilitiesItem);

    cJSON *deviceTypesItem = nullptr;
    if (!to_json(deviceTypesItem, hapModuleInfo.deviceTypes)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json deviceTypes failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, HAP_MODULE_INFO_DEVICE_TYPES.c_str(), deviceTypesItem);

    cJSON *abilityInfosItem = nullptr;
    if (!to_json(abilityInfosItem, hapModuleInfo.abilityInfos)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json abilityInfos failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, HAP_MODULE_INFO_ABILITY_INFOS.c_str(), abilityInfosItem);
    
    cJSON_AddNumberToObject(jsonObject, HAP_MODULE_INFO_COLOR_MODE.c_str(),
        static_cast<double>(hapModuleInfo.colorMode));
    cJSON_AddStringToObject(jsonObject, Constants::BUNDLE_NAME, hapModuleInfo.bundleName.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_MAIN_ELEMENTNAME.c_str(),
        hapModuleInfo.mainElementName.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_PAGES.c_str(), hapModuleInfo.pages.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_SYSTEM_THEME.c_str(), hapModuleInfo.systemTheme.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_PROCESS.c_str(), hapModuleInfo.process.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_RESOURCE_PATH.c_str(), hapModuleInfo.resourcePath.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_SRC_ENTRANCE.c_str(), hapModuleInfo.srcEntrance.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_UI_SYNTAX.c_str(), hapModuleInfo.uiSyntax.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_VIRTUAL_MACHINE.c_str(), hapModuleInfo.virtualMachine.c_str());
    cJSON_AddBoolToObject(jsonObject, HAP_MODULE_INFO_DELIVERY_WITH_INSTALL.c_str(), hapModuleInfo.deliveryWithInstall);
    cJSON_AddBoolToObject(jsonObject, HAP_MODULE_INFO_INSTALLATION_FREE.c_str(), hapModuleInfo.installationFree);
    cJSON_AddBoolToObject(jsonObject, HAP_MODULE_INFO_IS_MODULE_JSON.c_str(), hapModuleInfo.isModuleJson);
    cJSON_AddBoolToObject(jsonObject, HAP_MODULE_INFO_IS_STAGE_BASED_MODEL.c_str(), hapModuleInfo.isStageBasedModel);

    cJSON *isRemovableItem = nullptr;
    if (!to_json(isRemovableItem, hapModuleInfo.isRemovable)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json isRemovable failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, HAP_MODULE_INFO_IS_REMOVABLE.c_str(), isRemovableItem);

    cJSON_AddNumberToObject(jsonObject, HAP_MODULE_INFO_UPGRADE_FLAG.c_str(),
        static_cast<double>(hapModuleInfo.upgradeFlag));
    cJSON_AddNumberToObject(jsonObject, HAP_MODULE_INFO_MODULE_TYPE.c_str(),
        static_cast<double>(hapModuleInfo.moduleType));

    cJSON *extensionInfosItem = nullptr;
    if (!to_json(extensionInfosItem, hapModuleInfo.extensionInfos)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json extensionInfos failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, HAP_MODULE_INFO_EXTENSION_INFOS.c_str(), extensionInfosItem);

    cJSON *metadataItem = nullptr;
    if (!to_json(metadataItem, hapModuleInfo.metadata)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json metadata failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, HAP_MODULE_INFO_META_DATA.c_str(), metadataItem);

    cJSON *dependenciesItem = nullptr;
    if (!to_json(dependenciesItem, hapModuleInfo.dependencies)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json dependencies failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, HAP_MODULE_INFO_DEPENDENCIES.c_str(), dependenciesItem);

    cJSON_AddNumberToObject(jsonObject, HAP_MODULE_INFO_COMPILE_MODE.c_str(),
        static_cast<double>(hapModuleInfo.compileMode));
    cJSON_AddBoolToObject(jsonObject, HAP_MODULE_INFO_IS_LIB_ISOLATED.c_str(), hapModuleInfo.isLibIsolated);
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_NATIVE_LIBRARY_PATH.c_str(),
        hapModuleInfo.nativeLibraryPath.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_CPU_ABI.c_str(), hapModuleInfo.cpuAbi.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_MODULE_SOURCE_DIR.c_str(),
        hapModuleInfo.moduleSourceDir.c_str());
    
    cJSON *overlayModuleInfosItem = nullptr;
    if (!to_json(overlayModuleInfosItem, hapModuleInfo.overlayModuleInfos)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json overlayModuleInfos failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, HAP_OVERLAY_MODULE_INFO.c_str(), overlayModuleInfosItem);

    cJSON_AddNumberToObject(jsonObject, HAP_MODULE_INFO_ATOMIC_SERVICE_MODULE_TYPE.c_str(),
        static_cast<double>(hapModuleInfo.atomicServiceModuleType));

    cJSON *preloadsItem = nullptr;
    if (!to_json(preloadsItem, hapModuleInfo.preloads)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json preloads failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, HAP_MODULE_INFO_PRELOADS.c_str(), preloadsItem);

    cJSON *proxyDatasItem = nullptr;
    if (!to_json(proxyDatasItem, hapModuleInfo.proxyDatas)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json proxyDatas failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, HAP_MODULE_INFO_PROXY_DATAS.c_str(), proxyDatasItem);

    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_BUILD_HASH.c_str(), hapModuleInfo.buildHash.c_str());
    cJSON_AddNumberToObject(jsonObject, HAP_MODULE_INFO_ISOLATION_MODE.c_str(),
        static_cast<double>(hapModuleInfo.isolationMode));
    cJSON_AddNumberToObject(jsonObject, HAP_MODULE_INFO_AOT_COMPILE_STATUS.c_str(),
        static_cast<double>(hapModuleInfo.aotCompileStatus));
    cJSON_AddBoolToObject(jsonObject, HAP_MODULE_INFO_COMPRESS_NATIVE_LIBS.c_str(), hapModuleInfo.compressNativeLibs);

    cJSON *nativeLibraryFileNamesItem = nullptr;
    if (!to_json(nativeLibraryFileNamesItem, hapModuleInfo.nativeLibraryFileNames)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json nativeLibraryFileNames failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, HAP_MODULE_INFO_NATIVE_LIBRARY_FILE_NAMES.c_str(), nativeLibraryFileNamesItem);

    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_FILE_CONTEXT_MENU.c_str(),
        hapModuleInfo.fileContextMenu.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_ROUTER_MAP.c_str(), hapModuleInfo.routerMap.c_str());

    cJSON *routerArrayItem = nullptr;
    if (!to_json(routerArrayItem, hapModuleInfo.routerArray)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json routerArray failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, HAP_MODULE_INFO_ROUTER_ARRAY.c_str(), routerArrayItem);

    cJSON *appEnvironmentsItem = nullptr;
    if (!to_json(appEnvironmentsItem, hapModuleInfo.appEnvironments)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json appEnvironments failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, HAP_MODULE_INFO_APP_ENVIRONMENTS.c_str(), appEnvironmentsItem);

    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_PACKAGE_NAME.c_str(), hapModuleInfo.packageName.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_ABILITY_SRC_ENTRY_DELEGATOR.c_str(),
        hapModuleInfo.abilitySrcEntryDelegator.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_ABILITY_STAGE_SRC_ENTRY_DELEGATOR.c_str(),
        hapModuleInfo.abilityStageSrcEntryDelegator.c_str());
    cJSON_AddStringToObject(jsonObject, HAP_MODULE_INFO_APP_STARTUP.c_str(), hapModuleInfo.appStartup.c_str());

    return true;
}

void from_json(const cJSON *jsonObject, HapModuleInfo &hapModuleInfo)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_NAME, hapModuleInfo.name, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_PACKAGE, hapModuleInfo.package, false, parseResult);
    GetStringValueIfFindKey(jsonObject, Constants::MODULE_NAME, hapModuleInfo.moduleName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_DESCRIPTION, hapModuleInfo.description, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, HAP_MODULE_INFO_DESCRIPTION_ID, hapModuleInfo.descriptionId, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_ICON_PATH, hapModuleInfo.iconPath, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, HAP_MODULE_INFO_ICON_ID, hapModuleInfo.iconId, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_LABEL, hapModuleInfo.label, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, HAP_MODULE_INFO_LABEL_ID, hapModuleInfo.labelId, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_BACKGROUND_IMG, hapModuleInfo.backgroundImg, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_MAIN_ABILITY, hapModuleInfo.mainAbility, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_SRC_PATH, hapModuleInfo.srcPath, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_HASH_VALUE, hapModuleInfo.hashValue, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_HAP_PATH, hapModuleInfo.hapPath, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, HAP_MODULE_INFO_SUPPORTED_MODES, hapModuleInfo.supportedModes, false,
        parseResult);
    GetStringValuesIfFindKey(jsonObject, HAP_MODULE_INFO_REQ_CAPABILITIES, hapModuleInfo.reqCapabilities, false,
        parseResult);
    GetStringValuesIfFindKey(jsonObject, HAP_MODULE_INFO_DEVICE_TYPES, hapModuleInfo.deviceTypes, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, HAP_MODULE_INFO_ABILITY_INFOS, hapModuleInfo.abilityInfos, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, HAP_MODULE_INFO_COLOR_MODE, hapModuleInfo.colorMode, false, parseResult);
    GetStringValueIfFindKey(jsonObject, Constants::BUNDLE_NAME, hapModuleInfo.bundleName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_MAIN_ELEMENTNAME, hapModuleInfo.mainElementName, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_PAGES, hapModuleInfo.pages, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_SYSTEM_THEME, hapModuleInfo.systemTheme, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_PROCESS, hapModuleInfo.process, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_RESOURCE_PATH, hapModuleInfo.resourcePath, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_SRC_ENTRANCE, hapModuleInfo.srcEntrance, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_UI_SYNTAX, hapModuleInfo.uiSyntax, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_VIRTUAL_MACHINE, hapModuleInfo.virtualMachine, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, HAP_MODULE_INFO_DELIVERY_WITH_INSTALL, hapModuleInfo.deliveryWithInstall, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, HAP_MODULE_INFO_INSTALLATION_FREE, hapModuleInfo.installationFree, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, HAP_MODULE_INFO_IS_MODULE_JSON, hapModuleInfo.isModuleJson, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, HAP_MODULE_INFO_IS_STAGE_BASED_MODEL, hapModuleInfo.isStageBasedModel, false,
        parseResult);
    GetBoolValueMapIfFindKey(jsonObject, HAP_MODULE_INFO_IS_REMOVABLE, hapModuleInfo.isRemovable, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, HAP_MODULE_INFO_UPGRADE_FLAG, hapModuleInfo.upgradeFlag, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, HAP_MODULE_INFO_MODULE_TYPE, hapModuleInfo.moduleType, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, HAP_MODULE_INFO_EXTENSION_INFOS, hapModuleInfo.extensionInfos, false,
        parseResult);
    GetObjectValuesIfFindKey(jsonObject, HAP_MODULE_INFO_META_DATA, hapModuleInfo.metadata, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, HAP_MODULE_INFO_DEPENDENCIES, hapModuleInfo.dependencies, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, HAP_MODULE_INFO_COMPILE_MODE, hapModuleInfo.compileMode, false, parseResult);
    GetObjectValueIfFindKey(jsonObject, HAP_MODULE_INFO_HQF_INFO, hapModuleInfo.hqfInfo, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, HAP_MODULE_INFO_IS_LIB_ISOLATED, hapModuleInfo.isLibIsolated, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_NATIVE_LIBRARY_PATH, hapModuleInfo.nativeLibraryPath, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_CPU_ABI, hapModuleInfo.cpuAbi, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_MODULE_SOURCE_DIR, hapModuleInfo.moduleSourceDir, false,
        parseResult);
    GetObjectValuesIfFindKey(jsonObject, HAP_OVERLAY_MODULE_INFO, hapModuleInfo.overlayModuleInfos, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, HAP_MODULE_INFO_ATOMIC_SERVICE_MODULE_TYPE,
        hapModuleInfo.atomicServiceModuleType, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, HAP_MODULE_INFO_PRELOADS, hapModuleInfo.preloads, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, HAP_MODULE_INFO_PROXY_DATAS, hapModuleInfo.proxyDatas, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_BUILD_HASH, hapModuleInfo.buildHash, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, HAP_MODULE_INFO_ISOLATION_MODE, hapModuleInfo.isolationMode, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, HAP_MODULE_INFO_AOT_COMPILE_STATUS, hapModuleInfo.aotCompileStatus, false,
        parseResult);
    GetBoolValueIfFindKey(jsonObject, HAP_MODULE_INFO_COMPRESS_NATIVE_LIBS, hapModuleInfo.compressNativeLibs, false,
        parseResult);
    GetStringValuesIfFindKey(jsonObject, HAP_MODULE_INFO_NATIVE_LIBRARY_FILE_NAMES,
        hapModuleInfo.nativeLibraryFileNames, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_FILE_CONTEXT_MENU, hapModuleInfo.fileContextMenu, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_ROUTER_MAP, hapModuleInfo.routerMap, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, HAP_MODULE_INFO_ROUTER_ARRAY, hapModuleInfo.routerArray, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, HAP_MODULE_INFO_APP_ENVIRONMENTS, hapModuleInfo.appEnvironments, false,
        parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_PACKAGE_NAME, hapModuleInfo.packageName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_ABILITY_SRC_ENTRY_DELEGATOR, hapModuleInfo.abilitySrcEntryDelegator,
        false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_ABILITY_STAGE_SRC_ENTRY_DELEGATOR,
        hapModuleInfo.abilityStageSrcEntryDelegator, false, parseResult);
    GetStringValueIfFindKey(jsonObject, HAP_MODULE_INFO_APP_STARTUP, hapModuleInfo.appStartup, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "HapModuleInfo error:%{public}d", parseResult);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
