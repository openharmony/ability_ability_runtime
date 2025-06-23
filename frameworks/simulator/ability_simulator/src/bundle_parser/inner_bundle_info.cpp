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

#include "inner_bundle_info.h"

#include <algorithm>
#include <deque>
#include <regex>
#include <unistd.h>

#include "common_profile.h"
#include "hilog_tag_wrapper.h"
#include "json_serializer.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string APP_TYPE = "appType";
const std::string UID = "uid";
const std::string GID = "gid";
const std::string BUNDLE_STATUS = "bundleStatus";
const std::string BASE_APPLICATION_INFO = "baseApplicationInfo";
const std::string BASE_BUNDLE_INFO = "baseBundleInfo";
const std::string BASE_ABILITY_INFO = "baseAbilityInfos";
const std::string INNER_MODULE_INFO = "innerModuleInfos";
const std::string USER_ID = "userId_";
const std::string APP_FEATURE = "appFeature";
const std::string CAN_UNINSTALL = "canUninstall";
const std::string NAME = "name";
const std::string MODULE_PACKAGE = "modulePackage";
const std::string MODULE_PATH = "modulePath";
const std::string MODULE_NAME = "moduleName";
const std::string MODULE_DESCRIPTION = "description";
const std::string MODULE_DESCRIPTION_ID = "descriptionId";
const std::string MODULE_ICON = "icon";
const std::string MODULE_ICON_ID = "iconId";
const std::string MODULE_LABEL = "label";
const std::string MODULE_LABEL_ID = "labelId";
const std::string MODULE_DESCRIPTION_INSTALLATION_FREE = "installationFree";
const std::string MODULE_IS_REMOVABLE = "isRemovable";
const std::string MODULE_UPGRADE_FLAG = "upgradeFlag";
const std::string MODULE_IS_ENTRY = "isEntry";
const std::string MODULE_METADATA = "metaData";
const std::string MODULE_COLOR_MODE = "colorMode";
const std::string MODULE_DISTRO = "distro";
const std::string MODULE_REQ_CAPABILITIES = "reqCapabilities";
const std::string MODULE_DATA_DIR = "moduleDataDir";
const std::string MODULE_RES_PATH = "moduleResPath";
const std::string MODULE_HAP_PATH = "hapPath";
const std::string MODULE_ABILITY_KEYS = "abilityKeys";
const std::string MODULE_MAIN_ABILITY = "mainAbility";
const std::string MODULE_ENTRY_ABILITY_KEY = "entryAbilityKey";
const std::string MODULE_DEPENDENCIES = "dependencies";
const std::string MODULE_IS_LIB_ISOLATED = "isLibIsolated";
const std::string MODULE_NATIVE_LIBRARY_PATH = "nativeLibraryPath";
const std::string MODULE_CPU_ABI = "cpuAbi";
const std::string NEW_BUNDLE_NAME = "newBundleName";
const std::string MODULE_SRC_PATH = "srcPath";
const std::string MODULE_HASH_VALUE = "hashValue";
const std::string SCHEME_SEPARATOR = "://";
const std::string PORT_SEPARATOR = ":";
const std::string PATH_SEPARATOR = "/";
const std::string PARAM_SEPARATOR = "?";
const std::string INSTALL_MARK = "installMark";
const std::string TYPE_WILDCARD = "*/*";
const std::string MODULE_PROCESS = "process";
const std::string MODULE_SRC_ENTRANCE = "srcEntrance";
const std::string MODULE_DEVICE_TYPES = "deviceTypes";
const std::string MODULE_VIRTUAL_MACHINE = "virtualMachine";
const std::string MODULE_UI_SYNTAX = "uiSyntax";
const std::string MODULE_PAGES = "pages";
const std::string MODULE_META_DATA = "metadata";
const std::string MODULE_EXTENSION_KEYS = "extensionKeys";
const std::string MODULE_IS_MODULE_JSON = "isModuleJson";
const std::string MODULE_IS_STAGE_BASED_MODEL = "isStageBasedModel";
const std::string BUNDLE_IS_NEW_VERSION = "isNewVersion";
const std::string BUNDLE_IS_NEED_UPDATE = "upgradeFlag";
const std::string BUNDLE_BASE_EXTENSION_INFOS = "baseExtensionInfos";
const std::string ALLOWED_ACLS = "allowedAcls";
const std::string META_DATA_SHORTCUTS_NAME = "ohos.ability.shortcuts";
const std::string APP_INDEX = "appIndex";
const std::string BUNDLE_IS_SANDBOX_APP = "isSandboxApp";
const std::string BUNDLE_SANDBOX_PERSISTENT_INFO = "sandboxPersistentInfo";
const std::string MODULE_COMPILE_MODE = "compileMode";
const std::string BUNDLE_HQF_INFOS = "hqfInfos";
const std::string MODULE_TARGET_MODULE_NAME = "targetModuleName";
const std::string MODULE_TARGET_PRIORITY = "targetPriority";
const std::string MODULE_ATOMIC_SERVICE_MODULE_TYPE = "atomicServiceModuleType";
const std::string MODULE_PRELOADS = "preloads";
const std::string MODULE_BUNDLE_TYPE = "bundleType";
const std::string MODULE_VERSION_CODE = "versionCode";
const std::string MODULE_VERSION_NAME = "versionName";
const std::string MODULE_PROXY_DATAS = "proxyDatas";
const std::string MODULE_BUILD_HASH = "buildHash";
const std::string MODULE_ISOLATION_MODE = "isolationMode";
const std::string MODULE_COMPRESS_NATIVE_LIBS = "compressNativeLibs";
const std::string MODULE_NATIVE_LIBRARY_FILE_NAMES = "nativeLibraryFileNames";
const std::string MODULE_AOT_COMPILE_STATUS = "aotCompileStatus";
const std::string DATA_GROUP_INFOS = "dataGroupInfos";
const std::map<std::string, IsolationMode> ISOLATION_MODE_MAP = {
    {"isolationOnly", IsolationMode::ISOLATION_ONLY},
    {"nonisolationOnly", IsolationMode::NONISOLATION_ONLY},
    {"isolationFirst", IsolationMode::ISOLATION_FIRST},
};
const std::string NATIVE_LIBRARY_PATH_SYMBOL = "!/";

const std::string STR_PHONE = "phone";
const std::string STR_DEFAULT = "default";

const std::string OVERLAY_TYPE = "overlayType";

inline CompileMode ConvertCompileMode(const std::string &compileMode)
{
    if (compileMode == Profile::COMPILE_MODE_ES_MODULE) {
        return CompileMode::ES_MODULE;
    } else {
        return CompileMode::JS_BUNDLE;
    }
}
} // namespace

InnerBundleInfo::InnerBundleInfo()
{
    baseApplicationInfo_ = std::make_shared<ApplicationInfo>();
    if (baseApplicationInfo_ == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "null baseApplicationInfo_");
    }
    baseBundleInfo_ = std::make_shared<BundleInfo>();
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "instance created");
}

InnerBundleInfo &InnerBundleInfo::operator=(const InnerBundleInfo &info)
{
    if (this == &info) {
        return *this;
    }
    this->appType_ = info.appType_;
    this->userId_ = info.userId_;
    this->bundleStatus_ = info.bundleStatus_;
    this->appFeature_ = info.appFeature_;
    this->allowedAcls_ = info.allowedAcls_;
    this->appIndex_ = info.appIndex_;
    this->isSandboxApp_ = info.isSandboxApp_;
    this->currentPackage_ = info.currentPackage_;
    this->onlyCreateBundleUser_ = info.onlyCreateBundleUser_;
    this->innerModuleInfos_ = info.innerModuleInfos_;
    this->baseAbilityInfos_ = info.baseAbilityInfos_;
    this->isNewVersion_ = info.isNewVersion_;
    this->baseExtensionInfos_= info.baseExtensionInfos_;
    this->baseApplicationInfo_ = std::make_shared<ApplicationInfo>();
    if (info.baseApplicationInfo_ != nullptr) {
        *(this->baseApplicationInfo_) = *(info.baseApplicationInfo_);
    }
    this->provisionMetadatas_ = info.provisionMetadatas_;
    this->baseBundleInfo_ = std::make_shared<BundleInfo>();
    if (info.baseBundleInfo_ != nullptr) {
        *(this->baseBundleInfo_) = *(info.baseBundleInfo_);
    }
    this->overlayType_ = info.overlayType_;
    return *this;
}

InnerBundleInfo::~InnerBundleInfo()
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "instance destroyed");
}

bool to_json(cJSON *&jsonObject, const Distro &distro)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddBoolToObject(jsonObject, ProfileReader::BUNDLE_MODULE_PROFILE_KEY_DELIVERY_WITH_INSTALL,
        distro.deliveryWithInstall);
    cJSON_AddStringToObject(jsonObject, ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_NAME,
        distro.moduleName.c_str());
    cJSON_AddStringToObject(jsonObject, ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_TYPE,
        distro.moduleType.c_str());
    cJSON_AddBoolToObject(jsonObject, ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_INSTALLATION_FREE,
        distro.installationFree);
    return true;
}

bool to_json(cJSON *&jsonObject, const Dependency &dependency)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddStringToObject(jsonObject, Profile::DEPENDENCIES_MODULE_NAME, dependency.moduleName.c_str());
    cJSON_AddStringToObject(jsonObject, Profile::DEPENDENCIES_BUNDLE_NAME, dependency.bundleName.c_str());
    cJSON_AddNumberToObject(jsonObject, Profile::APP_VERSION_CODE, static_cast<double>(dependency.versionCode));
    return true;
}

bool to_json(cJSON *&jsonObject, const InnerModuleInfo &info)
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }

    cJSON_AddStringToObject(jsonObject, NAME.c_str(), info.name.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_PACKAGE.c_str(), info.modulePackage.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_NAME.c_str(), info.moduleName.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_PATH.c_str(), info.modulePath.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_DATA_DIR.c_str(), info.moduleDataDir.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_RES_PATH.c_str(), info.moduleResPath.c_str());
    cJSON_AddBoolToObject(jsonObject, MODULE_IS_ENTRY.c_str(), info.isEntry);

    cJSON *metaDataItem = nullptr;
    if (!to_json(metaDataItem, info.metaData)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json metaData failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, MODULE_METADATA.c_str(), metaDataItem);

    cJSON_AddNumberToObject(jsonObject, MODULE_COLOR_MODE.c_str(), static_cast<double>(info.colorMode));

    cJSON *distroItem = nullptr;
    if (!to_json(distroItem, info.distro)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json distro failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, MODULE_DISTRO.c_str(), distroItem);

    cJSON_AddStringToObject(jsonObject, MODULE_DESCRIPTION.c_str(), info.description.c_str());
    cJSON_AddNumberToObject(jsonObject, MODULE_DESCRIPTION_ID.c_str(), static_cast<double>(info.descriptionId));
    cJSON_AddStringToObject(jsonObject, MODULE_ICON.c_str(), info.icon.c_str());
    cJSON_AddNumberToObject(jsonObject, MODULE_ICON_ID.c_str(), static_cast<double>(info.iconId));
    cJSON_AddStringToObject(jsonObject, MODULE_LABEL.c_str(), info.label.c_str());
    cJSON_AddNumberToObject(jsonObject, MODULE_LABEL_ID.c_str(), static_cast<double>(info.labelId));
    cJSON_AddBoolToObject(jsonObject, MODULE_DESCRIPTION_INSTALLATION_FREE.c_str(), info.installationFree);

    cJSON *isRemovableItem = nullptr;
    if (!to_json(isRemovableItem, info.isRemovable)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json isRemovable failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, MODULE_IS_REMOVABLE.c_str(), isRemovableItem);

    cJSON_AddNumberToObject(jsonObject, MODULE_UPGRADE_FLAG.c_str(), static_cast<double>(info.upgradeFlag));
    
    cJSON *reqCapabilitiesItem = nullptr;
    if (!to_json(reqCapabilitiesItem, info.reqCapabilities)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json reqCapabilities failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, MODULE_REQ_CAPABILITIES.c_str(), reqCapabilitiesItem);

    cJSON *abilityKeysItem = nullptr;
    if (!to_json(abilityKeysItem, info.abilityKeys)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json abilityKeys failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, MODULE_ABILITY_KEYS.c_str(), abilityKeysItem);

    cJSON_AddStringToObject(jsonObject, MODULE_MAIN_ABILITY.c_str(), info.mainAbility.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_ENTRY_ABILITY_KEY.c_str(), info.entryAbilityKey.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_SRC_PATH.c_str(), info.srcPath.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_HASH_VALUE.c_str(), info.hashValue.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_PROCESS.c_str(), info.process.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_SRC_ENTRANCE.c_str(), info.srcEntrance.c_str());

    cJSON *deviceTypesItem = nullptr;
    if (!to_json(deviceTypesItem, info.deviceTypes)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json deviceTypes failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, MODULE_DEVICE_TYPES.c_str(), deviceTypesItem);

    cJSON_AddStringToObject(jsonObject, MODULE_VIRTUAL_MACHINE.c_str(), info.virtualMachine.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_UI_SYNTAX.c_str(), info.uiSyntax.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_PAGES.c_str(), info.pages.c_str());

    cJSON *metadataItem = nullptr;
    if (!to_json(metadataItem, info.metadata)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json metadata failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, MODULE_META_DATA.c_str(), metadataItem);

    cJSON *extensionKeysItem = nullptr;
    if (!to_json(extensionKeysItem, info.extensionKeys)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json extensionKeys failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, MODULE_EXTENSION_KEYS.c_str(), extensionKeysItem);

    cJSON_AddBoolToObject(jsonObject, MODULE_IS_MODULE_JSON.c_str(), info.isModuleJson);
    cJSON_AddBoolToObject(jsonObject, MODULE_IS_STAGE_BASED_MODEL.c_str(), info.isStageBasedModel);

    cJSON *dependenciesItem = nullptr;
    if (!to_json(dependenciesItem, info.dependencies)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json dependencies failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, MODULE_DEPENDENCIES.c_str(), dependenciesItem);

    cJSON_AddBoolToObject(jsonObject, MODULE_IS_LIB_ISOLATED.c_str(), info.isLibIsolated);
    cJSON_AddStringToObject(jsonObject, MODULE_NATIVE_LIBRARY_PATH.c_str(), info.nativeLibraryPath.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_CPU_ABI.c_str(), info.cpuAbi.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_HAP_PATH.c_str(), info.hapPath.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_COMPILE_MODE.c_str(), info.compileMode.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_TARGET_MODULE_NAME.c_str(), info.targetModuleName.c_str());
    cJSON_AddNumberToObject(jsonObject, MODULE_TARGET_PRIORITY.c_str(), static_cast<double>(info.targetPriority));
    cJSON_AddNumberToObject(jsonObject, MODULE_ATOMIC_SERVICE_MODULE_TYPE.c_str(),
        static_cast<double>(info.atomicServiceModuleType));

    cJSON *preloadsItem = nullptr;
    if (!to_json(preloadsItem, info.preloads)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json preloads failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, MODULE_PRELOADS.c_str(), preloadsItem);

    cJSON_AddNumberToObject(jsonObject, MODULE_BUNDLE_TYPE.c_str(), static_cast<double>(info.bundleType));
    cJSON_AddNumberToObject(jsonObject, MODULE_VERSION_CODE.c_str(), static_cast<double>(info.versionCode));
    cJSON_AddStringToObject(jsonObject, MODULE_VERSION_NAME.c_str(), info.versionName.c_str());

    cJSON *proxyDatasItem = nullptr;
    if (!to_json(proxyDatasItem, info.proxyDatas)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json proxyDatas failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, MODULE_PROXY_DATAS.c_str(), proxyDatasItem);

    cJSON_AddStringToObject(jsonObject, MODULE_BUILD_HASH.c_str(), info.buildHash.c_str());
    cJSON_AddStringToObject(jsonObject, MODULE_ISOLATION_MODE.c_str(), info.isolationMode.c_str());
    cJSON_AddBoolToObject(jsonObject, MODULE_COMPRESS_NATIVE_LIBS.c_str(), info.compressNativeLibs);

    cJSON *nativeLibraryFileNamesItem = nullptr;
    if (!to_json(nativeLibraryFileNamesItem, info.nativeLibraryFileNames)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json nativeLibraryFileNames failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, MODULE_NATIVE_LIBRARY_FILE_NAMES.c_str(), nativeLibraryFileNamesItem);

    cJSON_AddNumberToObject(jsonObject, MODULE_AOT_COMPILE_STATUS.c_str(), static_cast<double>(info.aotCompileStatus));
    return true;
}

bool InnerBundleInfo::ToJson(cJSON *&jsonObject) const
{
    jsonObject = cJSON_CreateObject();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json object failed");
        return false;
    }
    cJSON_AddNumberToObject(jsonObject, APP_TYPE.c_str(), static_cast<double>(appType_));
    cJSON_AddNumberToObject(jsonObject, BUNDLE_STATUS.c_str(), static_cast<double>(bundleStatus_));

    cJSON *allowedAclsItem = nullptr;
    if (!to_json(allowedAclsItem, allowedAcls_)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json allowedAcls failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, ALLOWED_ACLS.c_str(), allowedAclsItem);

    cJSON *baseApplicationInfoItem = nullptr;
    if (!to_json(baseApplicationInfoItem, *baseApplicationInfo_)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json baseApplicationInfo failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BASE_APPLICATION_INFO.c_str(), baseApplicationInfoItem);

    cJSON *baseBundleInfoItem = nullptr;
    if (!to_json(baseBundleInfoItem, *baseBundleInfo_)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json baseBundleInfo failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BASE_BUNDLE_INFO.c_str(), baseBundleInfoItem);

    cJSON *baseAbilityInfosItem = nullptr;
    if (!to_json(baseAbilityInfosItem, baseAbilityInfos_)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json baseAbilityInfos failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BASE_ABILITY_INFO.c_str(), baseAbilityInfosItem);

    cJSON *innerModuleInfosItem = nullptr;
    if (!to_json(innerModuleInfosItem, innerModuleInfos_)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json innerModuleInfos failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, INNER_MODULE_INFO.c_str(), innerModuleInfosItem);

    cJSON_AddNumberToObject(jsonObject, USER_ID.c_str(), static_cast<double>(userId_));
    cJSON_AddStringToObject(jsonObject, APP_FEATURE.c_str(), appFeature_.c_str());
    cJSON_AddBoolToObject(jsonObject, BUNDLE_IS_NEW_VERSION.c_str(), isNewVersion_);

    cJSON *baseExtensionInfosItem = nullptr;
    if (!to_json(baseExtensionInfosItem, baseExtensionInfos_)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json baseExtensionInfos failed");
        cJSON_Delete(jsonObject);
        return false;
    }
    cJSON_AddItemToObject(jsonObject, BUNDLE_BASE_EXTENSION_INFOS.c_str(), baseExtensionInfosItem);

    cJSON_AddNumberToObject(jsonObject, APP_INDEX.c_str(), static_cast<double>(appIndex_));
    cJSON_AddBoolToObject(jsonObject, BUNDLE_IS_SANDBOX_APP.c_str(), isSandboxApp_);
    cJSON_AddNumberToObject(jsonObject, OVERLAY_TYPE.c_str(), static_cast<double>(overlayType_));
    return true;
}

void from_json(const cJSON *jsonObject, InnerModuleInfo &info)
{
    // these are not required fields.
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, NAME, info.name, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_PACKAGE, info.modulePackage, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_NAME, info.moduleName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_PATH, info.modulePath, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_DATA_DIR, info.moduleDataDir, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_HAP_PATH, info.hapPath, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_RES_PATH, info.moduleResPath, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, MODULE_IS_ENTRY, info.isEntry, false, parseResult);
    GetObjectValueIfFindKey(jsonObject, MODULE_METADATA, info.metaData, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, MODULE_COLOR_MODE, info.colorMode, false, parseResult);
    GetObjectValueIfFindKey(jsonObject, MODULE_DISTRO, info.distro, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_DESCRIPTION, info.description, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, MODULE_DESCRIPTION_ID, info.descriptionId, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_ICON, info.icon, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, MODULE_ICON_ID, info.iconId, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_LABEL, info.label, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, MODULE_LABEL_ID, info.labelId, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_MAIN_ABILITY, info.mainAbility, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_ENTRY_ABILITY_KEY, info.entryAbilityKey, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_SRC_PATH, info.srcPath, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_HASH_VALUE, info.hashValue, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, MODULE_DESCRIPTION_INSTALLATION_FREE, info.installationFree, false, parseResult);
    GetBoolValueMapIfFindKey(jsonObject, MODULE_IS_REMOVABLE, info.isRemovable, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, MODULE_UPGRADE_FLAG, info.upgradeFlag, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, MODULE_REQ_CAPABILITIES, info.reqCapabilities, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, MODULE_ABILITY_KEYS, info.abilityKeys, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_PROCESS, info.process, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_SRC_ENTRANCE, info.srcEntrance, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, MODULE_DEVICE_TYPES, info.deviceTypes, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_VIRTUAL_MACHINE, info.virtualMachine, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_UI_SYNTAX, info.uiSyntax, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_PAGES, info.pages, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, MODULE_META_DATA, info.metadata, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, MODULE_EXTENSION_KEYS, info.extensionKeys, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, MODULE_IS_MODULE_JSON, info.isModuleJson, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, MODULE_IS_STAGE_BASED_MODEL, info.isStageBasedModel, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, MODULE_DEPENDENCIES, info.dependencies, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_COMPILE_MODE, info.compileMode, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, MODULE_IS_LIB_ISOLATED, info.isLibIsolated, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_NATIVE_LIBRARY_PATH, info.nativeLibraryPath, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_CPU_ABI, info.cpuAbi, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_TARGET_MODULE_NAME, info.targetModuleName, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, MODULE_TARGET_PRIORITY, info.targetPriority, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, MODULE_ATOMIC_SERVICE_MODULE_TYPE, info.atomicServiceModuleType, false,
        parseResult);
    GetStringValuesIfFindKey(jsonObject, MODULE_PRELOADS, info.preloads, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, MODULE_BUNDLE_TYPE, info.bundleType, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, MODULE_VERSION_CODE, info.versionCode, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_VERSION_NAME, info.versionName, false, parseResult);
    GetObjectValuesIfFindKey(jsonObject, MODULE_PROXY_DATAS, info.proxyDatas, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_BUILD_HASH, info.buildHash, false, parseResult);
    GetStringValueIfFindKey(jsonObject, MODULE_ISOLATION_MODE, info.isolationMode, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, MODULE_COMPRESS_NATIVE_LIBS, info.compressNativeLibs, false, parseResult);
    GetStringValuesIfFindKey(jsonObject, MODULE_NATIVE_LIBRARY_FILE_NAMES, info.nativeLibraryFileNames, false,
        parseResult);
    GetNumberValueIfFindKey(jsonObject, MODULE_AOT_COMPILE_STATUS, info.aotCompileStatus, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "read InnerModuleInfo from database error:%{public}d", parseResult);
    }
}

void from_json(const cJSON *jsonObject, Dependency &dependency)
{
    int32_t parseResult = ERR_OK;
    GetStringValueIfFindKey(jsonObject, Profile::DEPENDENCIES_MODULE_NAME, dependency.moduleName, false, parseResult);
    GetStringValueIfFindKey(jsonObject, Profile::DEPENDENCIES_BUNDLE_NAME, dependency.bundleName, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, Profile::APP_VERSION_CODE, dependency.versionCode, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "Dependency error:%{public}d", parseResult);
    }
}

void from_json(const cJSON *jsonObject, Distro &distro)
{
    TAG_LOGD(AAFwkTag::ABILITY_SIM, "called");
    int32_t parseResult = ERR_OK;
    GetBoolValueIfFindKey(jsonObject, ProfileReader::BUNDLE_MODULE_PROFILE_KEY_DELIVERY_WITH_INSTALL,
        distro.deliveryWithInstall, true, parseResult);
    GetStringValueIfFindKey(jsonObject, ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_NAME, distro.moduleName, true,
        parseResult);
    GetStringValueIfFindKey(jsonObject, ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_TYPE, distro.moduleType, true,
        parseResult);
    // mustFlag decide by distro.moduleType
    GetBoolValueIfFindKey(jsonObject, ProfileReader::BUNDLE_MODULE_PROFILE_KEY_MODULE_INSTALLATION_FREE,
        distro.installationFree, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "Distro error:%{public}d", parseResult);
    }
}

int32_t InnerBundleInfo::FromJson(const cJSON *jsonObject)
{
    int32_t parseResult = ERR_OK;
    GetNumberValueIfFindKey(jsonObject, APP_TYPE, appType_, true, parseResult);
    GetStringValuesIfFindKey(jsonObject, ALLOWED_ACLS, allowedAcls_, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, BUNDLE_STATUS, bundleStatus_, true, parseResult);
    GetObjectValueIfFindKey(jsonObject, BASE_BUNDLE_INFO, *baseBundleInfo_, true, parseResult);
    GetObjectValueIfFindKey(jsonObject, BASE_APPLICATION_INFO, *baseApplicationInfo_, true, parseResult);
    GetObjectValueMapIfFindKey(jsonObject, BASE_ABILITY_INFO, baseAbilityInfos_, true, parseResult);
    GetObjectValueMapIfFindKey(jsonObject, INNER_MODULE_INFO, innerModuleInfos_, true, parseResult);
    GetNumberValueIfFindKey(jsonObject, USER_ID, userId_, true, parseResult);
    GetStringValueIfFindKey(jsonObject, APP_FEATURE, appFeature_, true, parseResult);
    GetBoolValueIfFindKey(jsonObject, BUNDLE_IS_NEW_VERSION, isNewVersion_, false, parseResult);
    GetObjectValueMapIfFindKey(jsonObject, BUNDLE_BASE_EXTENSION_INFOS, baseExtensionInfos_, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, APP_INDEX, appIndex_, false, parseResult);
    GetBoolValueIfFindKey(jsonObject, BUNDLE_IS_SANDBOX_APP, isSandboxApp_, false, parseResult);
    GetNumberValueIfFindKey(jsonObject, OVERLAY_TYPE, overlayType_, false, parseResult);
    if (parseResult != ERR_OK) {
        TAG_LOGE(
            AAFwkTag::ABILITY_SIM, "read InnerBundleInfo from database error:%{public}d", parseResult);
    }
    return parseResult;
}

std::optional<HapModuleInfo> InnerBundleInfo::FindHapModuleInfo(const std::string &modulePackage, int32_t userId) const
{
    auto it = innerModuleInfos_.find(modulePackage);
    if (it == innerModuleInfos_.end()) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "not find module %{public}s", modulePackage.c_str());
        return std::nullopt;
    }
    HapModuleInfo hapInfo;
    hapInfo.name = it->second.name;
    hapInfo.package = it->second.modulePackage;
    hapInfo.moduleName = it->second.moduleName;
    hapInfo.description = it->second.description;
    hapInfo.descriptionId = it->second.descriptionId;
    hapInfo.label = it->second.label;
    hapInfo.labelId = it->second.labelId;
    hapInfo.iconPath = it->second.icon;
    hapInfo.iconId = it->second.iconId;
    hapInfo.mainAbility = it->second.mainAbility;
    hapInfo.srcPath = it->second.srcPath;
    hapInfo.hapPath = it->second.hapPath;
    hapInfo.supportedModes = baseApplicationInfo_->supportedModes;
    hapInfo.reqCapabilities = it->second.reqCapabilities;
    hapInfo.colorMode = it->second.colorMode;
    hapInfo.isRemovable = it->second.isRemovable;
    hapInfo.upgradeFlag = it->second.upgradeFlag;
    hapInfo.isLibIsolated = it->second.isLibIsolated;
    hapInfo.nativeLibraryPath = it->second.nativeLibraryPath;
    hapInfo.cpuAbi = it->second.cpuAbi;

    hapInfo.bundleName = baseApplicationInfo_->bundleName;
    hapInfo.mainElementName = it->second.mainAbility;
    hapInfo.pages = it->second.pages;
    hapInfo.process = it->second.process;
    hapInfo.resourcePath = it->second.moduleResPath;
    hapInfo.srcEntrance = it->second.srcEntrance;
    hapInfo.uiSyntax = it->second.uiSyntax;
    hapInfo.virtualMachine = it->second.virtualMachine;
    hapInfo.deliveryWithInstall = it->second.distro.deliveryWithInstall;
    hapInfo.installationFree = it->second.distro.installationFree;
    hapInfo.isModuleJson = it->second.isModuleJson;
    hapInfo.isStageBasedModel = it->second.isStageBasedModel;
    std::string moduleType = it->second.distro.moduleType;
    if (moduleType == Profile::MODULE_TYPE_ENTRY) {
        hapInfo.moduleType = ModuleType::ENTRY;
    } else if (moduleType == Profile::MODULE_TYPE_FEATURE) {
        hapInfo.moduleType = ModuleType::FEATURE;
    } else if (moduleType == Profile::MODULE_TYPE_SHARED) {
        hapInfo.moduleType = ModuleType::SHARED;
    } else {
        hapInfo.moduleType = ModuleType::UNKNOWN;
    }
    std::string key;
    key.append(".").append(modulePackage).append(".");
    for (const auto &extension : baseExtensionInfos_) {
        if (extension.first.find(key) != std::string::npos) {
            hapInfo.extensionInfos.emplace_back(extension.second);
        }
    }
    hapInfo.metadata = it->second.metadata;
    bool first = false;
    for (auto &ability : baseAbilityInfos_) {
        if (ability.second.name == Constants::APP_DETAIL_ABILITY) {
            continue;
        }
        if (ability.first.find(key) != std::string::npos) {
            if (!first) {
                hapInfo.deviceTypes = ability.second.deviceTypes;
                first = true;
            }
            auto &abilityInfo = hapInfo.abilityInfos.emplace_back(ability.second);
            GetApplicationInfo(ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION |
                ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT, userId,
                abilityInfo.applicationInfo);
        }
    }
    hapInfo.dependencies = it->second.dependencies;
    hapInfo.compileMode = ConvertCompileMode(it->second.compileMode);
    hapInfo.atomicServiceModuleType = it->second.atomicServiceModuleType;
    for (const auto &item : it->second.preloads) {
        PreloadItem preload(item);
        hapInfo.preloads.emplace_back(preload);
    }
    for (const auto &item : it->second.proxyDatas) {
        ProxyData proxyData(item);
        hapInfo.proxyDatas.emplace_back(proxyData);
    }
    hapInfo.buildHash = it->second.buildHash;
    hapInfo.isolationMode = GetIsolationMode(it->second.isolationMode);
    hapInfo.compressNativeLibs = it->second.compressNativeLibs;
    hapInfo.nativeLibraryFileNames = it->second.nativeLibraryFileNames;
    hapInfo.aotCompileStatus = it->second.aotCompileStatus;
    return hapInfo;
}

std::optional<AbilityInfo> InnerBundleInfo::FindAbilityInfo(
    const std::string &moduleName,
    const std::string &abilityName,
    int32_t userId) const
{
    for (const auto &ability : baseAbilityInfos_) {
        auto abilityInfo = ability.second;
        if ((abilityInfo.name == abilityName) &&
            (moduleName.empty() || (abilityInfo.moduleName == moduleName))) {
            GetApplicationInfo(ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION |
                ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT, userId,
                abilityInfo.applicationInfo);
            return abilityInfo;
        }
    }

    return std::nullopt;
}

ErrCode InnerBundleInfo::FindAbilityInfo(
    const std::string &moduleName, const std::string &abilityName, AbilityInfo &info) const
{
    bool isModuleFind = false;
    for (const auto &ability : baseAbilityInfos_) {
        auto abilityInfo = ability.second;
        if ((abilityInfo.moduleName == moduleName)) {
            isModuleFind = true;
            if (abilityInfo.name == abilityName) {
                info = abilityInfo;
                return ERR_OK;
            }
        }
    }
    TAG_LOGE(AAFwkTag::ABILITY_SIM,
        "bundleName:%{public}s not find moduleName:%{public}s, abilityName:%{public}s, isModuleFind:%{public}d",
        GetBundleName().c_str(), moduleName.c_str(), abilityName.c_str(), isModuleFind);
    if (isModuleFind) {
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    } else {
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
}

std::string InnerBundleInfo::ToString() const
{
    cJSON *jsonObject = nullptr;
    if (!ToJson(jsonObject)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ToJson failed");
        return {};
    }
    std::string jsonStr = JsonToString(jsonObject);
    cJSON_Delete(jsonObject);
    return jsonStr;
}

void InnerBundleInfo::GetApplicationInfo(int32_t flags, int32_t userId, ApplicationInfo &appInfo) const
{
    appInfo = *baseApplicationInfo_;

    for (const auto &info : innerModuleInfos_) {
        bool deCompress = info.second.hapPath.empty();
        ModuleInfo moduleInfo;
        moduleInfo.moduleName = info.second.moduleName;
        if (deCompress) {
            moduleInfo.moduleSourceDir = info.second.modulePath;
            appInfo.moduleSourceDirs.emplace_back(info.second.modulePath);
        }
        moduleInfo.preloads = info.second.preloads;
        appInfo.moduleInfos.emplace_back(moduleInfo);
        if (deCompress && info.second.isEntry) {
            appInfo.entryDir = info.second.modulePath;
        }
        if ((static_cast<uint32_t>(flags) & GET_APPLICATION_INFO_WITH_METADATA) == GET_APPLICATION_INFO_WITH_METADATA) {
            bool isModuleJson = info.second.isModuleJson;
            if (!isModuleJson && info.second.metaData.customizeData.size() > 0) {
                appInfo.metaData[info.second.moduleName] = info.second.metaData.customizeData;
            }
            if (isModuleJson && info.second.metadata.size() > 0) {
                appInfo.metadata[info.second.moduleName] = info.second.metadata;
            }
        }
        if ((static_cast<uint32_t>(flags) & GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT) !=
            GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT) {
            appInfo.fingerprint.clear();
        }
    }
    if (!appInfo.permissions.empty()) {
        RemoveDuplicateName(appInfo.permissions);
    }
}

void InnerBundleInfo::RemoveDuplicateName(std::vector<std::string> &name) const
{
    std::sort(name.begin(), name.end());
    auto iter = std::unique(name.begin(), name.end());
    name.erase(iter, name.end());
}

IsolationMode InnerBundleInfo::GetIsolationMode(const std::string &isolationMode) const
{
    auto isolationModeRes = ISOLATION_MODE_MAP.find(isolationMode);
    if (isolationModeRes != ISOLATION_MODE_MAP.end()) {
        return isolationModeRes->second;
    } else {
        return IsolationMode::NONISOLATION_FIRST;
    }
}

void InnerBundleInfo::SetBaseBundleInfo(const BundleInfo &bundleInfo)
{
    *baseBundleInfo_ = bundleInfo;
}
void InnerBundleInfo::SetApplicationBundleType(BundleType type)
{
    baseApplicationInfo_->bundleType = type;
}
bool InnerBundleInfo::SetInnerModuleAtomicPreload(
    const std::string &moduleName, const std::vector<std::string> &preloads)
{
    if (innerModuleInfos_.find(moduleName) == innerModuleInfos_.end()) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "innerBundleInfo does not contain the module");
        return false;
    }
    innerModuleInfos_.at(moduleName).preloads = preloads;
    return true;
}

ErrCode InnerBundleInfo::GetApplicationInfoV9(int32_t flags, int32_t userId, ApplicationInfo &appInfo) const
{
    appInfo = *baseApplicationInfo_;
    for (const auto &info : innerModuleInfos_) {
        bool deCompress = info.second.hapPath.empty();
        ModuleInfo moduleInfo;
        moduleInfo.moduleName = info.second.moduleName;
        if (deCompress) {
            moduleInfo.moduleSourceDir = info.second.modulePath;
            appInfo.moduleSourceDirs.emplace_back(info.second.modulePath);
        }
        moduleInfo.preloads = info.second.preloads;
        appInfo.moduleInfos.emplace_back(moduleInfo);
        if (deCompress && info.second.isEntry) {
            appInfo.entryDir = info.second.modulePath;
        }
        if ((static_cast<uint32_t>(flags) &
                static_cast<uint32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_METADATA)) ==
            static_cast<uint32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_METADATA)) {
            bool isModuleJson = info.second.isModuleJson;
            if (!isModuleJson && info.second.metaData.customizeData.size() > 0) {
                appInfo.metaData[info.second.moduleName] = info.second.metaData.customizeData;
            }
            if (isModuleJson && info.second.metadata.size() > 0) {
                appInfo.metadata[info.second.moduleName] = info.second.metadata;
            }
        }
    }
    if (!appInfo.permissions.empty()) {
        RemoveDuplicateName(appInfo.permissions);
    }
    return ERR_OK;
}

void InnerBundleInfo::ProcessBundleWithHapModuleInfoFlag(
    int32_t flags, BundleInfo &bundleInfo, int32_t userId, int32_t appIndex) const
{
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE)) !=
        static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE)) {
        bundleInfo.hapModuleInfos.clear();
        return;
    }
    for (const auto &info : innerModuleInfos_) {
        auto hapmoduleinfo = FindHapModuleInfo(info.second.modulePackage, userId);
        if (hapmoduleinfo) {
            HapModuleInfo hapModuleInfo = *hapmoduleinfo;
            auto it = innerModuleInfos_.find(info.second.modulePackage);
            if (it == innerModuleInfos_.end()) {
                TAG_LOGE(AAFwkTag::ABILITY_SIM, "not find module %{public}s", info.second.modulePackage.c_str());
            } else {
                hapModuleInfo.hashValue = it->second.hashValue;
            }
            if (hapModuleInfo.hapPath.empty()) {
                hapModuleInfo.moduleSourceDir = info.second.modulePath;
            }
            if ((static_cast<uint32_t>(flags) &
                    static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA)) !=
                static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA)) {
                hapModuleInfo.metadata.clear();
            }
            bundleInfo.hapModuleInfos.emplace_back(hapModuleInfo);
        }
    }
}

void InnerBundleInfo::ProcessBundleFlags(int32_t flags, int32_t userId, BundleInfo &bundleInfo, int32_t appIndex) const
{
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)) ==
        static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION)) {
        if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA)) ==
            static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_METADATA)) {
            GetApplicationInfoV9(static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_METADATA), userId,
                bundleInfo.applicationInfo);
        } else {
            GetApplicationInfoV9(static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT), userId,
                bundleInfo.applicationInfo);
        }
    }
    bundleInfo.applicationInfo.appIndex = appIndex;
    ProcessBundleWithHapModuleInfoFlag(flags, bundleInfo, userId, appIndex);
    if ((static_cast<uint32_t>(flags) &
            static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO)) ==
        static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO)) {
        bundleInfo.signatureInfo.appId = baseBundleInfo_->appId;
        bundleInfo.signatureInfo.fingerprint = baseApplicationInfo_->fingerprint;
        bundleInfo.signatureInfo.certificate = baseBundleInfo_->signatureInfo.certificate;
    }
}

ErrCode InnerBundleInfo::GetBundleInfoV9(int32_t flags, BundleInfo &bundleInfo, int32_t userId, int32_t appIndex) const
{
    bundleInfo = *baseBundleInfo_;
    bundleInfo.overlayType = overlayType_;
    bundleInfo.isNewVersion = isNewVersion_;
    for (const auto &info : innerModuleInfos_) {
        bundleInfo.hapModuleNames.emplace_back(info.second.modulePackage);
        bundleInfo.moduleNames.emplace_back(info.second.moduleName);
        bundleInfo.moduleDirs.emplace_back(info.second.modulePath);
        bundleInfo.modulePublicDirs.emplace_back(info.second.moduleDataDir);
        bundleInfo.moduleResPaths.emplace_back(info.second.moduleResPath);
    }
    ProcessBundleFlags(flags, userId, bundleInfo, appIndex);
    return ERR_OK;
}

ErrCode InnerBundleInfo::GetAppServiceHspInfo(BundleInfo &bundleInfo) const
{
    if (baseApplicationInfo_->bundleType != BundleType::APP_SERVICE_FWK) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "%{public}s is not app service", GetBundleName().c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    bundleInfo = *baseBundleInfo_;
    bundleInfo.applicationInfo = *baseApplicationInfo_;
    for (const auto &info : innerModuleInfos_) {
        if (info.second.distro.moduleType == Profile::MODULE_TYPE_SHARED) {
            auto hapmoduleinfo = FindHapModuleInfo(info.second.modulePackage, Constants::ALL_USERID);
            if (hapmoduleinfo) {
                HapModuleInfo hapModuleInfo = *hapmoduleinfo;
                hapModuleInfo.moduleSourceDir =
                    hapModuleInfo.hapPath.empty() ? info.second.modulePath : hapModuleInfo.moduleSourceDir;
                bundleInfo.hapModuleInfos.emplace_back(hapModuleInfo);
            }
        }
    }
    if (bundleInfo.hapModuleInfos.empty()) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "bundleName:%{public}s no hsp module info",
            baseApplicationInfo_->bundleName.c_str());
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    return ERR_OK;
}

bool InnerBundleInfo::GetSharedBundleInfo(int32_t flags, BundleInfo &bundleInfo) const
{
    bundleInfo = *baseBundleInfo_;
    ProcessBundleWithHapModuleInfoFlag(flags, bundleInfo, Constants::ALL_USERID);
    bundleInfo.applicationInfo = *baseApplicationInfo_;
    return true;
}
} // namespace AppExecFwk
}  // namespace OHOS
