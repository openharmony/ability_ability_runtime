/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_CJ_ABILITY_STAGE_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_CJ_ABILITY_STAGE_CONTEXT_H

#include <cstdint>

#include "cj_common_ffi.h"
#include "cj_utils_ffi.h"
#include "configuration.h"
#include "ffi_remote_data.h"
#include "hap_module_info.h"

namespace OHOS {
namespace AbilityRuntime {

class Context;

struct RetMetadata {
    char* name;
    char* value;
    char* resource;
};

struct CArrMetadata {
    RetMetadata* head;
    int64_t size;
};

struct ModuleMetadata {
    char* moduleName;
    CArrMetadata metadata;
};

struct CArrMoMeta {
    ModuleMetadata* head;
    int64_t size;
};

struct CResource {
    char* bundleName;
    char* moduleName;
    uint32_t id;
};

struct CArrString {
    char** head;
    int64_t size;
};

struct MultiAppMode {
    uint8_t multiAppModeType;
    int32_t count;
};

struct RetApplicationInfo {
    char* name;
    char* description;
    uint32_t descriptionId;
    bool enabled;
    char* label;
    uint32_t labelId;
    char* icon;
    uint32_t iconId;
    char* process;
    CArrString permissions;
    char* codePath;
    CArrMoMeta metadataArray;
    bool removable;
    uint32_t accessTokenId;
    int32_t uid;
    CResource iconResource;
    CResource labelResource;
    CResource descriptionResource;
    char* appDistributionType;
    char* appProvisionType;
    bool systemApp;
    int32_t bundleType;
    bool debug;
    bool dataUnclearable;
    bool cloudFileSyncEnabled;
    char* nativeLibraryPath;
    MultiAppMode multiAppMode;
    int32_t appIndex;
    char* installSource;
    char* releaseType;
};

struct CArrInt32 {
    int32_t* head;
    int64_t size;
};

struct RetWindowSize {
    double maxWindowRatio;
    double minWindowRatio;
    uint32_t maxWindowWidth;
    uint32_t minWindowWidth;
    uint32_t maxWindowHeight;
    uint32_t minWindowHeight;
};

struct RetSkillUri {
    char* scheme;
    char* host;
    char* port;
    char* path;
    char* pathStartWith;
    char* pathRegex;
    char* type;
    char* utd;
    int32_t maxFileSupported;
    char* linkFeature;
};

struct RetCArrSkillUri {
    RetSkillUri* head;
    int64_t size;
};

struct RetSkill {
    CArrString actions;
    CArrString entities;
    RetCArrSkillUri uris;
    bool domainVerify;
};

struct RetCArrSkill {
    RetSkill* head;
    int64_t size;
};

struct RetAbilityInfo {
    char* bundleName;
    char* moduleName;
    char* name;
    char* label;
    uint32_t labelId;
    char* description;
    uint32_t descriptionId;
    char* icon;
    uint32_t iconId;
    char* process;
    bool exported;
    int32_t orientation;
    int32_t launchType;
    CArrString permissions;
    CArrString deviceTypes;
    RetApplicationInfo applicationInfo;
    CArrMetadata metadata;
    bool enabled;
    CArrInt32 supportWindowModes;
    RetWindowSize windowSize;
    bool excludeFromDock;
    RetCArrSkill skills;
    int32_t appIndex;
};

struct CArrRetAbilityInfo {
    RetAbilityInfo* head;
    int64_t size;
};

struct RetExtensionAbilityInfo {
    char* bundleName;
    char* moduleName;
    char* name;
    uint32_t labelId;
    uint32_t descriptionId;
    uint32_t iconId;
    bool exported;
    int32_t extensionAbilityType;
    CArrString permissions;
    RetApplicationInfo applicationInfo;
    CArrMetadata metadata;
    bool enabled;
    char* readPermission;
    char* writePermission;
    char* extensionAbilityTypeName;
    RetCArrSkill skills;
    int32_t appIndex;
};

struct CArrRetExtensionAbilityInfo {
    RetExtensionAbilityInfo* head;
    int64_t size;
};

struct RetPreloadItem {
    char* moduleName;
};

struct CArrRetPreloadItem {
    RetPreloadItem* head;
    int64_t size;
};

struct RetDependency {
    char* bundleName;
    char* moduleName;
    uint32_t versionCode;
};

struct CArrRetDependency {
    RetDependency* head;
    int64_t size;
};

struct CDataItem {
    char* key;
    char* value;
};

struct CArrDataItem {
    CDataItem* head;
    int64_t size;
};

struct CRouterItem {
    char* name;
    char* pageSourceFile;
    char* buildFunction;
    CArrDataItem data;
    char* customData;
};

struct CArrRouterItem {
    CRouterItem* head;
    int64_t size;
};

struct RetHapModuleInfo {
    char* name;
    char* icon;
    uint32_t iconId;
    char* label;
    uint32_t labelId;
    char* description;
    uint32_t descriptionId;
    char* mainElementName;
    CArrRetAbilityInfo abilitiesInfo;
    CArrRetExtensionAbilityInfo extensionAbilitiesInfo;
    CArrMetadata metadata;
    CArrString deviceTypes;
    bool installationFree;
    char* hashValue;
    int32_t moduleType;
    CArrRetPreloadItem preloads;
    CArrRetDependency dependencies;
    char* fileContextMenuConfig;
    CArrRouterItem routerMap;
    char* codePath;
    char* nativeLibraryPath;
};

class CJAbilityStageContext : public FFI::FFIData {
public:
    explicit CJAbilityStageContext(std::weak_ptr<AbilityRuntime::Context> &&abilityStageContext)
        :abilityStageContext_(std::move(abilityStageContext)){};

    std::shared_ptr<AppExecFwk::HapModuleInfo> GetHapModuleInfo();
    RetHapModuleInfo GetRetHapModuleInfo();
    CConfiguration GetConfiguration();
    std::shared_ptr<Context> GetContext()
    {
        return abilityStageContext_.lock();
    }

private:
    std::weak_ptr<AbilityRuntime::Context> abilityStageContext_;
};

CConfiguration ConvertConfiguration(const AppExecFwk::Configuration &configuration);
char *MallocCString(const std::string &origin);
}
}
#endif //OHOS_ABILITY_RUNTIME_CJ_ABILITY_STAGE_CONTEXT_H