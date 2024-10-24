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

#ifndef CJ_BUNDLE_MANAGER_UTILS_H
#define CJ_BUNDLE_MANAGER_UTILS_H

#include <cstdint>

#include "bundle_info.h"

namespace OHOS {
namespace FfiContext {
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

RetApplicationInfo ConvertApplicationInfo(AppExecFwk::ApplicationInfo cAppInfo);
}
}

#endif