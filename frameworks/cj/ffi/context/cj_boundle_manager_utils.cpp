/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cj_boundle_manager_utils.h"

#include <cstdint>
#include <string>

namespace OHOS {
namespace FfiContext {

const std::string CONTEXT_DATA_STORAGE_BUNDLE("/data/storage/el1/bundle/");

char *MallocCString(const std::string &origin)
{
    if (origin.empty()) {
        return nullptr;
    }
    auto len = origin.length() + 1;
    char* res = static_cast<char *>(malloc(sizeof(char) * len));
    if (res == nullptr) {
        return nullptr;
    }
    return std::char_traits<char>::copy(res, origin.c_str(), len);
}

void ClearCharPointer(char** ptr, int count)
{
    for (int i = 0; i < count; i++) {
        free(ptr[i]);
        ptr[i] = nullptr;
    }
}

CArrString ConvertArrString(std::vector<std::string> vecStr)
{
    char **retValue = static_cast<char **>(malloc(sizeof(char *) * vecStr.size()));
    if (retValue == nullptr) {
        return {nullptr, 0};
    }

    for (size_t i = 0; i < vecStr.size(); i++) {
        retValue[i] = MallocCString(vecStr[i]);
        if (retValue[i] == nullptr) {
            ClearCharPointer(retValue, i);
            free(retValue);
            return {nullptr, 0};
        }
    }

    return {retValue, vecStr.size()};
}

RetMetadata ConvertMetadata(AppExecFwk::Metadata cdata)
{
    RetMetadata data;
    data.name = MallocCString(cdata.name);
    data.value = MallocCString(cdata.value);
    data.resource = MallocCString(cdata.resource);
    return data;
}

CArrMetadata ConvertArrMetadata(std::vector<AppExecFwk::Metadata> cdata)
{
    CArrMetadata data;
    data.size = static_cast<int64_t>(cdata.size());
    data.head = nullptr;
    if (data.size > 0) {
        RetMetadata *retValue = reinterpret_cast<RetMetadata *>(malloc(sizeof(RetMetadata) * data.size));
        if (retValue != nullptr) {
            for (int32_t i = 0; i < data.size; i++) {
                retValue[i] = ConvertMetadata(cdata[i]);
            }
            data.head = retValue;
        } else {
            return data;
        }
    }
    return data;
}

CArrMoMeta ConvertArrMoMeta(std::map<std::string, std::vector<AppExecFwk::Metadata>> metadata)
{
    CArrMoMeta arrMdata;
    arrMdata.size = static_cast<int64_t>(metadata.size());
    arrMdata.head = nullptr;
    if (arrMdata.size > 0) {
        ModuleMetadata* retValue = reinterpret_cast<ModuleMetadata *>(malloc(sizeof(ModuleMetadata) * arrMdata.size));
        if (retValue != nullptr) {
            int32_t i = 0;
            for (const auto &item : metadata) {
                retValue[i].moduleName = MallocCString(item.first);
                retValue[i++].metadata = ConvertArrMetadata(item.second);
            }
        } else {
            return arrMdata;
        }
        arrMdata.head = retValue;
    }
    return arrMdata;
}

CResource ConvertResource(AppExecFwk::Resource cres)
{
    CResource res;
    res.bundleName = MallocCString(cres.bundleName);
    res.moduleName = MallocCString(cres.moduleName);
    res.id = cres.id;
    return res;
}

RetApplicationInfo ConvertApplicationInfo(AppExecFwk::ApplicationInfo cAppInfo)
{
    RetApplicationInfo appInfo;
    appInfo.name = MallocCString(cAppInfo.name);
    appInfo.description = MallocCString(cAppInfo.description);
    appInfo.descriptionId = cAppInfo.descriptionId;
    appInfo.enabled = cAppInfo.enabled;
    appInfo.label = MallocCString(cAppInfo.label);
    appInfo.labelId = cAppInfo.labelId;
    appInfo.icon = MallocCString(cAppInfo.iconPath);
    appInfo.iconId = cAppInfo.iconId;
    appInfo.process = MallocCString(cAppInfo.process);

    appInfo.permissions = ConvertArrString(cAppInfo.permissions);

    appInfo.codePath = MallocCString(cAppInfo.codePath);

    appInfo.metadataArray = ConvertArrMoMeta(cAppInfo.metadata);

    appInfo.removable = cAppInfo.removable;
    appInfo.accessTokenId = cAppInfo.accessTokenId;
    appInfo.uid = cAppInfo.uid;

    appInfo.iconResource = ConvertResource(cAppInfo.iconResource);
    appInfo.labelResource = ConvertResource(cAppInfo.labelResource);
    appInfo.descriptionResource = ConvertResource(cAppInfo.descriptionResource);

    appInfo.appDistributionType = MallocCString(cAppInfo.appDistributionType);
    appInfo.appProvisionType = MallocCString(cAppInfo.appProvisionType);
    appInfo.systemApp = cAppInfo.isSystemApp;
    appInfo.bundleType = static_cast<int32_t>(cAppInfo.bundleType);
    appInfo.debug = cAppInfo.debug;
    appInfo.dataUnclearable = !cAppInfo.userDataClearable;
    appInfo.cloudFileSyncEnabled = cAppInfo.cloudFileSyncEnabled;
    std::string externalNativeLibraryPath = "";
    if (!cAppInfo.nativeLibraryPath.empty()) {
        externalNativeLibraryPath = CONTEXT_DATA_STORAGE_BUNDLE + cAppInfo.nativeLibraryPath;
    }
    appInfo.nativeLibraryPath = MallocCString(externalNativeLibraryPath);
    appInfo.multiAppMode.multiAppModeType = static_cast<int32_t>(cAppInfo.multiAppMode.multiAppModeType);
    appInfo.multiAppMode.count = cAppInfo.multiAppMode.maxCount;
    appInfo.appIndex = cAppInfo.appIndex;
    appInfo.installSource =  MallocCString(cAppInfo.installSource);
    appInfo.releaseType = MallocCString(cAppInfo.apiReleaseType);
    return appInfo;
}
}
}