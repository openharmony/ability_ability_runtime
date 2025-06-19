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

#ifndef ABILITY_FUZZ_UTIL_H
#define ABILITY_FUZZ_UTIL_H

#include <fuzzer/FuzzedDataProvider.h>
#include <map>
#include <string>
#include <vector>

#include "auto_startup_info.h"
#include "bundle_info.h"
#include "bundle_user_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace AbilityFuzzUtil {
constexpr size_t STRING_MAX_LENGTH = 128;
std::vector<std::string> GenerateStringArray(FuzzedDataProvider& fdp, size_t arraySizeMax = STRING_MAX_LENGTH,
    size_t stringSize = STRING_MAX_LENGTH)
{
    std::vector<std::string> result;
    size_t arraySize = fdp.ConsumeIntegralInRange<size_t>(0, arraySizeMax);
    result.reserve(arraySize);

    for (size_t i = 0; i < arraySize; ++i) {
        std::string str = fdp.ConsumeRandomLengthString(stringSize);
        result.emplace_back(str);
    }

    return result;
}

void GenerateSignatureInfo(FuzzedDataProvider& fdp, SignatureInfo &signatureInfo)
{
    signatureInfo.appId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    signatureInfo.fingerprint = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    signatureInfo.appIdentifier = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    signatureInfo.certificate = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomAutoStartupInfo(FuzzedDataProvider& fdp, AutoStartupInfo& info)
{
    info.appCloneIndex = fdp.ConsumeIntegral<int32_t>();
    info.userId = fdp.ConsumeIntegral<int32_t>();
    info.retryCount = fdp.ConsumeIntegral<int32_t>();
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.abilityTypeName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.accessTokenId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomBundleInfo(FuzzedDataProvider& fdp, BundleInfo& info)
{
    info.isNewVersion = fdp.ConsumeBool();
    info.isKeepAlive = fdp.ConsumeBool();
    info.singleton = fdp.ConsumeBool();
    info.isPreInstallApp = fdp.ConsumeBool();
    info.isNativeApp = fdp.ConsumeBool();
    info.entryInstallationFree = fdp.ConsumeBool();
    info.isDifferentName = fdp.ConsumeBool();
    info.versionCode = fdp.ConsumeIntegral<uint32_t>();
    info.minCompatibleVersionCode = fdp.ConsumeIntegral<uint32_t>();
    info.compatibleVersion = fdp.ConsumeIntegral<uint32_t>();
    info.targetVersion = fdp.ConsumeIntegral<uint32_t>();
    info.appIndex = fdp.ConsumeIntegral<int32_t>();
    info.minSdkVersion = fdp.ConsumeIntegral<int32_t>();
    info.maxSdkVersion = fdp.ConsumeIntegral<int32_t>();
    info.overlayType = fdp.ConsumeIntegral<int32_t>();
    info.installTime = fdp.ConsumeIntegral<int64_t>();
    info.updateTime = fdp.ConsumeIntegral<int64_t>();
    info.firstInstallTime = fdp.ConsumeIntegral<int64_t>();
    info.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.versionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.vendor = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.releaseType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.mainEntry = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.entryModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.appId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.seInfo = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.jointUserId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    GenerateSignatureInfo(fdp, info.signatureInfo);
    info.oldAppIds = GenerateStringArray(fdp);
    info.hapModuleNames = GenerateStringArray(fdp);
    info.moduleNames = GenerateStringArray(fdp);
    info.modulePublicDirs = GenerateStringArray(fdp);
    info.moduleDirs = GenerateStringArray(fdp);
    info.moduleResPaths = GenerateStringArray(fdp);
    info.reqPermissions = GenerateStringArray(fdp);
    info.defPermissions = GenerateStringArray(fdp);
}
}  // namespace AbilityFuzzUtil
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // BMS_FUZZTEST_UTIL_H