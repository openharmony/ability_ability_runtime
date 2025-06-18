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

#include "residentprocessmanagersecond_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "resident_process_manager.h"
#undef private

#include "ability_record.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t U32_AT_SIZE = 4;
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
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    // fuzz for ResidentProcessManager
    auto residentProcessManager = std::make_shared<ResidentProcessManager>();
    std::vector<AppExecFwk::BundleInfo> bundleInfos;
    BundleInfo info;
    int32_t userId;
    FuzzedDataProvider fdp(data, size);
    userId = fdp.ConsumeIntegral<int32_t>();
    size_t arraySize = fdp.ConsumeIntegralInRange<size_t>(0, U32_AT_SIZE);
    for (size_t i = 0; i < arraySize; ++i) {
        GetRandomBundleInfo(fdp, info);
        bundleInfos.emplace_back(info);
    }
    residentProcessManager->StartResidentProcessWithMainElement(bundleInfos, userId);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}