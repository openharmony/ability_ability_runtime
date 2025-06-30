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
#include "extract_insight_intent_profile.h"
#include "keep_alive_process_manager.h"

namespace OHOS {
namespace AppExecFwk {
namespace AbilityFuzzUtil {
constexpr size_t CODE_TWO = 2;
constexpr size_t CODE_MAX = 99;
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

AppExecFwk::ElementName GenerateElementName(FuzzedDataProvider& fdp, AppExecFwk::ElementName &elementName)
{
    std::string deviceId;
    std::string bundleName;
    std::string abilityName;
    std::string moduleName;
    deviceId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    AppExecFwk::ElementName name(deviceId, bundleName, abilityName, moduleName);

    return name;
}

void GetRandomExtractInsightIntentGenericInfo(FuzzedDataProvider& fdp, ExtractInsightIntentGenericInfo& info)
{
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.intentName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.displayName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.decoratorType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomInsightIntentInfoForQuery(FuzzedDataProvider& fdp, InsightIntentInfoForQuery& info)
{
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.intentName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.domain = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.intentVersion = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.displayName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.displayDescription = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.schema = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.llmDescription = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.intentType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.parameters = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.result = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.keywords = GenerateStringArray(fdp);
}

void GetRandomExtractInsightIntentInfo(FuzzedDataProvider& fdp, ExtractInsightIntentInfo& info)
{
    info.decoratorFile = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.decoratorClass = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.displayDescription = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.domain = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.intentVersion = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.schema = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.llmDescription = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.result = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.example = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.keywords = GenerateStringArray(fdp);
}

void GetRandomInsightIntentExecuteParam(FuzzedDataProvider& fdp, InsightIntentExecuteParam& info)
{
    info.executeMode_ = fdp.ConsumeIntegral<int32_t>();
    info.displayId_ = fdp.ConsumeIntegral<int32_t>();
    info.flags_ = fdp.ConsumeIntegral<int32_t>();
    info.insightIntentId_ = fdp.ConsumeIntegral<uint64_t>();
    info.bundleName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.abilityName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.insightIntentName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.uris_ = GenerateStringArray(fdp);
    info.decoratorType_ = fdp.ConsumeIntegral<int8_t>();
    info.srcEntrance_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.className_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.methodName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.methodParams_ = GenerateStringArray(fdp);
    info.pagePath_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.navigationId_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.navDestinationName_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
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

void GetRandomKeepAliveInfo(FuzzedDataProvider& fdp, KeepAliveInfo& info)
{
    info.userId = fdp.ConsumeIntegral<int32_t>();
    info.setterId = fdp.ConsumeIntegral<int32_t>();
    info.appType = static_cast<KeepAliveAppType>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_TWO));
    info.setter = static_cast<KeepAliveSetter>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_TWO));
    info.policy = static_cast<KeepAlivePolicy>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_TWO));
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomKeepAliveAbilityInfo(FuzzedDataProvider& fdp, KeepAliveAbilityInfo& info)
{
    info.userId = fdp.ConsumeIntegral<int32_t>();
    info.appCloneIndex = fdp.ConsumeIntegral<int32_t>();
    info.uid = fdp.ConsumeIntegral<int32_t>();
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

void GetRandomKeepAliveAppInfo(FuzzedDataProvider& fdp, AppInfo& info)
{
    info.processName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.state = static_cast<AppState>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_TWO));
    info.pid = fdp.ConsumeIntegral<uint32_t>();
    info.appIndex = fdp.ConsumeIntegral<int32_t>();
    info.instanceKey = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}
}  // namespace AbilityFuzzUtil
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // BMS_FUZZTEST_UTIL_H