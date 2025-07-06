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

#include "uriutils_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "uri_utils.h"
#undef private

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::string bundleName;
    std::string identifier;
    std::string callerName;
    std::string targetBundleName;
    std::string targetPkg;
    std::string callerBundleName;
    std::string oriUri;
    std::string eventType;
    Want want;
    bool checkResult;
    bool isSandboxApp;
    int32_t appIndex;
    int32_t apiVersion;
    int32_t collaboratorType;
    uint32_t tokenId;
    uint32_t callerTokenId;
    uint32_t fromTokenId;
    uint32_t flag;
    uint32_t initiatorTokenId;
    std::vector<Uri> permissionedUris;
    std::vector<std::string> uriVec;
    // std::vector<bool> checkResults;
    AbilityRequest abilityRequest;
    FuzzedDataProvider fdp(data, size);
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    identifier = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    callerName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    targetBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    targetPkg = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    callerBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    oriUri = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    eventType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    checkResult = fdp.ConsumeBool();
    isSandboxApp = fdp.ConsumeBool();
    appIndex = fdp.ConsumeIntegral<int32_t>();
    apiVersion = fdp.ConsumeIntegral<int32_t>();
    collaboratorType = fdp.ConsumeIntegral<int32_t>();
    tokenId = fdp.ConsumeIntegral<uint32_t>();
    callerTokenId = fdp.ConsumeIntegral<uint32_t>();
    fromTokenId = fdp.ConsumeIntegral<uint32_t>();
    flag = fdp.ConsumeIntegral<uint32_t>();
    initiatorTokenId = fdp.ConsumeIntegral<uint32_t>();
    UriUtils::GetInstance().IsInAncoAppIdentifier(bundleName);
    UriUtils::GetInstance().CheckIsInAncoAppIdentifier(identifier, bundleName);
    identifier = "";
    UriUtils::GetInstance().CheckIsInAncoAppIdentifier(identifier, bundleName);
    UriUtils::GetInstance().GetUriListFromWantDms(want);
    UriUtils::GetInstance().ProcessWantUri(checkResult, apiVersion, want, permissionedUris);
    UriUtils::GetInstance().GetCallerNameAndApiVersion(tokenId, callerName, apiVersion);
    UriUtils::GetInstance().GetUriListFromWant(want, uriVec);
    UriUtils::GetInstance().IsGrantUriPermissionFlag(want);
    ExtensionAbilityType extensionAbilityType = ExtensionAbilityType::SERVICE;
    UriUtils::GetInstance().IsServiceExtensionType(extensionAbilityType);
    extensionAbilityType = ExtensionAbilityType::UI_SERVICE;
    UriUtils::GetInstance().IsServiceExtensionType(extensionAbilityType);
    UriUtils::GetInstance().IsDmsCall(fromTokenId);
    UriUtils::GetInstance().GrantDmsUriPermission(want, callerTokenId, targetBundleName, appIndex);
    UriUtils::GetInstance().GrantShellUriPermission(uriVec, flag, targetPkg, appIndex);
    UriUtils::GetInstance().CheckUriPermission(callerTokenId, want);
    UriUtils::GetInstance().GrantUriPermission(uriVec, flag, targetBundleName, appIndex, initiatorTokenId);
    UriUtils::GetInstance().IsSandboxApp(tokenId);
    UriUtils::GetInstance().GrantUriPermission(want, targetBundleName, appIndex, isSandboxApp,
        callerTokenId, collaboratorType);
    UriUtils::GetInstance().ProcessUDMFKey(want);
    UriUtils::GetInstance().PublishFileOpenEvent(want);
    UriUtils::GetInstance().GrantUriPermissionForServiceExtension(abilityRequest);
    UriUtils::GetInstance().GrantUriPermissionForUIOrServiceExtension(abilityRequest);
    UriUtils::GetInstance().SendGrantUriPermissionEvent(callerBundleName, targetBundleName, oriUri,
        apiVersion, eventType);
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