/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "extensionrecordmanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "ability_record.h"
#include "extension_record_factory.h"
#define private public
#define inline
#include "extension_record.h"
#include "extension_record_manager.h"
#define inline
#undef private
#include "ability_fuzz_util.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
} // namespace

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    auto extensionRecordManager = std::make_shared<ExtensionRecordManager>(0);
    int32_t userId;
    int32_t extensionRecordId;
    int32_t pid;
    int32_t hostPid;
    int32_t recordNum;
    std::shared_ptr<AbilityRuntime::ExtensionRecord> record;
    std::shared_ptr<AbilityRuntime::ExtensionRecord> extensionRecord;
    std::shared_ptr<AAFwk::AbilityRecord> abilityRecord;
    std::list<sptr<IRemoteObject>> callerList;
    std::string hostBundleName;
    std::string bundleName;
    std::string process;
    std::string moduleName;
    bool isLoaded;
    AbilityInfo abilityInfo;
    AbilityRequest abilityRequest;
    ExtensionRecordManager::PreLoadUIExtensionMapKey preLoadUIExtensionInfo;
    UIExtensionSessionInfo uiExtensionSessionInfo;
    ElementName element;
    std::vector<std::string> extensionList;
    sptr<AAFwk::SessionInfo> sessionInfo;
    sptr<IRemoteObject> focusedCallerToken;
    sptr<IRemoteObject> token;
    sptr<IRemoteObject> focusToken;
    std::tuple<std::string, std::string, std::string, int32_t> extensionRecordMapKey;

    FuzzedDataProvider fdp(data, size);
    userId = fdp.ConsumeIntegral<int32_t>();
    extensionRecordId = fdp.ConsumeIntegral<int32_t>();
    pid = fdp.ConsumeIntegral<int32_t>();
    hostPid = fdp.ConsumeIntegral<int32_t>();
    recordNum = fdp.ConsumeIntegral<int32_t>();
    hostBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    process = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    isLoaded = fdp.ConsumeBool();
    extensionList = AbilityFuzzUtil::GenerateStringArray(fdp);
    AbilityFuzzUtil::GetRandomAbilityInfo(fdp, abilityInfo);
    AbilityFuzzUtil::GetRandomAbilityRequestInfo(fdp, abilityRequest);
    AbilityFuzzUtil::GenerateElementName(fdp, element);

    extensionRecordManager->GenerateExtensionRecordId(extensionRecordId);
    extensionRecordManager->AddExtensionRecord(extensionRecordId, record);
    extensionRecordManager->RemoveExtensionRecord(extensionRecordId);
    extensionRecordManager->AddExtensionRecordToTerminatedList(extensionRecordId);
    extensionRecordManager->GetExtensionRecord(extensionRecordId, hostBundleName, extensionRecord, isLoaded);
    extensionRecordManager->IsBelongToManager(abilityInfo);
    extensionRecordManager->GetActiveUIExtensionList(pid, extensionList);
    extensionRecordManager->GetActiveUIExtensionList(bundleName, extensionList);
    extensionRecordManager->GetOrCreateExtensionRecord(abilityRequest, hostBundleName, abilityRecord, isLoaded);
    extensionRecordManager->GetAbilityRecordBySessionInfo(sessionInfo);
    extensionRecordManager->IsHostSpecifiedProcessValid(abilityRequest, record, process);
    extensionRecordManager->UpdateProcessName(abilityRequest, record);
    extensionRecordManager->GetHostPidForExtensionId(extensionRecordId, hostPid);
    extensionRecordManager->AddPreloadUIExtensionRecord(abilityRecord);
    extensionRecordManager->RemoveAllPreloadUIExtensionRecord(preLoadUIExtensionInfo);
    extensionRecordManager->IsPreloadExtensionRecord(abilityRequest, hostPid, extensionRecord, isLoaded);
    extensionRecordManager->RemovePreloadUIExtensionRecordById(extensionRecordMapKey, extensionRecordId);
    extensionRecordManager->RemovePreloadUIExtensionRecord(extensionRecordMapKey);
    extensionRecordManager->GetOrCreateExtensionRecordInner(abilityRequest, hostBundleName, extensionRecord, isLoaded);
    extensionRecordManager->SetAbilityProcessName(abilityRequest, abilityRecord, extensionRecord);
    extensionRecordManager->StartAbility(abilityRequest);
    extensionRecordManager->SetCachedFocusedCallerToken(extensionRecordId, focusedCallerToken);
    extensionRecordManager->GetCachedFocusedCallerToken(extensionRecordId);
    extensionRecordManager->GetRootCallerTokenLocked(extensionRecordId, abilityRecord);
    extensionRecordManager->CreateExtensionRecord(abilityRequest, hostBundleName, extensionRecord, hostPid);
    extensionRecordManager->GetUIExtensionRootHostInfo(token);
    extensionRecordManager->GetUIExtensionSessionInfo(token, uiExtensionSessionInfo);
    extensionRecordManager->GetExtensionRecordById(extensionRecordId);
    extensionRecordManager->LoadTimeout(extensionRecordId);
    extensionRecordManager->ForegroundTimeout(extensionRecordId);
    extensionRecordManager->BackgroundTimeout(extensionRecordId);
    extensionRecordManager->TerminateTimeout(extensionRecordId);
    extensionRecordManager->GetCallerTokenList(abilityRecord, callerList);
    extensionRecordManager->IsFocused(extensionRecordId, token, focusToken);
    extensionRecordManager->QueryPreLoadUIExtensionRecord(element, moduleName, hostPid, recordNum);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
