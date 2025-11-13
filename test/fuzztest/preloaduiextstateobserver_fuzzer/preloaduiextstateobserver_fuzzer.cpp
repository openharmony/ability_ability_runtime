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
#include "preloaduiextstateobserver_fuzzer.h"

#define private public
#include "preload_uiext_state_observer.h"
#undef private

#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include "base_extension_record.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr uint8_t ENABLE = 2;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t STRING_MAX_LENGTH = 128;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityRequest.abilityInfo.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    auto abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest);
    std::shared_ptr<AbilityRuntime::ExtensionRecord> extRecord;
    std::weak_ptr<AbilityRuntime::ExtensionRecord> weakExtRecord = extRecord;
    std::shared_ptr<AAFwk::PreLoadUIExtStateObserver> preLoad =
        std::make_shared<AAFwk::PreLoadUIExtStateObserver>(weakExtRecord);
    if (!preLoad) {
        return false;
    }

    AppExecFwk::ProcessData processData;
    processData.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    processData.pid = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    processData.uid = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    processData.hostPid = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    processData.gpuPid = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    processData.renderUid = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    processData.isContinuousTask = fdp.ConsumeBool();
    processData.isKeepAlive = fdp.ConsumeBool();
    processData.isFocused = fdp.ConsumeBool();
    processData.requestProcCode = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    processData.processChangeReason = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    processData.processName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    processData.accessTokenId = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    processData.isTestMode = fdp.ConsumeBool();
    processData.exitReason = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    processData.exitMsg = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    processData.childUid = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    processData.isPreload = fdp.ConsumeBool();
    processData.isPreloadModule = fdp.ConsumeBool();
    processData.callerPid = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    processData.killReason = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    processData.processType = AppExecFwk::ProcessType::NORMAL;
    processData.extensionType = AppExecFwk::ExtensionAbilityType::UNSPECIFIED;
    processData.state = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    preLoad->OnProcessDied(processData);
    processData.processType = AppExecFwk::ProcessType::EXTENSION;
    processData.extensionType = AppExecFwk::ExtensionAbilityType::APP_ACCOUNT_AUTHORIZATION;
    processData.state = AppExecFwk::AppProcessState::APP_STATE_CREATE;
    preLoad->OnProcessDied(processData);
    processData.processType = AppExecFwk::ProcessType::RENDER;
    processData.extensionType = AppExecFwk::ExtensionAbilityType::HMS_ACCOUNT;
    processData.state = AppExecFwk::AppProcessState::APP_STATE_READY;
    preLoad->OnProcessDied(processData);
    processData.processType = AppExecFwk::ProcessType::GPU;
    processData.extensionType = AppExecFwk::ExtensionAbilityType::REMOTE_NOTIFICATION;
    processData.state = AppExecFwk::AppProcessState::APP_STATE_FOCUS;
    preLoad->OnProcessDied(processData);

    AppExecFwk::AppStateData appStateData;
    std::vector<int32_t> renderPids;
    appStateData.isFocused = fdp.ConsumeBool();
    appStateData.isSplitScreenMode = fdp.ConsumeBool();
    appStateData.isFloatingWindowMode = fdp.ConsumeBool();
    appStateData.isSpecifyTokenId = fdp.ConsumeBool();
    appStateData.isPreloadModule = fdp.ConsumeBool();
    appStateData.pid = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    appStateData.uid = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    appStateData.callerUid = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    appStateData.state = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    appStateData.appIndex = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    appStateData.accessTokenId = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    appStateData.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appStateData.callerBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appStateData.extensionType = AppExecFwk::ExtensionAbilityType::UNSPECIFIED;
    preLoad->OnAppCacheStateChanged(appStateData);
    appStateData.extensionType = AppExecFwk::ExtensionAbilityType::REMOTE_NOTIFICATION;
    preLoad->OnAppCacheStateChanged(appStateData);
    appStateData.extensionType = AppExecFwk::ExtensionAbilityType::HMS_ACCOUNT;
    preLoad->OnAppCacheStateChanged(appStateData);
    appStateData.extensionType = AppExecFwk::ExtensionAbilityType::APP_ACCOUNT_AUTHORIZATION;
    preLoad->OnAppCacheStateChanged(appStateData);
    appStateData.extensionType = AppExecFwk::ExtensionAbilityType::ACCOUNTLOGOUT;
    preLoad->OnAppCacheStateChanged(appStateData);
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