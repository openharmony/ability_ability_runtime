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

namespace OHOS {
namespace {
constexpr uint8_t ENABLE = 2;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t STRING_MAX_LENGTH = 128;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
{
    std::shared_ptr<AbilityRuntime::ExtensionRecord> extRecord;
    std::weak_ptr<AbilityRuntime::ExtensionRecord> weakExtRecord = extRecord;
    std::shared_ptr<AAFwk::PreLoadUIExtStateObserver> preLoad =
        std::make_shared<AAFwk::PreLoadUIExtStateObserver>(weakExtRecord);
    if (!preLoad) {
        return false;
    }
    AppExecFwk::ProcessData processData;
    AppExecFwk::AppStateData appStateData;
    preLoad->OnProcessDied(processData);
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