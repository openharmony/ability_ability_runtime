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

#include "abilityautostartupdatamanagerfourth_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "ability_auto_startup_data_manager.h"
#undef private

#include "ability_record.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t STRING_MAX_LENGTH = 128;
void GetRandomAutoStartupInfo(FuzzedDataProvider& fdp, AutoStartupInfo& info)
{
    info.appCloneIndex = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    info.userId = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    info.retryCount = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    info.userId = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    info.setterUserId = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    info.canUserModify = fdp.ConsumeIntegralInRange<bool>(false, true);
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.abilityTypeName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.accessTokenId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    auto abilityAutoStartupDataManager = std::make_shared<AbilityRuntime::AbilityAutoStartupDataManager>();
    FuzzedDataProvider fdp(data, size);
    AutoStartupInfo info;
    std::vector<AutoStartupInfo> infoList;
    int32_t in32Param = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    size_t arraySize = fdp.ConsumeIntegralInRange<size_t>(0, U32_AT_SIZE);
    bool isCalledByEDM = fdp.ConsumeIntegralInRange<bool>(false, true);
    for (size_t i = 0; i < arraySize; ++i) {
        GetRandomAutoStartupInfo(fdp, info);
        infoList.emplace_back(info);
    }
    abilityAutoStartupDataManager->QueryAllAutoStartupApplications(infoList, in32Param, isCalledByEDM);
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