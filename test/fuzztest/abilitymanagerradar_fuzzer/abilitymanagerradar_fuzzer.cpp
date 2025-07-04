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

#include "abilitymanagerradar_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "ability_manager_radar.h"

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::string func;
    unsigned int flags = 0;
    int32_t errCode;
    FuzzedDataProvider fdp(data, size);
    func = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    errCode = fdp.ConsumeIntegral<int32_t>();
    AAFWK::ContinueRadar::GetInstance().ClickIconContinue(func);
    AAFWK::ContinueRadar::GetInstance().ClickIconStartAbility(func, flags, errCode);
    AAFWK::ContinueRadar::GetInstance().ClickIconRecvOver(func);
    AAFWK::ContinueRadar::GetInstance().SaveDataContinue(func);
    AAFWK::ContinueRadar::GetInstance().SaveDataRes(func);
    AAFWK::ContinueRadar::GetInstance().SaveDataRemoteWant(func);
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