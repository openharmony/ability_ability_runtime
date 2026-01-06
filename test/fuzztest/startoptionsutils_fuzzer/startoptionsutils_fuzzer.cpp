/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "startoptionsutils_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "ability_fuzz_util.h"
#define private public
#include "start_options_utils.h"
#undef private

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    ElementName elementName;
    AbilityFuzzUtil::GenerateElementName(fdp, elementName);
    Want want;
    want.SetElement(elementName);

    StartOptions startOptions;
    AbilityFuzzUtil::GetRandomStartOptions(fdp, startOptions);
    sptr<IRemoteObject> callerToken = nullptr;
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    StartOptionsUtils::CheckProcessOptions(want, startOptions, callerToken, userId);
    StartOptionsUtils::CheckProcessOptionsInner(want, startOptions, callerToken, userId);
    StartOptionsUtils::CheckStartSelfUIAbilityStartOptions(want, startOptions);
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