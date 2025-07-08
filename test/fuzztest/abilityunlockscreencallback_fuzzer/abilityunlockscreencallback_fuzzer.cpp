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
#include "abilityunlockscreencallback_fuzzer.h"

#include "unlock_screen_callback.h"

#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include "securec.h"

namespace OHOS {
using namespace OHOS::AbilityRuntime;
namespace {
constexpr size_t U32_AT_SIZE = 4;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    int32_t screenLockResult = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    std::shared_ptr<std::promise<bool>> promise = std::make_shared<std::promise<bool>>();
    std::shared_ptr<UnlockScreenCallback> callback = std::make_shared<UnlockScreenCallback>(promise);
    if (callback == nullptr) {
        return false;
    }
    callback->OnCallBack(screenLockResult);
    callback->screenLockResult_ = nullptr;
    callback->OnCallBack(screenLockResult);
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