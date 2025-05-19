/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "abilityappdebugmanagersecond_fuzzer.h"

#define private public
#include "app_debug_manager.h"
#include "app_debug_listener_proxy.h"
#undef private

#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include "securec.h"
#include "configuration.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t STRING_MAX_LENGTH = 128;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<AppDebugManager> manager=std::make_shared<AppDebugManager>();
    if (!manager) {
        return false;
    }
    FuzzedDataProvider fdp(data, size);
    AppDebugInfo info;
    info.pid = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    info.uid = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    manager->RemoveAppDebugInfo(info);
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