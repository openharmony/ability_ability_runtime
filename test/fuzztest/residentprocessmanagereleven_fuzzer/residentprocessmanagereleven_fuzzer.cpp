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

#include "residentprocessmanagereleven_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "resident_process_manager.h"
#undef private

#include "ability_record.h"
#include "../ability_fuzz_util.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    // fuzz for ResidentProcessManager
    auto residentProcessManager = std::make_shared<ResidentProcessManager>();
    std::vector<AppExecFwk::BundleInfo> bundleInfos;
    BundleInfo info;
    int32_t userId;
    FuzzedDataProvider fdp(data, size);
    size_t arraySize = fdp.ConsumeIntegralInRange<size_t>(0, STRING_MAX_LENGTH);
    for (size_t i = 0; i < arraySize; ++i) {
        AbilityFuzzUtil::GetRandomBundleInfo(fdp, info);
        bundleInfos.emplace_back(info);
    }
    userId = fdp.ConsumeIntegral<int32_t>();
    residentProcessManager->GetResidentBundleInfosForUser(bundleInfos, userId);
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