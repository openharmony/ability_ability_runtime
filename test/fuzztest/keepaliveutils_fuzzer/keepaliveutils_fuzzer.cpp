/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "keepaliveutils_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "keep_alive_utils.h"
#include "ability_fuzz_util.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::vector<BundleInfo> bundleInfos = AbilityFuzzUtil::GenerateBundleInfoArray(fdp);
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    KeepAliveUtils::NotifyDisableKeepAliveProcesses(bundleInfos, userId);
    BundleInfo bundleInfo;
    AbilityFuzzUtil::GenerateBundleInfo(fdp, bundleInfo);
    KeepAliveType type =
        static_cast<KeepAliveType>(fdp.ConsumeIntegralInRange<int32_t>(0, AbilityFuzzUtil::CODE_TWO) - 1);
    KeepAliveUtils::IsKeepAliveBundle(bundleInfo, userId, type);
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