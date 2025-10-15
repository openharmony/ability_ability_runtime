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

#include "mainelementutilssecond_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "ability_fuzz_util.h"
#include "main_element_utils.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.process = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleInfo bundleInfo;
    AbilityFuzzUtil::GetRandomBundleInfo(fdp, bundleInfo);

    AbilityRuntime::LoadParam loadParam;
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    std::string mainElement = fdp.ConsumeRandomLengthString();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();

    bool isMainUIAbility = MainElementUtils::IsMainUIAbility(bundleName, abilityName, userId);
    MainElementUtils::SetMainUIAbilityKeepAliveFlag(isMainUIAbility, bundleName, loadParam);
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