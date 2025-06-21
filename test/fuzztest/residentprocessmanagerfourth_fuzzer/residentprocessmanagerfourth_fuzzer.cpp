/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "residentprocessmanagerfourth_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#define private public
#include "resident_process_manager.h"
#undef private

#include "ability_record.h"

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
    AppExecFwk::HapModuleInfo hapModuleInfo;
    std::string processName;
    size_t index;
    std::set<uint32_t> needEraseIndexSet;
    int32_t userId;
    FuzzedDataProvider fdp(data, size);
    hapModuleInfo.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.package = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.description = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.descriptionId = fdp.ConsumeIntegral<int32_t>();
    hapModuleInfo.iconPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.iconId = fdp.ConsumeIntegral<int32_t>();
    hapModuleInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.labelId = fdp.ConsumeIntegral<int32_t>();
    hapModuleInfo.backgroundImg = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.mainAbility = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.srcPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.hashValue = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.hapPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.isLibIsolated = fdp.ConsumeBool();
    hapModuleInfo.nativeLibraryPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo.compressNativeLibs = fdp.ConsumeBool();
    processName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    index = fdp.ConsumeIntegralInRange<size_t>(0, STRING_MAX_LENGTH);
    userId = fdp.ConsumeIntegral<int32_t>();
    size_t arraySize = fdp.ConsumeIntegralInRange<size_t>(0, STRING_MAX_LENGTH);
    for (size_t i = 0; i < arraySize; ++i) {
        uint32_t temp = fdp.ConsumeIntegral<uint32_t>();
        needEraseIndexSet.insert(temp);
    }
    residentProcessManager->StartResidentProcessWithMainElementPerBundleHap(hapModuleInfo, processName, index,
        needEraseIndexSet, userId);
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