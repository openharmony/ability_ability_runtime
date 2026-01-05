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

#include "insightintentutilsfirst_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "ability_fuzz_util.h"
#include "insight_intent_utils.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t CODE_FOUR = 4;
constexpr size_t STRING_MAX_LENGTH = 128;
}
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    AbilityRuntime::InsightIntentUtils utils;
    AppExecFwk::ElementName elementName;
    std::string intentName;
    AppExecFwk::ExecuteMode executeMode;
    std::string srcEntry;
    FuzzedDataProvider fdp(data, size);
    AbilityFuzzUtil::GenerateElementName(fdp, elementName);
    intentName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    executeMode = static_cast<ExecuteMode>(fdp.ConsumeIntegralInRange<int32_t>(0, CODE_FOUR));
    srcEntry = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    utils.GetSrcEntry(elementName, intentName, executeMode, srcEntry);
    AbilityRuntime::InsightIntentInfo info;
    info.intentName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.intentDomain = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.intentVersion = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.srcEntry = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.arkTSMode = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.inputParams = AppExecFwk::AbilityFuzzUtil::GenerateStringArray(fdp);
    info.outputParams = AppExecFwk::AbilityFuzzUtil::GenerateStringArray(fdp);
    info.cfgEntities = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.displayName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.displayDescription = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    info.keywords = AppExecFwk::AbilityFuzzUtil::GenerateStringArray(fdp);
    AbilityRuntime::InsightIntentInfoForQuery queryInfo;
    bool getEntity = fdp.ConsumeBool();
    utils.ConvertConfigInsightIntentInfo(info, queryInfo, getEntity);
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