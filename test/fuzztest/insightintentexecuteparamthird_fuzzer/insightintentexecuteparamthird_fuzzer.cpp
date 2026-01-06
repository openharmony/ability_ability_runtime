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

#include "insightintentexecuteparamthird_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "ability_fuzz_util.h"
#include "insight_intent_execute_param.h"
#include "insight_intent_utils.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t STRING_MAX_LENGTH = 128;
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    InsightIntentExecuteParam executeParam;
    Want want;
    InsightIntentExecuteParam param;
    FuzzedDataProvider fdp(data, size);
    AbilityFuzzUtil::GetRandomInsightIntentExecuteParam(fdp, param);
    executeParam.GenerateFromWant(want, param);
    std::string executeParamName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, executeParamName);
    executeParam.GenerateFromWant(want, param);

    int32_t intentId = fdp.ConsumeIntegralInRange<int32_t>(0, U32_AT_SIZE);
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_ID, std::to_string(intentId));
    executeParam.GenerateFromWant(want, param);

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