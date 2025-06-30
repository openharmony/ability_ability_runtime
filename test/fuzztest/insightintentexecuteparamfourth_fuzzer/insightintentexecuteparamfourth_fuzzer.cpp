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

#include "insightintentexecuteparamfourth_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "insight_intent_execute_param.h"
#include "int_wrapper.h"
#include "string_wrapper.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    InsightIntentExecuteParam executeParam;
    WantParams wantParams;
    WantParams insightIntentParam;
    FuzzedDataProvider fdp(data, size);
    wantParams.SetParam(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH), 0);
    insightIntentParam.SetParam(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH),
        String::Box(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH)));
    insightIntentParam.SetParam(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH),
        Integer::Box(fdp.ConsumeIntegral<int32_t>()));
    executeParam.UpdateInsightIntentCallerInfo(wantParams, insightIntentParam);

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