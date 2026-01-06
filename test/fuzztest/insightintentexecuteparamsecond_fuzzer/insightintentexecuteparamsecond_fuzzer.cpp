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

#include "insightintentexecuteparamsecond_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "insight_intent_execute_param.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 128;
}
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    InsightIntentExecuteParam executeParam;
    Parcel parcel;
    Want want;
    FuzzedDataProvider fdp(data, size);
    parcel.WriteString(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    executeParam.Marshalling(parcel);
    executeParam.Unmarshalling(parcel);
    executeParam.IsInsightIntentExecute(want);
    executeParam.IsInsightIntentPage(want);
    want.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_NAME, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    want.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_ID, std::to_string(fdp.ConsumeIntegral<uint64_t>()));
    want.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_MODE, fdp.ConsumeIntegral<int32_t>());
    want.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_PARAM, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    want.SetParam(AppExecFwk::INSIGHT_INTENT_SRC_ENTRY, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    want.SetParam(AppExecFwk::INSIGHT_INTENT_ARKTS_MODE, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    want.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_URI, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    want.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_FLAGS, fdp.ConsumeIntegral<int32_t>());
    want.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_OPENLINK_FLAG, fdp.ConsumeIntegral<int32_t>());
    want.SetParam(AppExecFwk::INSIGHT_INTENT_DECORATOR_TYPE, fdp.ConsumeIntegral<int32_t>());
    want.SetParam(AppExecFwk::INSIGHT_INTENT_SRC_ENTRANCE, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    want.SetParam(AppExecFwk::INSIGHT_INTENT_FUNC_PARAM_CLASSNAME, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    want.SetParam(AppExecFwk::INSIGHT_INTENT_FUNC_PARAM_METHODNAME, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    want.SetParam(AppExecFwk::INSIGHT_INTENT_FUNC_PARAM_METHODPARAMS, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    want.SetParam(AppExecFwk::INSIGHT_INTENT_PAGE_PARAM_PAGEPATH, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    want.SetParam(AppExecFwk::INSIGHT_INTENT_PAGE_PARAM_NAVIGATIONID, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    want.SetParam(
        AppExecFwk::INSIGHT_INTENT_PAGE_PARAM_NAVDESTINATIONNAME, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    executeParam.RemoveInsightIntent(want);

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