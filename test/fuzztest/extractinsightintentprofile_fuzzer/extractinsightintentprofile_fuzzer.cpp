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

#include "extractinsightintentprofile_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>
#include "extract_insight_intent_profile.h"
#include "hilog_tag_wrapper.h"

using namespace OHOS;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t STRING_MAX_LENGTH = 256;
const std::vector<std::string> DECORATOR_TYPE_LIST = {
    "@InsightIntentLink",
    "@InsightIntentPage",
    "@InsightIntentEntry",
    "@InsightIntentFunctionMethod",
    "@InsightIntentForm"
};
const std::vector<std::string> EXECUTE_MODE_LIST = {
    "foreground", "background", "uiextension", "serviceextension", "invalid_mode_456"
};
constexpr int32_t MIN_JSON_STR_SIZE = 2;

template <typename T>
const T& PickValueInVector(FuzzedDataProvider& fdp, const std::vector<T>& vec)
{
    if (vec.empty()) {
        static const T emptyVal{};
        return emptyVal;
    }
    size_t idx = fdp.ConsumeIntegralInRange<size_t>(0, vec.size() - 1);
    return vec[idx];
}
}

static void GenerateRandomLinkIntentParamProfileMapping(
    FuzzedDataProvider &fdp, LinkIntentParamProfileMapping &paramMap)
{
    paramMap.paramName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    paramMap.paramMappingName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    paramMap.paramCategory = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

static void GenerateRandomExtractInsightIntentProfileInfo(
    FuzzedDataProvider &fdp, ExtractInsightIntentProfileInfo &profileInfo)
{
    profileInfo.decoratorFile = fdp.ConsumeBool() ? fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH) : "";
    profileInfo.decoratorClass = fdp.ConsumeBool() ? fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH) : "";
    profileInfo.decoratorType = PickValueInVector(fdp, DECORATOR_TYPE_LIST);
    profileInfo.bundleName = fdp.ConsumeBool() ? fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH) : "";
    profileInfo.moduleName = fdp.ConsumeBool() ? fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH) : "";
    profileInfo.intentName = fdp.ConsumeBool() ? fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH) : "";
    profileInfo.domain = fdp.ConsumeBool() ? fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH) : "";
    profileInfo.intentVersion = fdp.ConsumeBool() ? fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH) : "";
    profileInfo.displayName = fdp.ConsumeBool() ? fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH) : "";

    profileInfo.displayDescription = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    profileInfo.schema = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    profileInfo.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    profileInfo.llmDescription = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    profileInfo.example = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    profileInfo.uri = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    profileInfo.uiAbility = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    profileInfo.pagePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    profileInfo.navigationId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    profileInfo.navDestinationName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    profileInfo.abilityName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    profileInfo.functionName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    profileInfo.formName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

    size_t vecSize = fdp.ConsumeIntegralInRange<size_t>(0, 5);
    for (size_t i = 0; i < vecSize; i++) {
        std::string keyword = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        profileInfo.keywords.emplace_back(keyword);
    }
    for (size_t i = 0; i < vecSize; i++) {
        std::string mode = PickValueInVector(fdp, EXECUTE_MODE_LIST);
        profileInfo.executeMode.emplace_back(mode);
    }
    for (size_t i = 0; i < vecSize; i++) {
        std::string funcParam = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        profileInfo.functionParams.emplace_back(funcParam);
    }
    for (size_t i = 0; i < vecSize; i++) {
        LinkIntentParamProfileMapping paramMap;
        GenerateRandomLinkIntentParamProfileMapping(fdp, paramMap);
        profileInfo.paramMapping.emplace_back(paramMap);
    }
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);

    ExtractInsightIntentProfileInfo profileInfo;
    ExtractInsightIntentProfileInfoVec profileInfoVec;
    ExtractInsightIntentInfo insightIntentInfo;
    InsightIntentLinkInfo linkInfo;
    InsightIntentPageInfo pageInfo;
    InsightIntentEntryInfo entryInfo;
    InsightIntentFunctionInfo funcInfo;
    InsightIntentFormInfo formInfo;
    nlohmann::json jsonObj;
    std::string randomStr;

    GenerateRandomExtractInsightIntentProfileInfo(fdp, profileInfo);

    ExtractInsightIntentProfile::ProfileInfoFormat(profileInfo, insightIntentInfo);
    jsonObj.clear();
    randomStr = "";
    ExtractInsightIntentProfile::TransformTo(randomStr, profileInfoVec);
    randomStr = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    ExtractInsightIntentProfile::TransformTo(randomStr, profileInfoVec);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}