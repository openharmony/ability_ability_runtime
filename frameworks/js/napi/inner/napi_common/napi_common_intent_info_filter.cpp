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

#include "napi_common_intent_info_filter.h"

#include "hilog_tag_wrapper.h"
#include "napi_common_util.h"
#include "napi_common_want.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
bool UnwrapIntentInfoFilter(napi_env env, napi_value param, AppExecFwk::InsightIntentInfoFilter &filter)
{
    if (!IsTypeForNapiValue(env, param, napi_object)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "invalid params");
        return false;
    }

    int32_t intentFlags = 0;
    if (!UnwrapInt32ByPropertyName(env, param, "intentFlags", intentFlags)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "Wrong argument type intentFlags");
        return false;
    }
    if (intentFlags != GetInsightIntentFlag::GET_FULL_INSIGHT_INTENT &&
        intentFlags != GetInsightIntentFlag::GET_SUMMARY_INSIGHT_INTENT &&
        intentFlags != (GetInsightIntentFlag::GET_FULL_INSIGHT_INTENT | GetInsightIntentFlag::GET_ENTITY_INFO) &&
        intentFlags != (GetInsightIntentFlag::GET_SUMMARY_INSIGHT_INTENT | GetInsightIntentFlag::GET_ENTITY_INFO)) {
        TAG_LOGE(AAFwkTag::JSNAPI, "Parse flag failed");
        return false;
    }
    filter.intentFlags_ = static_cast<GetInsightIntentFlag>(intentFlags);

    if (IsExistsByPropertyName(env, param, "bundleName")) {
        std::string bundleName {""};
        if (!UnwrapStringByPropertyName(env, param, "bundleName", bundleName)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Wrong argument type bundleName");
            return false;
        }
        filter.bundleName_ = bundleName;
    }

    if (IsExistsByPropertyName(env, param, "moduleName")) {
        std::string moduleName {""};
        if (!UnwrapStringByPropertyName(env, param, "moduleName", moduleName)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Wrong argument type moduleName");
            return false;
        }
        filter.moduleName_ = moduleName;
    }

    if (IsExistsByPropertyName(env, param, "intentName")) {
        std::string intentName {""};
        if (!UnwrapStringByPropertyName(env, param, "intentName", intentName)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Wrong argument type intentName");
            return false;
        }
        filter.intentName_ = intentName;
    }

    if (IsExistsByPropertyName(env, param, "userId")) {
        int32_t userId = DEFAULT_INVAL_VALUE;
        if (!UnwrapInt32ByPropertyName(env, param, "userId", userId)) {
            TAG_LOGE(AAFwkTag::JSNAPI, "Wrong argument userId fail");
            return false;
        }
        filter.userId_ = userId;
    }

    return true;
}
}  // namespace AbilityRuntime
}  // namespace OHOS
