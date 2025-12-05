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

#include "ani_common_intent_info_filter.h"

#include "hilog_tag_wrapper.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ani_enum_convert.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;

bool UnwrapIntentInfoFilter(ani_env *env, ani_object param, AppExecFwk::InsightIntentInfoFilter &filter)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return false;
    }
    if (param == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null param");
        return false;
    }

    int32_t intentFlags = 0;
    if (!GetIntPropertyValue(env, param, "intentFlags", intentFlags)) {
        TAG_LOGE(AAFwkTag::INTENT, "Wrong argument intentFlags fail");
        return false;
    }

    if (intentFlags != GetInsightIntentFlag::GET_FULL_INSIGHT_INTENT &&
        intentFlags != GetInsightIntentFlag::GET_SUMMARY_INSIGHT_INTENT &&
        intentFlags != (GetInsightIntentFlag::GET_FULL_INSIGHT_INTENT | GetInsightIntentFlag::GET_ENTITY_INFO) &&
        intentFlags != (GetInsightIntentFlag::GET_SUMMARY_INSIGHT_INTENT | GetInsightIntentFlag::GET_ENTITY_INFO)) {
        TAG_LOGE(AAFwkTag::INTENT, "Parse flag failed");
        return false;
    }
    filter.intentFlags_ = static_cast<GetInsightIntentFlag>(intentFlags);

    if (IsExistsProperty(env, param, "bundleName")) {
        std::string bundleName {""};
        if (!GetStringProperty(env, param, "bundleName", bundleName)) {
            TAG_LOGE(AAFwkTag::INTENT, "Wrong argument type bundleName");
            return false;
        }
        filter.bundleName_ = bundleName;
    }

    if (IsExistsProperty(env, param, "moduleName")) {
        std::string moduleName {""};
        if (!GetStringProperty(env, param, "moduleName", moduleName)) {
            TAG_LOGE(AAFwkTag::INTENT, "Wrong argument type moduleName");
            return false;
        }
        filter.moduleName_ = moduleName;
    }

    if (IsExistsProperty(env, param, "intentName")) {
        std::string intentName {""};
        if (!GetStringProperty(env, param, "intentName", intentName)) {
            TAG_LOGE(AAFwkTag::INTENT, "Wrong argument type intentName");
            return false;
        }
        filter.intentName_ = intentName;
    }

    if (IsExistsProperty(env, param, "userId")) {
        ani_int userId = 0;
        if (!GetIntPropertyObject(env, param, "userId", userId)) {
            TAG_LOGE(AAFwkTag::INTENT, "Wrong argument userId fail");
            return false;
        }
        filter.userId_ = userId;
    }
    return true;
}
} // namespace AbilityRuntime
} // namespace OHOS
