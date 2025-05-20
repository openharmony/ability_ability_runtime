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

#include "ani_common_execute_result.h"

#include "hilog_tag_wrapper.h"
#include "insight_intent_execute_result.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "want_params.h"
#include <memory>

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
bool UnwrapResultOfExecuteResult(ani_env *env, ani_object &param, InsightIntentExecuteResult &executeResult)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return false;
    }
    ani_status status = ANI_OK;
    ani_ref wantParamRef = nullptr;
    if (!GetRefProperty(env, param, "result", wantParamRef)) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return false;
    }

    auto wantParams = std::make_shared<AAFwk::WantParams>();
    if (!UnwrapWantParams(env, wantParamRef, *wantParams)) {
        TAG_LOGE(AAFwkTag::INTENT, "failed to unwrap want parameter");
        return false;
    }

    if (!executeResult.CheckResult(wantParams)) {
        TAG_LOGE(AAFwkTag::INTENT, "Check wp fail");
        return false;
    }
    executeResult.result = wantParams;

    return true;
}

bool UnwrapExecuteResult(ani_env *env, ani_object &param, InsightIntentExecuteResult &executeResult)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return false;
    }

    if (param == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "param is nullptr");
        return false;
    }

    ani_double code = 0;
    if (!GetDoublePropertyValue(env, param, "code", code)) {
        TAG_LOGE(AAFwkTag::INTENT, "parse code fail");
        return false;
    }
    executeResult.code = static_cast<int32_t>(code);

    if (IsExistsProperty(env, param, "result")) {
        if (!UnwrapResultOfExecuteResult(env, param, executeResult)) {
            TAG_LOGE(AAFwkTag::INTENT, "unwrap execute result fail");
            return false;
        }
    }

    if (IsExistsProperty(env, param, "uris")) {
        std::vector<std::string> uris;
        if (!GetStringArrayProperty(env, param, "uris", uris)) {
            TAG_LOGE(AAFwkTag::INTENT, "unwrap uris is null");
            return false;
        }
        executeResult.uris = uris;
    }

    if (IsExistsProperty(env, param, "flags")) {
        double flags = 0.0;
        if (!GetDoublePropertyObject(env, param, "flags", flags)) {
            TAG_LOGE(AAFwkTag::INTENT, "unwrap flags is null");
            return false;
        }
        executeResult.flags = static_cast<int32_t>(flags);
    }

    return true;
}

ani_object WrapExecuteResult(ani_env *env, AppExecFwk::InsightIntentExecuteResult &executeResult)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return nullptr;
    }

    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method ctor = nullptr;
    ani_object objValue = {};

    if ((status = env->FindClass("L@ohos/app/ability/insightIntent/insightIntent/ExecuteResultInner;",
        &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return nullptr;
    }

    if ((status = env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return nullptr;
    }

    if ((status = env->Object_New(cls, ctor, &objValue)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return nullptr;
    }

    if (!SetDoublePropertyValue(env, objValue, "code", static_cast<double>(executeResult.code))) {
        TAG_LOGE(AAFwkTag::INTENT, "SetDoubleProperty failded");
        return nullptr;
    }
    if (executeResult.result != nullptr) {
        SetRefProperty(env, objValue, "result", WrapWantParams(env, *executeResult.result));
    }
    if (executeResult.uris.size() > 0) {
        SetStringArrayProperty(env, objValue, "uris", executeResult.uris);
    }
    SetDoublePropertyObject(env, objValue, "flags", static_cast<double>(executeResult.flags));

    return objValue;
}

ani_object CreateNullExecuteResult(ani_env *env)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return nullptr;
    }

    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method ctor = nullptr;
    ani_object objValue = {};

    if ((status = env->FindClass("L@ohos/app/ability/insightIntent/insightIntent/ExecuteResultInner;",
        &cls))
        != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return nullptr;
    }

    if ((status = env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return nullptr;
    }

    if ((status = env->Object_New(cls, ctor, &objValue)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        return nullptr;
    }

    return objValue;
}
} // namespace AbilityRuntime
} // namespace OHOS
