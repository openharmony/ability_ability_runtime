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
namespace {
constexpr const char *CLASSNAME_ARRAY = "std.core.Array";
}

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

bool UnwrapResultOfDecoratorExecuteResult(ani_env *env, ani_object &param, InsightIntentExecuteResult &executeResult)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return false;
    }
    if (param == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "decorator param is nullptr");
        return false;
    }

    auto wantParams = std::make_shared<AAFwk::WantParams>();
    if (!UnwrapWantParams(env, param, *wantParams)) {
        TAG_LOGE(AAFwkTag::INTENT, "failed to unwrap want parameter");
        return false;
    }

    if (!executeResult.CheckResult(wantParams)) {
        TAG_LOGE(AAFwkTag::INTENT, "Check wp fail");
        return false;
    }
    executeResult.result = wantParams;
    executeResult.code = wantParams->GetIntParam("code", 0);
    return true;
}

bool UnwrapExecuteResult(ani_env *env, ani_object &param, InsightIntentExecuteResult &executeResult, bool isDecorator)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return false;
    }

    if (param == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "param is nullptr");
        return false;
    }

    if (isDecorator) {
        executeResult.isDecorator = true;
        if (!UnwrapResultOfDecoratorExecuteResult(env, param, executeResult)) {
            TAG_LOGE(AAFwkTag::INTENT, "unwrap decorator result fail");
            return false;
        }
        return true;
    }

    int32_t code = 0;
    if (!GetIntPropertyValue(env, param, "code", code)) {
        TAG_LOGE(AAFwkTag::INTENT, "parse code fail");
        return false;
    }
    executeResult.code = code;

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
        int32_t flags = 0;
        if (!GetIntPropertyObject(env, param, "flags", flags)) {
            TAG_LOGE(AAFwkTag::INTENT, "unwrap flags is null");
            return false;
        }
        executeResult.flags = flags;
    }

    return true;
}

ani_object WrapExecuteResult(ani_env *env, const AppExecFwk::InsightIntentExecuteResult &executeResult)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return nullptr;
    }

    if (executeResult.isQueryEntity) {
        return WrapQueryEntityResult(env, executeResult);
    }

    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method ctor = nullptr;
    ani_object objValue = {};

    if ((status = env->FindClass("@ohos.app.ability.insightIntent.insightIntent.ExecuteResultInner",
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

    if (!SetIntPropertyValue(env, objValue, "code", executeResult.code)) {
        TAG_LOGE(AAFwkTag::INTENT, "SetIntPropertyValue failded");
        return nullptr;
    }
    if (executeResult.result != nullptr) {
        SetRefProperty(env, objValue, "result", WrapWantParams(env, *executeResult.result));
    }
    if (executeResult.uris.size() > 0) {
        SetStringArrayProperty(env, objValue, "uris", executeResult.uris);
    }
    SetIntPropertyObject(env, objValue, "flags", executeResult.flags);

    return objValue;
}

ani_object WrapQueryEntityResult(ani_env *env, const AppExecFwk::InsightIntentExecuteResult &executeResult)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return nullptr;
    }

    if (executeResult.queryResults.size() == 0) {
        return CreateEmptyArray(env);
    }

    ani_class arrayCls = nullptr;
    ani_status status = ANI_OK;
    status = env->FindClass(CLASSNAME_ARRAY, &arrayCls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "FindClass failed status: %{public}d", status);
        return nullptr;
    }

    ani_method arrayCtor;
    status = env->Class_FindMethod(arrayCls, "<ctor>", "i:", &arrayCtor);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "find ctor failed status: %{public}d", status);
        return nullptr;
    }

    ani_object arrayObj;
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, executeResult.queryResults.size());
    if (status != ANI_OK || arrayObj == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "Object_New array status: %{public}d", status);
        return nullptr;
    }
    ani_size index = 0;
    for (size_t i = 0; i < executeResult.queryResults.size(); i++) {
        if (executeResult.queryResults[i] == nullptr) {
            TAG_LOGE(AAFwkTag::INTENT, "queryResult: %{public}zu is nullptr", i);
            continue;
        }
        ani_object aniInfo = static_cast<ani_object>(WrapWantParams(env, *executeResult.queryResults[i]));
        if (aniInfo == nullptr) {
            TAG_LOGE(AAFwkTag::INTENT, "queryResult: %{public}zu is nullptr", i);
            continue;
        }
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "iY:", index, aniInfo);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::INTENT, "queryResult: %{public}zu SetObject failed status: %{public}d", i, status);
            continue;
        }
        index++;
    }
    return arrayObj;
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

    if ((status = env->FindClass("@ohos.app.ability.insightIntent.insightIntent.ExecuteResultInner",
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
