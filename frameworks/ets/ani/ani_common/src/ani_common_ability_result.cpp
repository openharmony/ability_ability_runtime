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

#include "ani_common_ability_result.h"

#include "ani_common_want.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char *ABILITY_RESULT_CLASS_NAME = "ability.abilityResult.AbilityResultInner";
} // namespace

ani_object WrapAbilityResult(ani_env *env, int32_t resultCode, const AAFwk::Want &want)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ANI, "null env");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_status status = env->FindClass(ABILITY_RESULT_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "FindClass status: %{public}d", status);
        return nullptr;
    }

    ani_method ctor = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", nullptr, &ctor)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "Class_FindMethod status: %{public}d", status);
        return nullptr;
    }

    ani_object resultObj = nullptr;
    if ((status = env->Object_New(cls, ctor, &resultObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "Object_New status: %{public}d", status);
        return nullptr;
    }
    
    ani_method resultCodeSetter = nullptr;
    if ((status = env->Class_FindMethod(cls, "<set>resultCode", nullptr, &resultCodeSetter)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "Class_FindMethod status: %{public}d", status);
        return nullptr;
    }

    if ((status = env->Object_CallMethod_Void(resultObj, resultCodeSetter, resultCode)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "Object_CallMethod_Void status: %{public}d", status);
        return nullptr;
    }

    ani_method wantSetter = nullptr;
    if ((status = env->Class_FindMethod(cls, "<set>want", nullptr, &wantSetter)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "Class_FindMethod status: %{public}d", status);
        return nullptr;
    }

    ani_object wantObj = AppExecFwk::WrapWant(env, want);
    if ((status = env->Object_CallMethod_Void(resultObj, wantSetter, wantObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ANI, "Object_CallMethod_Void status: %{public}d", status);
        return nullptr;
    }

    return resultObj;
}
} // namespace AppExecFwk
} // namespace OHOS
