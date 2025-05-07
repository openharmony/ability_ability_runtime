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

#include "ani_common_want_agent.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* LONG_CLASS = "Lstd/core/Long;";

ani_object createLong(ani_env *env, ani_long value)
{
    ani_class persion_cls;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(LONG_CLASS, &persion_cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return nullptr;
    }
    ani_method personInfoCtor;
    if ((status = env->Class_FindMethod(persion_cls, "<ctor>", "J:V", &personInfoCtor)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return nullptr;
    }
    ani_object personInfoObj;
    if ((status = env->Object_New(persion_cls, personInfoCtor, &personInfoObj, value)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::JSNAPI, "status : %{public}d", status);
        return nullptr;
    }
    return personInfoObj;
}
} // namespace

ani_object WrapWantAgent(ani_env *env, WantAgent *wantAgent)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "env null");
        return nullptr;
    }
    if (wantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "wantAgent null");
        return nullptr;
    }
    ani_long pWantAgent = reinterpret_cast<ani_long>(wantAgent);
    ani_object longObj =  createLong(env, pWantAgent);
    if (longObj == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null object");
        return nullptr;
    }
    return longObj;
}

void UnwrapWantAgent(ani_env *env, ani_object agent, void** result)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "env null");
        return;
    }
    if (agent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "agent null");
        return;
    }
    ani_long param_value;
    ani_status status = ANI_ERROR;
    ani_class cls {};
    ani_method method {};
    if ((status = env->FindClass(LONG_CLASS, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "FindClass failed status: %{public}d", status);
        return;
    }
    if ((status = env->Class_FindMethod(cls, "unboxed", nullptr, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Class_FindMethod failed status: %{public}d", status);
        return;
    }
    if ((status = env->Object_CallMethod_Long(agent, method, &param_value)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Object_CallMethod_Long failed status: %{public}d", status);
        return;
    }
    *result = reinterpret_cast<void*>(param_value);
}
} // namespace AppExecFwk
} // namespace OHOS
