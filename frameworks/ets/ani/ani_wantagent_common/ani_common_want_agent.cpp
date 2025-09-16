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
constexpr const char* WANT_AGENT_CLASS = "@ohos.app.ability.wantAgent.wantAgent.WantAgentCls";

ani_object CreateWantAgent(ani_env *env, ani_long ptr)
{
    ani_class cls = nullptr;
    ani_status status = env->FindClass(WANT_AGENT_CLASS, &cls);
    if (status != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "FindClass status: %{public}d, or null cls", status);
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "l:", &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Class_FindMethod status: %{public}d, or null method", status);
        return nullptr;
    }
    ani_object obj = nullptr;
    if ((status = env->Object_New(cls, method, &obj, ptr)) != ANI_OK || obj == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Object_New status: %{public}d, or null obj", status);
        return nullptr;
    }
    return obj;
}
} // namespace

ani_object WrapWantAgent(ani_env *env, WantAgent *wantAgent)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "WrapWantAgent called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null env");
        return nullptr;
    }
    if (wantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null wantAgent");
        return nullptr;
    }
    ani_long pWantAgent = (ani_long)wantAgent;
    ani_object wantAgentCls =  CreateWantAgent(env, pWantAgent);
    if (wantAgentCls == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null wantAgent");
        return nullptr;
    }
    return wantAgentCls;
}

void UnwrapWantAgent(ani_env *env, ani_object agent, void** result)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "UnwrapWantAgent called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null env");
        return;
    }
    if (agent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null agent");
        return;
    }
    ani_class cls = nullptr;
    ani_status status = env->FindClass(WANT_AGENT_CLASS, &cls);
    if (status != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "FindClass status: %{public}d, or null cls", status);
        return;
    }
    ani_boolean isWantAgentCls = ANI_FALSE;
    if ((status = env->Object_InstanceOf(agent, cls, &isWantAgentCls)) != ANI_OK || !isWantAgentCls) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Object_InstanceOf failed: status=%{public}d, isWantAgentCls=%{public}d", status,
            isWantAgentCls);
        return;
    }
    ani_field wantAgentPtrField = nullptr;
    if ((status = env->Class_FindField(cls, "wantAgentPtr", &wantAgentPtrField)) != ANI_OK ||
        wantAgentPtrField == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "Class_FindField status: %{public}d, or null wantAgentPtrField", status);
        return;
    }
    ani_long wantAgentPtr = 0;
    if ((status = env->Object_GetField_Long(agent, wantAgentPtrField, &wantAgentPtr)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "wantAgentPtr GetField status: %{public}d", status);
        return;
    }
    if (wantAgentPtr == 0) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null wantAgentPtr");
        return;
    }
    *result = reinterpret_cast<void*>(wantAgentPtr);
}
} // namespace AppExecFwk
} // namespace OHOS
