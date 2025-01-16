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

#include "napi_common_want_agent.h"

#include "hilog_tag_wrapper.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "want_agent.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AbilityRuntime;

inline void *DetachCallbackFunc(napi_env env, void *value, void *)
{
    return value;
}

napi_value AttachWantAgentFunc(napi_env env, void *value, void *)
{
    TAG_LOGI(AAFwkTag::WANTAGENT, "called");
    if (value == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null value");
        return nullptr;
    }

    napi_value jsObject = nullptr;
    NAPI_CALL(env, napi_create_object(env, &jsObject));

    if (!AbilityRuntime::WantAgent::WantAgent::GetIsMultithreadingSupported()) {
        TAG_LOGI(AAFwkTag::WANTAGENT, "wantAgent not support multi thread current");
        return jsObject;
    }

    auto wantAgent = new (std::nothrow) AbilityRuntime::WantAgent::WantAgent(
        reinterpret_cast<AbilityRuntime::WantAgent::WantAgent*>(value)->GetPendingWant());
    if (wantAgent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "new wantAgent failed");
        return jsObject;
    }

    napi_value wantAgentClass = nullptr;
    napi_define_class(env, "WantAgentClass", NAPI_AUTO_LENGTH,
        [](napi_env env, napi_callback_info info) -> napi_value {
            napi_value thisVar = nullptr;
            napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);

            return thisVar;
        }, nullptr, 0, nullptr, &wantAgentClass);
    napi_value result = nullptr;
    napi_new_instance(env, wantAgentClass, 0, nullptr, &result);
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "create instance failed");
        delete wantAgent;
        wantAgent = nullptr;
        return jsObject;
    }

    napi_coerce_to_native_binding_object(env, result, DetachCallbackFunc, AttachWantAgentFunc, value, nullptr);
    auto res = napi_wrap(env, result, reinterpret_cast<void*>(wantAgent),
        [](napi_env env, void* data, void* hint) {
            TAG_LOGD(AAFwkTag::WANTAGENT, "delete wantAgent");
            auto agent = static_cast<AbilityRuntime::WantAgent::WantAgent*>(data);
            delete agent;
            agent = nullptr;
        }, nullptr, nullptr);
    if (res != napi_ok && wantAgent != nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "napi_wrap failed:%{public}d", res);
        delete wantAgent;
        wantAgent = nullptr;
        return jsObject;
    }
    return result;
}

napi_value WrapWantAgent(napi_env env, AbilityRuntime::WantAgent::WantAgent* wantAgent, napi_finalize finalizeCb)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    napi_value wantAgentClass = nullptr;
    napi_define_class(
        env,
        "WantAgentClass",
        NAPI_AUTO_LENGTH,
        [](napi_env env, napi_callback_info info) -> napi_value {
            napi_value thisVar = nullptr;
            napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
            return thisVar;
        },
        nullptr,
        0,
        nullptr,
        &wantAgentClass);
    napi_value result = nullptr;
    napi_new_instance(env, wantAgentClass, 0, nullptr, &result);
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "create instance failed");
        return nullptr;
    }

    napi_coerce_to_native_binding_object(env, result, DetachCallbackFunc, AttachWantAgentFunc, wantAgent, nullptr);

    napi_finalize finalize = [](napi_env env, void* data, void* hint) {
        TAG_LOGD(AAFwkTag::WANTAGENT, "delete wantAgent");
        if (data != nullptr) {
            auto agent = static_cast<AbilityRuntime::WantAgent::WantAgent*>(data);
            delete agent;
            agent = nullptr;
        }
    };
    if (finalizeCb != nullptr) {
        finalize = finalizeCb;
    }

    auto res = napi_wrap(env, result, reinterpret_cast<void*>(wantAgent), finalize, nullptr, nullptr);
    if (res != napi_ok && wantAgent != nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "napi_wrap failed:%{public}d", res);
        return nullptr;
    }
    return result;
}

void UnwrapWantAgent(napi_env env, napi_value jsParam, void **result)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    if (jsParam == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "null jsParam");
        return;
    }

    if (!CheckTypeForNapiValue(env, jsParam, napi_object)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "jsParam type error");
        return;
    }

    napi_unwrap(env, jsParam, result);
}

} // namespace AppExecFwk
} // namespace OHOS