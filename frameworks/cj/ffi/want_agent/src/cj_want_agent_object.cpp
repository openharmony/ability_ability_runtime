/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cj_lambda.h"
#include "cj_utils_ffi.h"
#include "cj_want_agent_ffi.h"
#include "hilog_tag_wrapper.h"
#include "js_native_api.h"
#include "napi/native_api.h"
#include "start_options.h"
#include "want_agent_helper.h"
#include "want_params_wrapper.h"

namespace OHOS {
namespace FfiWantAgent {

using OHOS::AbilityRuntime::WantAgent::WantAgent;
using OHOS::FFI::FFIData;

namespace {

constexpr int32_t INVALID_REMOTE_DATA_ID = -1;

napi_value WrapWantAgent(napi_env env, WantAgent* wantAgent)
{
    TAG_LOGD(AAFwkTag::WANTAGENT, "called");
    napi_value wantAgentClass = nullptr;
    napi_define_class(
        env, "WantAgentClass", NAPI_AUTO_LENGTH,
        [](napi_env env, napi_callback_info info) -> napi_value {
            napi_value thisVar = nullptr;
            napi_get_cb_info(env, info, nullptr, nullptr, &thisVar, nullptr);
            return thisVar;
        },
        nullptr, 0, nullptr, &wantAgentClass);
    napi_value result = nullptr;
    napi_new_instance(env, wantAgentClass, 0, nullptr, &result);
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "create instance failed");
        delete wantAgent;
        wantAgent = nullptr;
        return nullptr;
    }

    auto res = napi_wrap(
        env, result, reinterpret_cast<void*>(wantAgent),
        [](napi_env env, void* data, void* hint) {
            TAG_LOGD(AAFwkTag::WANTAGENT, "delete wantAgent");
            auto agent = static_cast<WantAgent*>(data);
            delete agent;
            agent = nullptr;
        },
        nullptr, nullptr);
    if (res != napi_ok && wantAgent != nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "napi_wrap failed:%{public}d", res);
        delete wantAgent;
        wantAgent = nullptr;
        return nullptr;
    }
    return result;
}

bool CheckTypeForNapiValue(napi_env env, napi_value param, napi_valuetype expectType)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, param, &valueType) != napi_ok) {
        return false;
    }
    return valueType == expectType;
}

void UnwrapWantAgent(napi_env env, napi_value jsParam, void** result)
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
} // namespace

extern "C" {
napi_value FfiConvertWantAgent2Napi(napi_env env, int64_t id)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);
    auto cjWantAgent = FFIData::GetData<CJWantAgent>(id);
    if (cjWantAgent == nullptr || cjWantAgent->wantAgent_ == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "cj wantagent nullptr");
        return undefined;
    }
    WantAgent* agent = new WantAgent(cjWantAgent->wantAgent_->GetPendingWant());
    if (agent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "cj wantaget malloc failed");
        return undefined;
    }

    return WrapWantAgent(env, agent);
}

int64_t FfiCreateWantAgentFromNapi(napi_env env, napi_value wantAgent)
{
    if (env == nullptr || wantAgent == nullptr) {
        return INVALID_REMOTE_DATA_ID;
    }
    WantAgent* napiAgent = nullptr;
    UnwrapWantAgent(env, wantAgent, reinterpret_cast<void**>(&napiAgent));
    if (napiAgent == nullptr) {
        return INVALID_REMOTE_DATA_ID;
    }

    auto nativeWantAgent = FFIData::Create<CJWantAgent>(std::make_shared<WantAgent>(napiAgent->GetPendingWant()));
    if (nativeWantAgent == nullptr) {
        return INVALID_REMOTE_DATA_ID;
    }

    return nativeWantAgent->GetID();
}
}
} // namespace FfiWantAgent
} // namespace OHOS