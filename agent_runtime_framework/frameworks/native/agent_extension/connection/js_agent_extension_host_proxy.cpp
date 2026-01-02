/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ability_business_error.h"
#include "agent_extension_host_proxy.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "js_agent_extension_host_proxy.h"
#include "js_error_utils.h"
#include "napi_common_want.h"
#include "napi_common_util.h"
#include "permission_constants.h"


namespace OHOS {
namespace AgentRuntime {
using namespace AbilityRuntime;
using namespace AppExecFwk;

static constexpr int32_t INDEX_ZERO = 0;
static constexpr int32_t ARGC_ONE = 1;

napi_ref JsAgentExtensionHostProxy::CreateJsAgentExtensionHostProxy(napi_env env, const sptr<IRemoteObject>& impl)
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "called");
    napi_value object = nullptr;
    napi_create_object(env, &object);
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null object");
        return nullptr;
    }

    std::unique_ptr<JsAgentExtensionHostProxy> proxy = std::make_unique<JsAgentExtensionHostProxy>(impl);
    napi_ref nref = nullptr;
    napi_status status = napi_wrap(env, object, proxy.release(), JsAgentExtensionHostProxy::Finalizer, nullptr, &nref);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "napi_wrap failed %{public}d", status);
    }
    const char *moduleName = "JsAgentExtensionHostProxy";
    BindNativeFunction(env, object, "sendData", moduleName, JsAgentExtensionHostProxy::SendData);
    return nref;
}

void JsAgentExtensionHostProxy::Finalizer(napi_env env, void* data, void* hint)
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "called");
    std::unique_ptr<JsAgentExtensionHostProxy>(static_cast<JsAgentExtensionHostProxy*>(data));
}

JsAgentExtensionHostProxy::JsAgentExtensionHostProxy(const sptr<IRemoteObject>& impl)
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "called");
    if (impl != nullptr) {
        proxy_ = iface_cast<IAgentExtensionHost>(impl);
    }
    if (proxy_ == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null proxy");
    }
}

JsAgentExtensionHostProxy::~JsAgentExtensionHostProxy()
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "called");
    proxy_ = nullptr;
}

napi_value JsAgentExtensionHostProxy::SendData(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_AND_CALL(env, info, JsAgentExtensionHostProxy, OnSendData);
}

napi_value JsAgentExtensionHostProxy::OnSendData(napi_env env, NapiCallbackInfo& info)
{
    if (proxy_ == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null proxy_");
        ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return CreateJsUndefined(env);
    }
    if (info.argc < ARGC_ONE) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "invalid argc");
        ThrowTooFewParametersError(env);
        return CreateJsUndefined(env);
    }
    string data = "";
    data = AppExecFwk::UnwrapStringFromJS(env, info.argv[INDEX_ZERO], "");
    int32_t ret = proxy_->SendData(data);
    if (ret != static_cast<int32_t>(AbilityErrorCode::ERROR_OK)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "SendData failed");
        ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
    }
    return CreateJsUndefined(env);
}
}
}
