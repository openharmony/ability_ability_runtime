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

#include "js_agent_extension_proxy.h"
#include "ability_business_error.h"
#include "hilog_tag_wrapper.h"
#include "js_error_utils.h"
#include "napi_common_want.h"
#include "napi_common_util.h"

namespace OHOS {
namespace AgentRuntime {
using namespace AbilityRuntime;
using namespace AppExecFwk;

static constexpr int32_t INDEX_ZERO = 0;
static constexpr int32_t ARGC_ONE = 1;

napi_value JsAgentExtensionProxy::CreateJsAgentExtensionProxy(napi_env env, const sptr<IRemoteObject>& impl,
    int64_t connectionId, const sptr<IRemoteObject>& hostProxy)
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "called");
    napi_value object = nullptr;
    napi_create_object(env, &object);
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null object");
        return CreateJsUndefined(env);
    }

    std::unique_ptr<JsAgentExtensionProxy> proxy = std::make_unique<JsAgentExtensionProxy>(impl, hostProxy);
    proxy->SetConnectionId(connectionId);
    napi_wrap(env, object, proxy.release(), Finalizer, nullptr, nullptr);

    const char *moduleName = "JsAgentExtensionProxy";
    BindNativeFunction(env, object, "sendData", moduleName, JsAgentExtensionProxy::SendData);
    return object;
}

void JsAgentExtensionProxy::Finalizer(napi_env env, void* data, void* hint)
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "called");
    std::unique_ptr<JsAgentExtensionProxy>(static_cast<JsAgentExtensionProxy*>(data));
}

JsAgentExtensionProxy::JsAgentExtensionProxy(const sptr<IRemoteObject>& impl, const sptr<IRemoteObject>& hostProxy)
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "called");
    proxy_ = iface_cast<IAgentExtension>(impl);
    hostProxy_ = hostProxy;
    if (proxy_ == nullptr) {
        TAG_LOGI(AAFwkTag::SER_ROUTER, "null proxy");
    }
}

JsAgentExtensionProxy::~JsAgentExtensionProxy()
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "called");
    proxy_ = nullptr;
    hostProxy_ = nullptr;
}

napi_value JsAgentExtensionProxy::SendData(napi_env env, napi_callback_info info)
{
    GET_NAPI_INFO_AND_CALL(env, info, JsAgentExtensionProxy, OnSendData);
}

napi_value JsAgentExtensionProxy::OnSendData(napi_env env, NapiCallbackInfo& info)
{
    if (proxy_ == nullptr || hostProxy_ == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null proxy_ or hostProxy_");
        ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return CreateJsUndefined(env);
    }
    if (info.argc < ARGC_ONE) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "invalid argc");
        ThrowTooFewParametersError(env);
        return CreateJsUndefined(env);
    }
    std::string data = "";
    data = AppExecFwk::UnwrapStringFromJS(env, info.argv[INDEX_ZERO], "");
    int32_t ret = proxy_->SendData(hostProxy_, data);
    if (ret != static_cast<int32_t>(AbilityErrorCode::ERROR_OK)) {
        TAG_LOGW(AAFwkTag::SER_ROUTER, "proxy_->SendData failed");
        ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
    }
    return CreateJsUndefined(env);
}
}
}
