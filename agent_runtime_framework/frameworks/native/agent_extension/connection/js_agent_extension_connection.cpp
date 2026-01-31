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
#include "agnet_extension_host_stub_impl.h"
#include "hilog_tag_wrapper.h"
#include "js_agent_extension_connection.h"
#include "js_agent_extension_proxy.h"
#include "js_error_utils.h"
#include "napi_common_want.h"

namespace OHOS {
namespace AgentRuntime {
constexpr size_t ARGC_ONE = 1;

namespace AgentExtensionConnection {
static std::map<ConnectionKey, sptr<JSAgentExtensionConnection>, KeyCompare> g_agentExtensionConnects;
static std::recursive_mutex g_agentExtensionConnectsLock_;
static int64_t g_agentExtensionSerialNumber = 0;

// This function has to be called from engine thread
void RemoveAgentExtensionConnection(int64_t connectId)
{
    std::lock_guard<std::recursive_mutex> lock(g_agentExtensionConnectsLock_);
    auto item = std::find_if(g_agentExtensionConnects.begin(), g_agentExtensionConnects.end(),
    [&connectId](const auto &obj) {
        return connectId == obj.first.id;
    });
    if (item != g_agentExtensionConnects.end()) {
        TAG_LOGD(AAFwkTag::SER_ROUTER, "exist, remove");
        if (item->second) {
            item->second->RemoveConnectionObject();
            item->second->SetProxyObject(nullptr);
        }
        g_agentExtensionConnects.erase(item);
    } else {
        TAG_LOGD(AAFwkTag::SER_ROUTER, "not exist");
    }
    TAG_LOGI(AAFwkTag::SER_ROUTER, "connects new size:%{public}zu", g_agentExtensionConnects.size());
}

int64_t InsertAgentExtensionConnection(sptr<JSAgentExtensionConnection> connection, const AAFwk::Want &want)
{
    std::lock_guard<std::recursive_mutex> lock(g_agentExtensionConnectsLock_);
    if (connection == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null connection");
        return -1;
    }
    int64_t connectId = g_agentExtensionSerialNumber;
    ConnectionKey key;
    key.id = g_agentExtensionSerialNumber;
    key.want = want;
    key.accountId = 0;
    connection->SetConnectionId(key.id);
    g_agentExtensionConnects.emplace(key, connection);
    if (g_agentExtensionSerialNumber < INT32_MAX) {
        g_agentExtensionSerialNumber++;
    } else {
        g_agentExtensionSerialNumber = 0;
    }
    return connectId;
}

void FindAgentExtensionConnection(const int64_t& connectId, AAFwk::Want& want,
    sptr<JSAgentExtensionConnection>& connection)
{
    std::lock_guard<std::recursive_mutex> lock(g_agentExtensionConnectsLock_);
    TAG_LOGI(AAFwkTag::SER_ROUTER, "connection:%{public}d", static_cast<int32_t>(connectId));
    auto item = std::find_if(g_agentExtensionConnects.begin(), g_agentExtensionConnects.end(),
        [&connectId](const auto &obj) {
            return connectId == obj.first.id;
        });
    if (item != g_agentExtensionConnects.end()) {
        want = item->first.want;
        connection = item->second;
        TAG_LOGI(AAFwkTag::SER_ROUTER, "found");
    } else {
        TAG_LOGI(AAFwkTag::SER_ROUTER, "not found");
    }
}

void FindAgentExtensionConnection(napi_env env, AAFwk::Want& want, napi_value callback,
    sptr<JSAgentExtensionConnection>& connection)
{
    std::lock_guard<std::recursive_mutex> lock(g_agentExtensionConnectsLock_);
    auto item = std::find_if(g_agentExtensionConnects.begin(), g_agentExtensionConnects.end(),
        [&want, env, callback](const auto &obj) {
        bool wantEquals = (obj.first.want.GetElement() == want.GetElement());
        std::unique_ptr<NativeReference>& tempCallbackPtr = obj.second->GetJsConnectionObject();
        bool callbackObjectEquals =
            JSAgentExtensionConnection::IsJsCallbackObjectEquals(env, tempCallbackPtr, callback);
        return wantEquals && callbackObjectEquals;
    });
    if (item == g_agentExtensionConnects.end()) {
        return;
    }
    connection = item->second;
}
} // namespace AgentExtensionConnection

JSAgentExtensionConnection::JSAgentExtensionConnection(napi_env env) : JSAbilityConnection(env)
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "JSAgentExtensionConnection");
    wptr<JSAgentExtensionConnection> weakthis = this;
    serviceHostStub_ = sptr<AgentExtensionHostStubImpl>::MakeSptr(weakthis);
}

JSAgentExtensionConnection::~JSAgentExtensionConnection()
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "~JSAgentExtensionConnection");
    serviceHostStub_ = nullptr;
    napiAsyncTask_ = nullptr;
    ReleaseNativeReference(serviceProxyObject_.release());
}

void JSAgentExtensionConnection::HandleOnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    if (napiAsyncTask_ != nullptr) {
        TAG_LOGI(AAFwkTag::SER_ROUTER, "HandleOnAbilityConnectDone, CreateJsUIServiceProxy");
        sptr<AgentExtensionHostStubImpl> hostStub = GetServiceHostStub();
        sptr<IRemoteObject> hostProxy = nullptr;
        if (hostStub != nullptr) {
            hostProxy = hostStub->AsObject();
        }
        napi_value proxy = JsAgentExtensionProxy::CreateJsAgentExtensionProxy(env_, remoteObject,
            connectionId_, hostProxy);
        SetProxyObject(proxy);
        napiAsyncTask_->ResolveWithNoError(env_, proxy);

        ResolveDuplicatedPendingTask(env_, proxy);
    } else {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "HandleOnAbilityConnectDone, napiAsyncTask_ null");
    }
    napiAsyncTask_ = nullptr;
}

void JSAgentExtensionConnection::HandleOnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
    int resultCode)
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "HandleOnAbilityDisconnectDone");
    if (napiAsyncTask_ != nullptr) {
        napi_value innerError = CreateJsError(env_, AbilityErrorCode::ERROR_CODE_INNER);
        napiAsyncTask_->Reject(env_, innerError);
        RejectDuplicatedPendingTask(env_, innerError);
        napiAsyncTask_ = nullptr;
    }

    CallJsOnDisconnect();
    AgentExtensionConnection::RemoveAgentExtensionConnection(connectionId_);
}

void JSAgentExtensionConnection::SetNapiAsyncTask(std::shared_ptr<NapiAsyncTask>& task)
{
    napiAsyncTask_ = task;
}

void JSAgentExtensionConnection::AddDuplicatedPendingTask(std::unique_ptr<NapiAsyncTask>& task)
{
    duplicatedPendingTaskList_.push_back(std::move(task));
}

void JSAgentExtensionConnection::ResolveDuplicatedPendingTask(napi_env env, napi_value proxy)
{
    for (auto &task : duplicatedPendingTaskList_) {
        if (task != nullptr) {
            task->ResolveWithNoError(env, proxy);
        }
    }
    duplicatedPendingTaskList_.clear();
}

void JSAgentExtensionConnection::RejectDuplicatedPendingTask(napi_env env, napi_value error)
{
    for (auto &task : duplicatedPendingTaskList_) {
        if (task != nullptr) {
            task->Reject(env, error);
        }
    }
    duplicatedPendingTaskList_.clear();
}

void JSAgentExtensionConnection::SetProxyObject(napi_value proxy)
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "SetProxyObject");
    serviceProxyObject_.reset();
    if (proxy != nullptr) {
        napi_ref ref = nullptr;
        napi_create_reference(env_, proxy, 1, &ref);
        serviceProxyObject_ = std::unique_ptr<NativeReference>(reinterpret_cast<NativeReference*>(ref));
    }
}

napi_value JSAgentExtensionConnection::GetProxyObject()
{
    if (serviceProxyObject_ == nullptr) {
        return nullptr;
    }
    return serviceProxyObject_->GetNapiValue();
}

int32_t JSAgentExtensionConnection::OnSendData(std::string &data)
{
    wptr<JSAgentExtensionConnection> connection = this;
    std::unique_ptr<NapiAsyncTask::CompleteCallback> complete = std::make_unique<NapiAsyncTask::CompleteCallback>
        ([connection, dataParam = data](napi_env env, NapiAsyncTask &task, int32_t status) {
            sptr<JSAgentExtensionConnection> connectionSptr = connection.promote();
            if (!connectionSptr) {
                TAG_LOGE(AAFwkTag::SER_ROUTER, "null connectionSptr");
                return;
            }
            connectionSptr->HandleOnSendData(dataParam);
        });

    napi_ref callback = nullptr;
    std::unique_ptr<NapiAsyncTask::ExecuteCallback> execute = nullptr;
    NapiAsyncTask::Schedule("JSAgentExtensionConnection::SendData",
        env_, std::make_unique<NapiAsyncTask>(callback, std::move(execute), std::move(complete)));

    return static_cast<int32_t>(AbilityErrorCode::ERROR_OK);
}

void JSAgentExtensionConnection::HandleOnSendData(const std::string &data)
{
    napi_value argv[] = { AbilityRuntime::CreateJsValue(env_, data) };
    CallObjectMethod("onData", argv, ARGC_ONE);
}

void JSAgentExtensionConnection::CallJsOnDisconnect()
{
    TAG_LOGI(AAFwkTag::SER_ROUTER, "called");
    CallObjectMethod("onDisconnect", nullptr, 0);
}

bool JSAgentExtensionConnection::IsJsCallbackObjectEquals(napi_env env,
    std::unique_ptr<NativeReference> &callback, napi_value value)
{
    if (value == nullptr || callback == nullptr) {
        return callback.get() == reinterpret_cast<NativeReference*>(value);
    }
    auto object = callback->GetNapiValue();
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null object");
        return false;
    }
    bool result = false;
    if (napi_strict_equals(env, object, value, &result) != napi_ok) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "object does not match value");
        return false;
    }
    return result;
}
} // namespace AgentRuntime
} // namespace OHOS
