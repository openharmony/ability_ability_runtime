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

#include "ets_uiservice_ability_connection.h"

#include "ability_business_error.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ets_error_utils.h"
#include "ets_ui_ability_servicehost_stub_impl.h"
#include "ets_ui_service_proxy.h"
#include "hilog_tag_wrapper.h"
#include "ui_ability_servicehost_stub_impl.h"

namespace OHOS {
namespace AbilityRuntime {

namespace EtsUIServiceConnection {
static std::map<ConnectionKey, sptr<EtsUIServiceExtAbilityConnection>, KeyCompare> g_uiServiceExtensionConnects;
static std::recursive_mutex g_uiServiceExtensionConnectsLock_;
static int64_t g_uiServiceExtensionSerialNumber = 0;

// This function has to be called from engine thread
void RemoveUIServiceAbilityConnection(int64_t connectId)
{
    std::lock_guard<std::recursive_mutex> lock(g_uiServiceExtensionConnectsLock_);
    auto item = std::find_if(g_uiServiceExtensionConnects.begin(), g_uiServiceExtensionConnects.end(),
    [&connectId](const auto &obj) {
        return connectId == obj.first.id;
    });
    if (item != g_uiServiceExtensionConnects.end()) {
        TAG_LOGD(AAFwkTag::UI_EXT, "exist, remove");
        if (item->second) {
            item->second->RemoveConnectionObject();
            item->second->SetProxyObject(nullptr);
        }
        g_uiServiceExtensionConnects.erase(item);
    } else {
        TAG_LOGD(AAFwkTag::UI_EXT, "not exist");
    }
    TAG_LOGI(AAFwkTag::UI_EXT, "connects new size:%{public}zu", g_uiServiceExtensionConnects.size());
}

int64_t InsertUIServiceAbilityConnection(sptr<EtsUIServiceExtAbilityConnection> connection, const AAFwk::Want& want)
{
    std::lock_guard<std::recursive_mutex> lock(g_uiServiceExtensionConnectsLock_);
    if (connection == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null connection");
        return -1;
    }
    int64_t connectId = g_uiServiceExtensionSerialNumber;
    ConnectionKey key;
    key.id = g_uiServiceExtensionSerialNumber;
    key.want = want;
    key.accountId = 0;
    connection->SetConnectionId(key.id);
    g_uiServiceExtensionConnects.emplace(key, connection);
    if (g_uiServiceExtensionSerialNumber < INT32_MAX) {
        g_uiServiceExtensionSerialNumber++;
    } else {
        g_uiServiceExtensionSerialNumber = 0;
    }
    return connectId;
}

void FindUIServiceAbilityConnection(const int64_t& connectId, AAFwk::Want& want,
    sptr<EtsUIServiceExtAbilityConnection>& connection)
{
    std::lock_guard<std::recursive_mutex> lock(g_uiServiceExtensionConnectsLock_);
    TAG_LOGI(AAFwkTag::UI_EXT, "connection:%{public}d", static_cast<int32_t>(connectId));
    auto item = std::find_if(g_uiServiceExtensionConnects.begin(), g_uiServiceExtensionConnects.end(),
        [&connectId](const auto &obj) {
            return connectId == obj.first.id;
        });
    if (item != g_uiServiceExtensionConnects.end()) {
        want = item->first.want;
        connection = item->second;
        TAG_LOGI(AAFwkTag::UI_EXT, "found");
    } else {
        TAG_LOGI(AAFwkTag::UI_EXT, "not found");
    }
}

void FindUIServiceAbilityConnection(ani_env *env, const AAFwk::Want &want, ani_object callback,
    sptr<EtsUIServiceExtAbilityConnection> &connection)
{
    std::lock_guard<std::recursive_mutex> lock(g_uiServiceExtensionConnectsLock_);
    auto item = std::find_if(g_uiServiceExtensionConnects.begin(), g_uiServiceExtensionConnects.end(),
        [&want, env, callback](const auto &obj) {
        bool wantEquals = (obj.first.want.GetElement() == want.GetElement());
        ani_ref tmpCallbackRef = obj.second->GetEtsConnectionObject();
        bool callbackObjectEquals =
            EtsUIServiceExtAbilityConnection::IsEtsCallbackObjectEquals(env, tmpCallbackRef, callback);
        return wantEquals && callbackObjectEquals;
    });
    if (item == g_uiServiceExtensionConnects.end()) {
        return;
    }
    connection = item->second;
}
}

EtsUIServiceExtAbilityConnection::EtsUIServiceExtAbilityConnection(ani_vm *etsVm) : ETSAbilityConnection(etsVm)
{
    TAG_LOGD(AAFwkTag::UISERVC_EXT, "EtsUIServiceExtAbilityConnection");
    wptr<EtsUIServiceExtAbilityConnection> weakthis = this;
    serviceHostStub_ = sptr<EtsUIAbilityServiceHostStubImpl>::MakeSptr(weakthis);
}

EtsUIServiceExtAbilityConnection::~EtsUIServiceExtAbilityConnection()
{
    TAG_LOGI(AAFwkTag::UISERVC_EXT, "~EtsUIServiceExtAbilityConnection");
    serviceHostStub_ = nullptr;
    ReleaseObjectReference(serviceProxyObject_);
    ReleaseObjectReference(aniAsyncCallback_);
    for (auto& callback : duplicatedPendingCallbacks_) {
        ReleaseObjectReference(callback);
    }
    duplicatedPendingCallbacks_.clear();
}

void EtsUIServiceExtAbilityConnection::HandleOnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    TAG_LOGD(AAFwkTag::UISERVC_EXT, "HandleOnAbilityConnectDone called");
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetEnv failed");
        return;
    }
    if (aniAsyncCallback_ ==  nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null napiAsyncTask_");
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    sptr<EtsUIAbilityServiceHostStubImpl> hostStub = GetServiceHostStub();
    sptr<IRemoteObject> hostProxy = nullptr;
    if (hostStub != nullptr) {
        hostProxy = hostStub->AsObject();
    }
    ani_object proxyObj = AAFwk::EtsUIServiceProxy::CreateEtsUIServiceProxy(env, remoteObject,
        connectionId_, hostProxy);
    SetProxyObject(proxyObj);
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(aniAsyncCallback_),
        EtsErrorUtil::CreateError(env, static_cast<AbilityErrorCode>(AbilityErrorCode::ERROR_OK)), proxyObj);

    ResolveDuplicatedPendingCallbacks(env, proxyObj);
    ReleaseObjectReference(proxyObj);
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

void EtsUIServiceExtAbilityConnection::ReleaseReference(ani_env *env, ani_ref etsObjRef)
{
    if (env == nullptr || etsObjRef == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "env or etsObjRef null");
        return;
    }
    ani_status status = ANI_ERROR;
    if ((status = env->GlobalReference_Delete(etsObjRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GlobalReference_Delete status: %{public}d", status);
    }
}

void EtsUIServiceExtAbilityConnection::CallObjectMethod(ani_env *env, const char *methodName,
    const char *signature, ...)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "call method:%{public}s", methodName);
    if (env == nullptr || etsConnectionRef_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "etsVm_ nullptr");
        return;
    }
    env->ResetError();
    va_list args;
    va_start(args, signature);
    ani_status status = ANI_ERROR;
    if ((status = env->Object_CallMethodByName_Void(reinterpret_cast<ani_object>(etsConnectionRef_),
        methodName, signature, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to CallObjectMethod , status: %{public}d", status);
    }
    va_end(args);
}

void EtsUIServiceExtAbilityConnection::HandleOnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
    int resultCode)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "HandleOnAbilityDisconnectDone called");
    if (aniAsyncCallback_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null napiAsyncTask_");
        return;
    }
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetEnv failed");
        return;
    }
    AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(aniAsyncCallback_),
        EtsErrorUtil::CreateError(env, static_cast<AbilityErrorCode>(AbilityErrorCode::ERROR_CODE_INNER)),
        AAFwk::EtsUIServiceProxy::CreateEmptyProxyObject(env));

    RejectDuplicatedPendingCallbacks(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER));
    ReleaseReference(env, aniAsyncCallback_);
    CallObjectMethod(env, "onDisconnect", nullptr);
    EtsUIServiceConnection::RemoveUIServiceAbilityConnection(connectionId_);
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

void EtsUIServiceExtAbilityConnection::SetAniAsyncCallback_(ani_object myCallback)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "SetAniAsyncCallback_ called");
    if (myCallback == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "myCallback is null");
        return;
    }
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "etsVm_ is null");
        return;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) != ANI_OK || env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetEnv failed status: %{public}d", status);
        return;
    }
    ani_ref global = nullptr;
    if ((status = env->GlobalReference_Create(myCallback, &global)) != ANI_OK
        || global == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GlobalReference_Create failed status: %{public}d", status);
        return;
    }
    aniAsyncCallback_ = global;
    TAG_LOGD(AAFwkTag::UI_EXT, "SetAniAsyncCallback_ success");
}

void EtsUIServiceExtAbilityConnection::AddDuplicatedPendingCallback(ani_object myCallback)
{
    duplicatedPendingCallbacks_.push_back(myCallback);
}

void EtsUIServiceExtAbilityConnection::ResolveDuplicatedPendingCallbacks(ani_env *env, ani_object proxyObj)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "ResolveDuplicatedPendingCallbacks, size: %{public}zu",
        duplicatedPendingCallbacks_.size());
    for (auto &callback : duplicatedPendingCallbacks_) {
        if (callback == nullptr) {
            continue;
        }
        AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callback),
            EtsErrorUtil::CreateError(env, static_cast<AbilityErrorCode>(AbilityErrorCode::ERROR_OK)), proxyObj);
        ReleaseReference(env, callback);
    }
    duplicatedPendingCallbacks_.clear();
}

void EtsUIServiceExtAbilityConnection::RejectDuplicatedPendingCallbacks(ani_env *env, int32_t error)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "RejectDuplicatedPendingCallbacks, size: %{public}zu",
        duplicatedPendingCallbacks_.size());
    for (auto &callback : duplicatedPendingCallbacks_) {
        if (callback == nullptr) {
            continue;
        }
        AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callback),
            AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(
                env, static_cast<int32_t>(error)), AAFwk::EtsUIServiceProxy::CreateEmptyProxyObject(env));
        ReleaseReference(env, callback);
    }
    duplicatedPendingCallbacks_.clear();
}

void EtsUIServiceExtAbilityConnection::SetProxyObject(ani_object proxy)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "SetProxyObject");
    if (proxy == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "etsVm_ nullptr");
        return;
    }
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "etsVm_ nullptr");
        return;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) != ANI_OK || env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetEnv failed status: %{public}d", status);
        return;
    }
    ani_ref global = nullptr;
    if ((status = env->GlobalReference_Create(proxy, &global)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        return;
    }
    ReleaseObjectReference(serviceProxyObject_);
    serviceProxyObject_ = global;
}

ani_ref EtsUIServiceExtAbilityConnection::GetProxyObject()
{
    return serviceProxyObject_;
}

int32_t EtsUIServiceExtAbilityConnection::OnSendData(OHOS::AAFwk::WantParams &data)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "OnSendData called");
    HandleOnSendData(data);
    return static_cast<int32_t>(AbilityErrorCode::ERROR_OK);
}

void EtsUIServiceExtAbilityConnection::HandleOnSendData(const OHOS::AAFwk::WantParams &data)
{
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null aniEnv");
        return;
    }
    ani_ref aniWantParams = AppExecFwk::WrapWantParams(env, data);
    if (aniWantParams == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null aniWantParams");
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    CallObjectMethod(env, "onData", nullptr, aniWantParams);
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

bool EtsUIServiceExtAbilityConnection::IsEtsCallbackObjectEquals(ani_env *env, ani_ref callback, ani_object value)
{
    if (env == nullptr || callback == nullptr || value == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "env or callback or value null");
        return false;
    }
    ani_boolean isEquals = ANI_FALSE;
    ani_status status = ANI_ERROR;
    if ((status = env->Reference_StrictEquals(callback, value, &isEquals)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Reference_StrictEquals failed status: %{public}d", status);
        return false;
    }
    return isEquals == ANI_TRUE;
}
} // namespace AbilityRuntime
} // namespace OHOS
