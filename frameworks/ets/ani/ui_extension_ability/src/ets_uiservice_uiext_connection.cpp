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

#include "ets_uiservice_uiext_connection.h"

#include "ability_business_error.h"
#include "ani_common_want.h"
#include "ets_error_utils.h"
#include "ets_ui_service_proxy.h"
#include "hilog_tag_wrapper.h"
#include "ui_extension_servicehost_stub_impl.h"

namespace OHOS {
namespace AbilityRuntime {
namespace ETSUIServiceConnection {
static std::map<UIExtensionConnectionKey, sptr<EtsUIServiceUIExtConnection>, key_compare> gUiServiceExtConnects;
static std::recursive_mutex gUiServiceExtConnectsLock;
static int64_t gUiServiceExtConnectSn = 0;

void AddUIServiceExtensionConnection(AAFwk::Want &want, sptr<EtsUIServiceUIExtConnection> &connection)
{
    std::lock_guard<std::recursive_mutex> lock(gUiServiceExtConnectsLock);
    UIExtensionConnectionKey key;
    key.id = gUiServiceExtConnectSn;
    key.want = want;
    connection->SetConnectionId(key.id);
    gUiServiceExtConnects.emplace(key, connection);
    if (gUiServiceExtConnectSn < INT32_MAX) {
        gUiServiceExtConnectSn++;
    } else {
        gUiServiceExtConnectSn = 0;
    }
}

void RemoveUIServiceExtensionConnection(const int64_t &connectId)
{
    std::lock_guard<std::recursive_mutex> lock(gUiServiceExtConnectsLock);
    auto item = std::find_if(gUiServiceExtConnects.begin(), gUiServiceExtConnects.end(),
        [&connectId](const auto &obj) {
            return connectId == obj.first.id;
        });
    if (item != gUiServiceExtConnects.end()) {
        TAG_LOGD(AAFwkTag::UI_EXT, "found, erase");
        gUiServiceExtConnects.erase(item);
    } else {
        TAG_LOGD(AAFwkTag::UI_EXT, "not found");
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "gUiServiceExtConnects new size:%{public}zu", gUiServiceExtConnects.size());
}

void FindUIServiceExtensionConnection(const int64_t& connectId, AAFwk::Want& want,
    sptr<AbilityRuntime::EtsUIServiceUIExtConnection> &connection)
{
    std::lock_guard<std::recursive_mutex> lock(gUiServiceExtConnectsLock);
    TAG_LOGD(AAFwkTag::UI_EXT, "connection:%{public}d", static_cast<int32_t>(connectId));
    auto item = std::find_if(gUiServiceExtConnects.begin(), gUiServiceExtConnects.end(),
        [&connectId](const auto &obj) {
            return connectId == obj.first.id;
        });
    if (item != gUiServiceExtConnects.end()) {
        want = item->first.want;
        connection = item->second;
        TAG_LOGD(AAFwkTag::UI_EXT, "found ui service ext connection");
    } else {
        TAG_LOGD(AAFwkTag::UI_EXT, "not found ui service ext connection");
    }
}

void FindUIServiceExtensionConnection(ani_env *env, const AAFwk::Want& want, ani_object callback,
    sptr<AbilityRuntime::EtsUIServiceUIExtConnection> &connection)
{
    std::lock_guard<std::recursive_mutex> lock(gUiServiceExtConnectsLock);
    auto item = std::find_if(gUiServiceExtConnects.begin(), gUiServiceExtConnects.end(),
        [&want, env, callback](const auto &obj) {
        bool wantEquals = (obj.first.want.GetElement() == want.GetElement());
        ani_ref tmpCallbackRef = obj.second->GetEtsConnectionObject();
        bool callbackObjectEquals =
            AbilityRuntime::EtsUIServiceUIExtConnection::IsEtsCallbackObjectEquals(env, tmpCallbackRef, callback);
        return wantEquals && callbackObjectEquals;
    });
    if (item == gUiServiceExtConnects.end()) {
        return;
    }
    connection = item->second;
}
} // namespace UIServiceConnection

EtsUIServiceUIExtConnection::EtsUIServiceUIExtConnection(ani_vm *etsVm) : EtsUIExtensionConnection(etsVm)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "EtsUIServiceUIExtConnection");
    wptr<EtsUIServiceUIExtConnection> weakthis = this;
    serviceHostStub_ = sptr<EtsUIExtensionServiceHostStubImpl>::MakeSptr(weakthis);
}

void EtsUIServiceUIExtConnection::ReleaseReference(ani_env *env, ani_ref etsObjRef)
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

EtsUIServiceUIExtConnection::~EtsUIServiceUIExtConnection()
{
    TAG_LOGD(AAFwkTag::UI_EXT, "~EtsUIServiceUIExtConnection");
    serviceHostStub_ = nullptr;
    ReleaseObjectReference(serviceProxyObject_);
    ReleaseObjectReference(aniAsyncCallback_);
    for (auto& callback : duplicatedPendingCallbacks_) {
        ReleaseObjectReference(callback);
    }
    duplicatedPendingCallbacks_.clear();
}

void EtsUIServiceUIExtConnection::HandleOnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "HandleOnAbilityConnectDone called");
    bool isAttachThread = false;
    ani_env *env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetEnv failed");
        return;
    }
    if (aniAsyncCallback_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null aniAsyncCallback_");
        AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
        return;
    }
    sptr<EtsUIExtensionServiceHostStubImpl> hostStub = GetServiceHostStub();
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

void EtsUIServiceUIExtConnection::HandleOnAbilityDisconnectDone(const AppExecFwk::ElementName &element,
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
    SetProxyObject(nullptr);
    RemoveConnectionObject();
    duplicatedPendingCallbacks_.clear();
    ETSUIServiceConnection::RemoveUIServiceExtensionConnection(connectionId_);
    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

void EtsUIServiceUIExtConnection::SetAniAsyncCallback_(ani_object myCallback)
{
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

void EtsUIServiceUIExtConnection::AddDuplicatedPendingCallback(ani_object myCallback)
{
    duplicatedPendingCallbacks_.push_back(myCallback);
}

void EtsUIServiceUIExtConnection::ResolveDuplicatedPendingCallbacks(ani_env *env, ani_object proxyObj)
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

void EtsUIServiceUIExtConnection::RejectDuplicatedPendingCallbacks(ani_env *env, int32_t error)
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

void EtsUIServiceUIExtConnection::SetProxyObject(ani_object proxy)
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

ani_ref EtsUIServiceUIExtConnection::GetProxyObject()
{
    return serviceProxyObject_;
}

int32_t EtsUIServiceUIExtConnection::OnSendData(AAFwk::WantParams &data)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "OnSendData called");
    HandleOnSendData(data);
    return static_cast<int32_t>(AbilityErrorCode::ERROR_OK);
}

void EtsUIServiceUIExtConnection::HandleOnSendData(const OHOS::AAFwk::WantParams &data)
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

void EtsUIServiceUIExtConnection::CallObjectMethod(ani_env *env, const char *methodName, const char *signature, ...)
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

bool EtsUIServiceUIExtConnection::IsEtsCallbackObjectEquals(ani_env *env, ani_ref callback, ani_object value)
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
