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

#include "ets_service_extension.h"

#include "ability_info.h"
#include "ability_manager_client.h"
#include "ani_common_want.h"
#include "ani_remote_object.h"
#include "configuration_utils.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "js_service_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;
namespace {
constexpr const char *CLASSNAME_SERVICE_ABILITY =
    "L@ohos/app/ability/ServiceExtensionAbility/ServiceExtensionAbility;";
constexpr const char *NATIVE_ONCONNECT_CALLBACK_SIGNATURE = "L@ohos/rpc/rpc/RemoteObject;:Z";
constexpr const char *ON_CREATE_SIGNATURE = "L@ohos/app/ability/Want/Want;:V";
constexpr const char *VOID_SIGNATURE = ":V";
constexpr const char *ON_CONNECT_SIGNATURE = "L@ohos/app/ability/Want/Want;:Lstd/core/Object;";
constexpr const char *CHECK_PROMISE_SIGNATURE = "Lstd/core/Object;:Z";
constexpr const char *CALL_PROMISE_SIGNATURE = "Lstd/core/Object;:Z";
constexpr const char *ON_DISCONNECT_SIGNATURE = "L@ohos/app/ability/Want/Want;:V";
constexpr const char *ON_REQUEST_SIGNATURE = "L@ohos/app/ability/Want/Want;D:V";

void DisconnectPromiseCallback(ani_env *env, ani_object aniObj)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "DisconnectPromiseCallback");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return;
    }
    ani_long disconnectCallbackPoint = 0;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Long(aniObj, "disconnectCallbackPoint", &disconnectCallbackPoint)) !=
        ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return;
    }
    auto *callbackInfo = reinterpret_cast<AppExecFwk::AbilityTransactionCallbackInfo<> *>(disconnectCallbackPoint);
    if (callbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null callbackInfo");
        return;
    }
    callbackInfo->Call();
    AppExecFwk::AbilityTransactionCallbackInfo<>::Destroy(callbackInfo);
}

void ConnectPromiseCallback(ani_env *env, ani_object aniObj, ani_object obj)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "ConnectPromiseCallback");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return;
    }
    ani_long connectCallbackPoint = 0;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Long(aniObj, "connectCallbackPoint", &connectCallbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return;
    }
    auto remoteObject = AniGetNativeRemoteObject(env, obj);
    if (remoteObject == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null remoteObject");
    }
    auto *callbackInfo =
        reinterpret_cast<AppExecFwk::AbilityTransactionCallbackInfo<sptr<IRemoteObject>> *>(connectCallbackPoint);
    if (callbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null callbackInfo");
        return;
    }

    callbackInfo->Call(remoteObject);
    AppExecFwk::AbilityTransactionCallbackInfo<sptr<IRemoteObject>>::Destroy(callbackInfo);
}
} // namespace

EtsServiceExtension *EtsServiceExtension::Create(const std::unique_ptr<Runtime> &runtime)
{
    return new EtsServiceExtension(static_cast<ETSRuntime &>(*runtime));
}

EtsServiceExtension::EtsServiceExtension(ETSRuntime &etsRuntime) : etsRuntime_(etsRuntime) {}
EtsServiceExtension::~EtsServiceExtension()
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "EtsServiceExtension destory");
    auto context = GetContext();
    if (context) {
        context->Unbind();
    }
}

void EtsServiceExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "EtsServiceExtension init");
    if ((token == nullptr) || (application == nullptr) || (handler == nullptr) || (record == nullptr)) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "init failed, some obj null");
        return;
    }
    Extension::Init(record, application, handler, token);
    if (Extension::abilityInfo_ == nullptr || Extension::abilityInfo_->srcEntrance.empty()) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "EtsServiceExtension Init abilityInfo error");
        return;
    }
    std::string srcPath(Extension::abilityInfo_->moduleName + "/");
    srcPath.append(Extension::abilityInfo_->srcEntrance);
    auto pos = srcPath.rfind(".");
    if (pos != std::string::npos) {
        srcPath.erase(pos);
        srcPath.append(".abc");
    }
    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    etsObj_ = etsRuntime_.LoadModule(moduleName, srcPath, abilityInfo_->hapPath,
        abilityInfo_->compileMode == AppExecFwk::CompileMode::ES_MODULE, false, abilityInfo_->srcEntrance);
    if (etsObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null etsObj");
        return;
    }
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return;
    }
    std::array functions = {
        ani_native_function {
            "nativeOnDisconnectCallback", VOID_SIGNATURE, reinterpret_cast<void *>(DisconnectPromiseCallback) },
        ani_native_function { "nativeOnConnectCallback", NATIVE_ONCONNECT_CALLBACK_SIGNATURE,
            reinterpret_cast<void *>(ConnectPromiseCallback) },
    };
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(CLASSNAME_SERVICE_ABILITY, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status: %{public}d", status);
        return;
    }
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "Class_BindNativeMethods is fail %{public}d", status);
        return;
    }
}

void EtsServiceExtension::OnStart(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "OnStart");
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "env not found Ability.ets");
        return;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
        return;
    }

    CallObjectMethod(false, "onCreate", ON_CREATE_SIGNATURE, wantRef);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
}

void EtsServiceExtension::OnStop()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "OnStop");
    ServiceExtension::OnStop();
    CallObjectMethod(false, "onDestroy", VOID_SIGNATURE);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
}

sptr<IRemoteObject> EtsServiceExtension::OnConnect(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "OnConnect");
    Extension::OnConnect(want);
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return nullptr;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
        return nullptr;
    }
    ani_ref result = CallObjectMethod(true, "onConnect", ON_CONNECT_SIGNATURE, wantRef);
    auto obj = reinterpret_cast<ani_object>(result);
    auto remoteObj = AniGetNativeRemoteObject(env, obj);
    if (remoteObj == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "remoteObj null");
        return nullptr;
    }
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
    return remoteObj;
}

sptr<IRemoteObject> EtsServiceExtension::OnConnect(const AAFwk::Want &want,
    AppExecFwk::AbilityTransactionCallbackInfo<sptr<IRemoteObject>> *callbackInfo, bool &isAsyncCallback)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "OnConnect");
    Extension::OnConnect(want);
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return nullptr;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
        return nullptr;
    }
    ani_long connectCallbackPoint = (ani_long)callbackInfo;
    ani_status status = ANI_ERROR;
    ani_field callbackField = nullptr;
    if ((status = env->Class_FindField(etsObj_->aniCls, "connectCallbackPoint", &callbackField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetField_Long(etsObj_->aniObj, callbackField, connectCallbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    ani_ref aniRemoteRef = CallObjectMethod(true, "onConnect", ON_CONNECT_SIGNATURE, wantRef);
    auto aniRemoteobj = reinterpret_cast<ani_object>(aniRemoteRef);
    ani_method method {};
    if ((status = env->Class_FindMethod(etsObj_->aniCls, "checkPromise", CHECK_PROMISE_SIGNATURE, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    ani_boolean isPromise = false;
    if ((status = env->Object_CallMethod_Boolean(etsObj_->aniObj, method, &isPromise, aniRemoteobj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    if (!isPromise) {
        isAsyncCallback = false;
        auto remoteObj = AniGetNativeRemoteObject(env, aniRemoteobj);
        if (remoteObj == nullptr) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "null remoteObj");
        }
        return remoteObj;
    }
    return OnConnectInner(env, aniRemoteobj, isAsyncCallback);
}

sptr<IRemoteObject> EtsServiceExtension::OnConnectInner(ani_env *env, ani_object &aniRemoteobj, bool &isAsyncCallback)
{
    ani_status status = ANI_ERROR;
    ani_method method {};
    if ((status = env->Class_FindMethod(etsObj_->aniCls, "callPromise", CALL_PROMISE_SIGNATURE, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    ani_boolean callResult = false;
    if ((status = env->Object_CallMethod_Boolean(etsObj_->aniObj, method, &callResult, aniRemoteobj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    isAsyncCallback = callResult;
    return nullptr;
}

void EtsServiceExtension::OnDisconnect(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "OnDisconnect");
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
        return;
    }
    CallObjectMethod(false, "onDisconnect", ON_DISCONNECT_SIGNATURE, wantRef);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
}

void EtsServiceExtension::OnDisconnect(
    const AAFwk::Want &want, AppExecFwk::AbilityTransactionCallbackInfo<> *callbackInfo, bool &isAsyncCallback)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "OnDisconnect");
    auto env = etsRuntime_.GetAniEnv();
    if (env) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
        return;
    }
    if (callbackInfo == nullptr) {
        isAsyncCallback = false;
        OnDisconnect(want);
        return;
    }
    ani_long disconnectCallbackPoint = (ani_long)callbackInfo;
    ani_status status = ANI_ERROR;
    ani_field field = nullptr;
    if ((status = env->Class_FindField(etsObj_->aniCls, "disconnectCallbackPoint", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return;
    }
    if ((status = env->Object_SetField_Long(etsObj_->aniObj, field, disconnectCallbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return;
    }
    CallObjectMethod(false, "callOnDisconnect", ON_DISCONNECT_SIGNATURE, wantRef);
}

void EtsServiceExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "OnCommand");
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
        return;
    }
    ani_int iStartId = static_cast<ani_int>(startId);
    CallObjectMethod(false, "onRequest", ON_REQUEST_SIGNATURE, wantRef, iStartId);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
    return;
}

ani_ref EtsServiceExtension::CallObjectMethod(bool withResult, const char *name, const char *signature, ...)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, std::string("CallObjectMethod:") + name);
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(etsObj_->aniCls, name, signature, &method)) != ANI_OK) {
        return nullptr;
    }
    if (method == nullptr) {
        return nullptr;
    }
    ani_ref res = nullptr;
    va_list args;
    if (withResult) {
        va_start(args, signature);
        if ((status = env->Object_CallMethod_Ref_V(etsObj_->aniObj, method, &res, args)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
            return nullptr;
        }
        va_end(args);
        return res;
    }
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(etsObj_->aniObj, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
    }
    va_end(args);
    return nullptr;
}
void EtsServiceExtension::OnConfigurationUpdated(const AppExecFwk::Configuration &configuration) {}

void EtsServiceExtension::ConfigurationUpdated() {}

void EtsServiceExtension::Dump(const std::vector<std::string> &params, std::vector<std::string> &info) {}
} // namespace AbilityRuntime
} // namespace OHOS