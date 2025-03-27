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

#include "sts_service_extension.h"
#include "ability_info.h"
#include "ability_manager_client.h"
#include "ani_common_want.h"
#include "ani_remote_object.h"
#include "configuration_utils.h"
#include "hitrace_meter.h"
#include "hilog_tag_wrapper.h"
#include "insight_intent_execute_param.h"
#include "insight_intent_execute_result.h"
#include "insight_intent_executor_info.h"
#include "insight_intent_executor_mgr.h"
#include "js_service_extension_context.h"
#ifdef SUPPORT_GRAPHICS
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "window_scene.h"
#endif

namespace OHOS {
namespace AbilityRuntime {

void DisconnectPromiseCallback(ani_env* env, ani_object aniObj)
{
    TAG_LOGI(AAFwkTag::SERVICE_EXT, "DisconnectPromiseCallback");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return;
    }
    ani_long disconnectCallbackPoint = 0;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Long(aniObj, "disconnectCallbackPoint",
        &disconnectCallbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return;
    }
    auto *callbackInfo =
        reinterpret_cast<AppExecFwk::AbilityTransactionCallbackInfo<> *>(disconnectCallbackPoint);
    if (callbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null callbackInfo");
        return;
    }
    callbackInfo->Call();
    AppExecFwk::AbilityTransactionCallbackInfo<>::Destroy(callbackInfo);
}

void ConnectPromiseCallback(ani_env* env, ani_object aniObj, ani_object obj)
{
    TAG_LOGI(AAFwkTag::SERVICE_EXT, "PromiseCallback");
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
        reinterpret_cast<AppExecFwk::AbilityTransactionCallbackInfo<sptr<IRemoteObject>>*>(connectCallbackPoint);
    if (callbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null callbackInfo");
        return;
    }

    callbackInfo->Call(remoteObject);
    AppExecFwk::AbilityTransactionCallbackInfo<sptr<IRemoteObject>>::Destroy(callbackInfo);
}

[[maybe_unused]]ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "ANI_Constructor");
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::DELEGATOR, "GetEnv failed status : %{public}d", status);
        return ANI_NOT_FOUND;
    }

    static const char *className = "L@ohos/app/ability/ServiceExtensionAbility/ServiceExtensionAbility;";
    ani_class cls;
    status = env->FindClass(className, &cls);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "FindClass is fail %{public}d", status);
        return ANI_ERROR;
    }

    std::array functions = {
        ani_native_function { "nativeOnDisconnectCallback", ":V", reinterpret_cast<void*>(DisconnectPromiseCallback) },
        ani_native_function { "nativeOnConnectCallback", nullptr, reinterpret_cast<void*>(ConnectPromiseCallback) },
    };

    status = env->Class_BindNativeMethods(cls, functions.data(), functions.size());
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "Class_BindNativeMethods is fail %{public}d", status);
        return ANI_ERROR;
    };
    *result = ANI_VERSION_1;
    TAG_LOGI(AAFwkTag::DELEGATOR, "ANI_Constructor finish");
    return ANI_OK;
}

using namespace OHOS::AppExecFwk;

StsServiceExtension* StsServiceExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    return new StsServiceExtension(static_cast<STSRuntime&>(*runtime));
}

StsServiceExtension::StsServiceExtension(STSRuntime& stsRuntime) : stsRuntime_(stsRuntime) {}
StsServiceExtension::~StsServiceExtension()
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
}

void StsServiceExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    TAG_LOGI(AAFwkTag::SERVICE_EXT, "StsServiceExtension init");
    if (record == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "record null");
        return;
    }
    Extension::Init(record, application, handler, token);
    if (Extension::abilityInfo_ == nullptr || Extension::abilityInfo_->srcEntrance.empty()) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "StsServiceExtension Init abilityInfo error");
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
    auto stsObj = stsRuntime_.LoadModule(
        moduleName, srcPath, abilityInfo_->hapPath, abilityInfo_->compileMode == AppExecFwk::CompileMode::ES_MODULE,
        false, abilityInfo_->srcEntrance);
    if (stsObj == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "Failed to get stsObj");
        return;
    }
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return;
    }
}
#ifdef SUPPORT_GRAPHICS
void StsServiceExtension::SystemAbilityStatusChangeListener::OnAddSystemAbility(int32_t systemAbilityId,
    const std::string& deviceId)
{
}
#endif //SUPPORT_GRAPHICS

void StsServiceExtension::OnStart(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");

    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "env not found Ability.sts");
        return;
    }

    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
        return;
    }

    const char* signature = "L@ohos/app/ability/Want/Want;:V";
    CallObjectMethod(false, "onCreate", signature, wantRef);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
}

void StsServiceExtension::OnStop()
{
    ServiceExtension::OnStop();
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
    const char* signature = ":V";
    CallObjectMethod(false, "onDestroy", signature);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
}

sptr<IRemoteObject> StsServiceExtension::OnConnect(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "env not found Ability.sts");
        return nullptr;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
        return nullptr;
    }
    const char* signature = "L@ohos/app/ability/Want/Want;:L@ohos/rpc/rpc/RemoteObject;";
    ani_ref result = CallObjectMethod(true, "onConnect", signature, wantRef);
    auto obj = reinterpret_cast<ani_object>(result);
    auto remoteObj = AniGetNativeRemoteObject(env, obj);
    if (remoteObj == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "remoteObj null");
    }
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
    return remoteObj;
}

sptr<IRemoteObject> StsServiceExtension::OnConnect(const AAFwk::Want &want,
    AppExecFwk::AbilityTransactionCallbackInfo<sptr<IRemoteObject>> *callbackInfo, bool &isAsyncCallback)
{
    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "env not found");
        return nullptr;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
        return nullptr;
    }
    if (callbackInfo == nullptr) {
        isAsyncCallback = false;
        return OnConnect(want);
    }
    ani_long connectCallbackPoint = (ani_long)callbackInfo;
    ani_status status = ANI_ERROR;
    ani_field field = nullptr;
    ani_class cls = nullptr;
    if ((status = env->FindClass("L@ohos/app/ability/ServiceExtensionAbility/ServiceExtensionAbility;", &cls))
        != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return nullptr;
    }
    ani_object object = nullptr;
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "connectCallbackPoint", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_SetField_Long(object, field, connectCallbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    CallObjectMethod(false, "callOnConnect", "L@ohos/app/ability/Want/Want;:V", wantRef);
    return nullptr;
}

void StsServiceExtension::OnDisconnect(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "env not found Ability.sts");
        return;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
        return;
    }
    const char* signature  = "L@ohos/app/ability/Want/Want;:V";
    CallObjectMethod(false, "onDisconnect", signature, wantRef);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
}

void StsServiceExtension::OnDisconnect(const AAFwk::Want &want,
    AppExecFwk::AbilityTransactionCallbackInfo<> *callbackInfo, bool &isAsyncCallback)
{
    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "env not found");
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
    ani_class cls = nullptr;
    if ((status = env->FindClass("L@ohos/app/ability/ServiceExtensionAbility/ServiceExtensionAbility;", &cls))
        != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return;
    }
    ani_object object = nullptr;
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        return;
    }
    if ((status = env->Class_FindField(cls, "disconnectCallbackPoint", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return;
    }
    if ((status = env->Object_SetField_Long(object, field, disconnectCallbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return;
    }
    CallObjectMethod(true, "callOnDisconnect", "L@ohos/app/ability/Want/Want;:Z");
}

void StsServiceExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "env not found Ability.sts");
        return;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null wantRef");
    }
    ani_int iStartId = static_cast<ani_int>(startId);
    const char* signature  = "L@ohos/app/ability/Want/Want;I:V";
    CallObjectMethod(false, "onRequest", signature, wantRef, iStartId);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
    return;
}

bool StsServiceExtension::HandleInsightIntent(const AAFwk::Want &want)
{
    return true;
}

bool StsServiceExtension::GetInsightIntentExecutorInfo(const Want &want,
    const std::shared_ptr<AppExecFwk::InsightIntentExecuteParam> &executeParam,
    InsightIntentExecutorInfo &executorInfo)
{
    return true;
}

bool StsServiceExtension::OnInsightIntentExecuteDone(uint64_t intentId,
    const AppExecFwk::InsightIntentExecuteResult &result)
{
    return true;
}

ani_ref StsServiceExtension::CallObjectMethod(bool withResult, const char* name, const char* signature, ...)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, std::string("CallObjectMethod:") + name);
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    auto env = stsRuntime_.GetAniEnv();
    if ((status = env->FindClass("L@ohos/app/ability/ServiceExtensionAbility/ServiceExtensionAbility;", &cls))
        != ANI_OK) {
        return nullptr;
    }
    if (cls == nullptr) {
        return nullptr;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        return nullptr;
    }
    ani_object object = nullptr;
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        return nullptr;
    }
    if (object == nullptr) {
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, name, signature, &method)) != ANI_OK) {
        return nullptr;
    }
    if (method == nullptr) {
        return nullptr;
    }
    ani_ref res = nullptr;
    va_list args;
    if (withResult) {
        va_start(args, signature);
        if ((status = env->Object_CallMethod_Ref_V(object, method, &res, args)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        }
        va_end(args);
        return res;
    }
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(object, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
    }
    va_end(args);
    return nullptr;
}
void StsServiceExtension::OnConfigurationUpdated(const AppExecFwk::Configuration& configuration)
{
}

void StsServiceExtension::ConfigurationUpdated()
{
}

void StsServiceExtension::Dump(const std::vector<std::string> &params, std::vector<std::string> &info)
{
}

#ifdef SUPPORT_GRAPHICS
void StsServiceExtension::OnCreate(Rosen::DisplayId displayId)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "enter");
}

void StsServiceExtension::OnDestroy(Rosen::DisplayId displayId)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "exit");
}

void StsServiceExtension::OnDisplayInfoChange(const sptr<IRemoteObject>& token, Rosen::DisplayId displayId,
    float density, Rosen::DisplayOrientation orientation)
{
}

void StsServiceExtension::OnChange(Rosen::DisplayId displayId)
{
}
#endif
} // AbilityRuntime
} // OHOS