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
#include "ability_business_error.h"
#include "ability_info.h"
#include "ability_manager_client.h"
#include "ani_common_configuration.h"
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
#include "sts_service_extension_context.h"

#ifdef SUPPORT_GRAPHICS
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "window_scene.h"
#endif

namespace OHOS {
namespace AbilityRuntime {

void DisconnectPromiseCallback(ani_env* env, ani_object aniObj)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "DisconnectPromiseCallback");
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
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "PromiseCallback");
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
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "StsServiceExtension init");
    if (record == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "record null");
        return;
    }
    ServiceExtension::Init(record, application, handler, token);
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
    stsObj_ = stsRuntime_.LoadModule(
        moduleName, srcPath, abilityInfo_->hapPath, abilityInfo_->compileMode == AppExecFwk::CompileMode::ES_MODULE,
        false, abilityInfo_->srcEntrance);
    if (stsObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "Failed to get stsObj");
        return;
    }
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return;
    }
    std::array functions = {
        ani_native_function { "nativeOnDisconnectCallback", ":V", reinterpret_cast<void*>(DisconnectPromiseCallback) },
        ani_native_function { "nativeOnConnectCallback", nullptr, reinterpret_cast<void*>(ConnectPromiseCallback) },
    };

    ani_status status = env->Class_BindNativeMethods(stsObj_->aniCls, functions.data(), functions.size());
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "Class_BindNativeMethods is fail %{public}d", status);
    };
    BindContext(env, record->GetWant(), application);
    return;
}
#ifdef SUPPORT_GRAPHICS
void StsServiceExtension::SystemAbilityStatusChangeListener::OnAddSystemAbility(int32_t systemAbilityId,
    const std::string& deviceId)
{
}
#endif //SUPPORT_GRAPHICS

ani_object StsServiceExtension::CreateSTSContext(ani_env* env, std::shared_ptr<ServiceExtensionContext> context,
    int32_t screenMode, const std::shared_ptr<OHOSApplication> &application)
{
    TAG_LOGI(AAFwkTag::SERVICE_EXT, "CreateSTSContext");
    ani_object obj = CreateStsServiceExtensionContext(env, context, application);
    return obj;
}

void StsServiceExtension::BindContext(ani_env*env, std::shared_ptr<AAFwk::Want> want,
    const std::shared_ptr<OHOSApplication> &application)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "StsServiceExtension BindContext Call");
    if (env == nullptr || want == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "Want info is null or env is null");
        return;
    }
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "Failed to get context");
        return;
    }
    int32_t screenMode = want->GetIntParam(AAFwk::SCREEN_MODE_KEY, AAFwk::IDLE_SCREEN_MODE);
    ani_object contextObj = CreateSTSContext(env, context, screenMode, application);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null contextObj");
        return;
    }
    //bind StsServiceExtension
    ani_field contextField;
    auto status = env->Class_FindField(stsObj_->aniCls, "context", &contextField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "Class_GetField context failed");
        ResetEnv(env);
        return;
    }
    ani_ref contextRef = nullptr;
    if (env->GlobalReference_Create(contextObj, &contextRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "GlobalReference_Create contextObj failed");
        return;
    }
    if (env->Object_SetField_Ref(stsObj_->aniObj, contextField, contextRef) != ANI_OK) {
        TAG_LOGI(AAFwkTag::SERVICE_EXT, "Object_SetField_Ref contextObj failed");
        ResetEnv(env);
    }
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "BindContext end");
}

void StsServiceExtension::ResetEnv(ani_env* env)
{
    env->DescribeError();  // 打印异常信息
    env->ResetError();  // 清除异常，避免影响后续 ANI 调用
}

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
        return nullptr;
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
    if ((status = env->Class_FindField(stsObj_->aniCls, "connectCallbackPoint", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_SetField_Long(stsObj_->aniObj, field, connectCallbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    ani_ref result =
        CallObjectMethod(true, "callOnConnect", "L@ohos/app/ability/Want/Want;:L@ohos/rpc/rpc/RemoteObject;", wantRef);
    auto obj = reinterpret_cast<ani_object>(result);
    auto remoteObj = AniGetNativeRemoteObject(env, obj);
    if (remoteObj == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "remoteObj null");
        return nullptr;
    }
    return remoteObj;
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
    if ((status = env->Class_FindField(stsObj_->aniCls, "disconnectCallbackPoint", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return;
    }
    if ((status = env->Object_SetField_Long(stsObj_->aniObj, field, disconnectCallbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return;
    }
    CallObjectMethod(false, "callOnDisconnect", "L@ohos/app/ability/Want/Want;:V", wantRef);
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
    const char* signature  = "L@ohos/app/ability/Want/Want;D:V";
    CallObjectMethod(false, "onRequest", signature, wantRef, iStartId);
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "end");
    return;
}

bool StsServiceExtension::HandleInsightIntent(const AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "HandleInsightIntent called");
    auto callback = std::make_unique<InsightIntentExecutorAsyncCallback>();
    callback.reset(InsightIntentExecutorAsyncCallback::Create());
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null callback");
        return false;
    }
    auto executeParam = std::make_shared<AppExecFwk::InsightIntentExecuteParam>();
    bool ret = AppExecFwk::InsightIntentExecuteParam::GenerateFromWant(want, *executeParam);
    if (!ret) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "Generate execute param failed");
        InsightIntentExecutorMgr::TriggerCallbackInner(std::move(callback),
            static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_PARAM));
        return false;
    }
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "Insight bundleName: %{public}s, moduleName: %{public}s, abilityName: %{public}s"
        "insightIntentName: %{public}s, executeMode: %{public}d, intentId: %{public}" PRIu64 "",
        executeParam->bundleName_.c_str(), executeParam->moduleName_.c_str(), executeParam->abilityName_.c_str(),
        executeParam->insightIntentName_.c_str(), executeParam->executeMode_, executeParam->insightIntentId_);
    auto asyncCallback = [weak = weak_from_this(), intentId = executeParam->insightIntentId_]
        (AppExecFwk::InsightIntentExecuteResult result) {
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "intentId %{public}" PRIu64"", intentId);
        auto extension = weak.lock();
        if (extension == nullptr) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "null extension");
            return;
        }
        auto ret = extension->OnInsightIntentExecuteDone(intentId, result);
        if (!ret) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "OnInsightIntentExecuteDone failed");
        }
    };
    callback->Push(asyncCallback);
    InsightIntentExecutorInfo executorInfo;
    ret = GetInsightIntentExecutorInfo(want, executeParam, executorInfo);
    if (!ret) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "Get Intent executor failed");
        InsightIntentExecutorMgr::TriggerCallbackInner(std::move(callback),
            static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_PARAM));
        return false;
    }
    ret = DelayedSingleton<InsightIntentExecutorMgr>::GetInstance()->ExecuteInsightIntent(
        stsRuntime_, executorInfo, std::move(callback));
    if (!ret) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "Execute insight intent failed");
        return false;
    }
    return true;
}

ani_ref StsServiceExtension::CallObjectMethod(bool withResult, const char* name, const char* signature, ...)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, std::string("CallObjectMethod:") + name);
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(stsObj_->aniCls, name, signature, &method)) != ANI_OK) {
        return nullptr;
    }
    if (method == nullptr) {
        return nullptr;
    }
    ani_ref res = nullptr;
    va_list args;
    if (withResult) {
        va_start(args, signature);
        if ((status = env->Object_CallMethod_Ref_V(stsObj_->aniObj, method, &res, args)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        }
        va_end(args);
        return res;
    }
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(stsObj_->aniObj, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
    }
    va_end(args);
    return nullptr;
}
void StsServiceExtension::OnConfigurationUpdated(const AppExecFwk::Configuration& configuration)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "call");
    ServiceExtension::OnConfigurationUpdated(configuration);
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null context");
        return;
    }
    auto contextConfig = context->GetConfiguration();
    if (contextConfig != nullptr) {
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "Config dump: %{public}s", contextConfig->GetName().c_str());
        std::vector<std::string> changeKeyV;
        contextConfig->CompareDifferent(changeKeyV, configuration);
        if (!changeKeyV.empty()) {
            contextConfig->Merge(changeKeyV, configuration);
        }
        TAG_LOGD(AAFwkTag::SERVICE_EXT, "Config dump after merge: %{public}s", contextConfig->GetName().c_str());
    }
    ConfigurationUpdated();
}

void StsServiceExtension::ConfigurationUpdated()
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "env nullptr");
        return;
    }
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null context");
        return;
    }
    auto fullConfig = context->GetConfiguration();
    if (!fullConfig) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null configuration");
        return;
    }

    ani_object aniConfiguration = OHOS::AppExecFwk::WrapConfiguration(env, *fullConfig);
    ani_method method = nullptr;
    ani_status status = env->Class_FindMethod(stsObj_->aniCls,
        "onConfigurationUpdate", "L@ohos/app/ability/Configuration/Configuration;:V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "Class_FindMethod failed, status: %{public}d", status);
        ResetEnv(env);
        return;
    }
    status = env->Object_CallMethod_Void(stsObj_->aniObj, method, aniConfiguration);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "CALL Object_CallMethod failed, status: %{public}d", status);
        ResetEnv(env);
        return;
    }
    UpdateContextConfiguration(env, stsObj_, aniConfiguration);
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