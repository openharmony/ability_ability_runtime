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
#include "ets_ability_stage.h"

#include <algorithm>
#include <cstring>
#include <exception>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>

#include "ability_delegator_registry.h"
#include "ani_common_configuration.h"
#include "ani_common_want.h"
#include "configuration_convertor.h"
#include "ets_ability_stage_context.h"
#include "freeze_util.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "ohos_application.h"
#include "startup_manager.h"

#ifdef WINDOWS_PLATFORM
#define ETS_EXPORT __declspec(dllexport)
#else
#define ETS_EXPORT __attribute__((visibility("default")))
#endif

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* CALLBACK_SUCCESS = "success";
constexpr const char* ABILITY_STAGE_CLASS_NAME = "L@ohos/app/ability/AbilityStage/AbilityStage;";
constexpr const char* ABILITY_STAGE_SYNC_METHOD_NAME = "L@ohos/app/ability/Want/Want;:Lstd/core/String;";
constexpr const char* ABILITY_STAGE_ASYNC_METHOD_NAME = "L@ohos/app/ability/Want/Want;:Z";
}

AbilityStage *ETSAbilityStage::Create(
    const std::unique_ptr<Runtime>& runtime, const AppExecFwk::HapModuleInfo& hapModuleInfo)
{
    if (runtime == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null runtime");
        return nullptr;
    }
    FreezeUtil::GetInstance().AddAppLifecycleEvent(0, "ETSAbilityStage::Create");

    auto& etsRuntime = static_cast<ETSRuntime&>(*runtime);

    std::string srcPath(hapModuleInfo.name);
    std::string moduleName(hapModuleInfo.moduleName);
    moduleName.append("::").append("AbilityStage");

    srcPath.append("/");
    if (!hapModuleInfo.srcEntrance.empty()) {
        srcPath.append(hapModuleInfo.srcEntrance);
        auto pos = srcPath.rfind(".");
        if (pos != std::string::npos) {
            srcPath.erase(pos);
            srcPath.append(".abc");
        }
    }
    std::unique_ptr<AppExecFwk::ETSNativeReference> moduleObj = nullptr;
    if (!hapModuleInfo.srcEntrance.empty()) {
        TAG_LOGD(AAFwkTag::APPKIT, "entry path: %{public}s", hapModuleInfo.srcEntrance.c_str());
        moduleObj = etsRuntime.LoadModule(moduleName, srcPath,
            hapModuleInfo.hapPath, false, false, hapModuleInfo.srcEntrance);
    }
    return new (std::nothrow) ETSAbilityStage(etsRuntime, std::move(moduleObj));
}

ETSAbilityStage::ETSAbilityStage(
    ETSRuntime &etsRuntime, std::unique_ptr<AppExecFwk::ETSNativeReference> &&etsAbilityStageObj)
    : etsRuntime_(etsRuntime), etsAbilityStageObj_(std::move(etsAbilityStageObj))
{}

ETSAbilityStage::~ETSAbilityStage()
{
    TAG_LOGI(AAFwkTag::APPKIT, "destructor");
    auto context = GetContext();
    if (context != nullptr) {
        context->Unbind();
    }
}

void ETSAbilityStage::Init(const std::shared_ptr<Context> &context,
    const std::weak_ptr<AppExecFwk::OHOSApplication> application)
{
    AbilityStage::Init(context, application);

    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        return;
    }
    if (!etsAbilityStageObj_) {
        TAG_LOGE(AAFwkTag::APPKIT, "null stage");
        return;
    }
    SetEtsAbilityStage(context);

    if (!BindNativeMethods()) {
        TAG_LOGE(AAFwkTag::APPKIT, "BindNativeMethods failed");
    }
}

void ETSAbilityStage::OnCreate(const AAFwk::Want &want) const
{
    TAG_LOGD(AAFwkTag::APPKIT, "OnCreate called");
    AbilityStage::OnCreate(want);

    FreezeUtil::GetInstance().AddAppLifecycleEvent(0, "ETSAbilityStage::OnCreate begin");
    CallObjectMethod(false, "onCreate", ":V");
    FreezeUtil::GetInstance().AddAppLifecycleEvent(0, "ETSAbilityStage::OnCreate end");

    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::ETS);
    if (delegator) {
        delegator->PostPerformStageStart(CreateStageProperty());
    }
}

void ETSAbilityStage::OnDestroy() const
{
    TAG_LOGD(AAFwkTag::APPKIT, "OnDestroy called");
    AbilityStage::OnDestroy();
    CallObjectMethod(false, "onDestroy", ":V");
}

std::string ETSAbilityStage::OnAcceptWant(const AAFwk::Want &want)
{
    return std::string();
}

std::string ETSAbilityStage::OnNewProcessRequest(const AAFwk::Want &want)
{
    return std::string();
}

std::string ETSAbilityStage::OnAcceptWant(const AAFwk::Want &want,
    AppExecFwk::AbilityTransactionCallbackInfo<std::string> *callbackInfo, bool &isAsync)
{
    TAG_LOGD(AAFwkTag::APPKIT, "OnAcceptWant called");
    if (callbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "callbackInfo nullptr");
        return "";
    }
    AbilityStage::OnAcceptWant(want, callbackInfo, isAsync);

    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return "";
    }
    if (etsAbilityStageObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null etsAbilityStageObj_");
        return "";
    }
    ani_long acceptCallbackPoint = reinterpret_cast<ani_long>(callbackInfo);
    ani_status status = env->Object_SetFieldByName_Long(etsAbilityStageObj_->aniObj, "acceptCallbackPoint",
        acceptCallbackPoint);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetFieldByName_Long status: %{public}d", status);
        return "";
    }
    std::string methodName = "callOnAcceptWant";
    if (CallAcceptOrRequestAsync(env, want, methodName, isAsync)) {
        TAG_LOGD(AAFwkTag::APPKIT, "callOnAcceptWant is implemented");
        return CALLBACK_SUCCESS;
    }
    methodName = "onAcceptWant";
    isAsync = false;
    if (CallAcceptOrRequestSync(env, want, methodName, callbackInfo)) {
        return CALLBACK_SUCCESS;
    }
    return "";
}

std::string ETSAbilityStage::OnNewProcessRequest(const AAFwk::Want &want,
    AppExecFwk::AbilityTransactionCallbackInfo<std::string> *callbackInfo, bool &isAsync)
{
    TAG_LOGD(AAFwkTag::APPKIT, "OnNewProcessRequest called");
    if (callbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "callbackInfo nullptr");
        return "";
    }
    AbilityStage::OnNewProcessRequest(want, callbackInfo, isAsync);

    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return "";
    }
    if (etsAbilityStageObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null etsAbilityStageObj_");
        return "";
    }
    ani_long newProcessRequestCallbackPoint = reinterpret_cast<ani_long>(callbackInfo);
    ani_status status = env->Object_SetFieldByName_Long(etsAbilityStageObj_->aniObj, "newProcessRequestCallbackPoint",
        newProcessRequestCallbackPoint);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetFieldByName_Long status: %{public}d", status);
        return "";
    }
    std::string methodName = "callOnNewProcessRequest";
    if (CallAcceptOrRequestAsync(env, want, methodName, isAsync)) {
        TAG_LOGD(AAFwkTag::APPKIT, "callOnNewProcessRequest is implemented");
        return CALLBACK_SUCCESS;
    }
    methodName = "onNewProcessRequest";
    isAsync = false;
    if (CallAcceptOrRequestSync(env, want, methodName, callbackInfo)) {
        return CALLBACK_SUCCESS;
    }
    return "";
}

void ETSAbilityStage::OnAcceptWantCallback(ani_env *env, ani_object aniObj, ani_string aniResult)
{
    TAG_LOGD(AAFwkTag::APPKIT, "OnAcceptWantCallback called");

    if (env == nullptr || aniObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env or null aniObj");
        return;
    }
    ani_long callbackPoint = 0;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Long(aniObj, "acceptCallbackPoint", &callbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return;
    }
    auto *callbackInfo = reinterpret_cast<AppExecFwk::AbilityTransactionCallbackInfo<std::string> *>(callbackPoint);
    if (callbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null callbackInfo");
        return;
    }
    std::string resultString = "";
    if (!AppExecFwk::GetStdString(env, aniResult, resultString)) {
        TAG_LOGE(AAFwkTag::APPKIT, "fail to get resultString");
        return;
    }
    callbackInfo->Call(resultString);
    AppExecFwk::AbilityTransactionCallbackInfo<std::string>::Destroy(callbackInfo);

    if ((status = env->Object_SetFieldByName_Long(aniObj, "acceptCallbackPoint",
        static_cast<ani_long>(0))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status : %{public}d", status);
        return;
    }
}

void ETSAbilityStage::OnNewProcessRequestCallback(ani_env *env, ani_object aniObj, ani_string aniResult)
{
    TAG_LOGD(AAFwkTag::APPKIT, "OnNewProcessRequestCallback called");

    if (env == nullptr || aniObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env or null aniObj");
        return;
    }
    ani_long callbackPoint = 0;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Long(aniObj, "newProcessRequestCallbackPoint",
        &callbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return;
    }
    auto *callbackInfo = reinterpret_cast<AppExecFwk::AbilityTransactionCallbackInfo<std::string> *>(callbackPoint);
    if (callbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null callbackInfo");
        return;
    }
    std::string resultString = "";
    if (!AppExecFwk::GetStdString(env, aniResult, resultString)) {
        TAG_LOGE(AAFwkTag::APPKIT, "fail to get resultString");
        return;
    }
    callbackInfo->Call(resultString);
    AppExecFwk::AbilityTransactionCallbackInfo<std::string>::Destroy(callbackInfo);

    if ((status = env->Object_SetFieldByName_Long(aniObj, "newProcessRequestCallbackPoint",
        static_cast<ani_long>(0))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status : %{public}d", status);
        return;
    }
}

void ETSAbilityStage::OnConfigurationUpdated(const AppExecFwk::Configuration &configuration)
{
    TAG_LOGD(AAFwkTag::APPKIT, "OnConfigurationUpdated called");
    AbilityStage::OnConfigurationUpdated(configuration);
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "env nullptr");
        return;
    }
    auto application = application_.lock();
    if (application == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "application is null");
        return;
    }
    auto fullConfig = application->GetConfiguration();
    if (!fullConfig) {
        TAG_LOGE(AAFwkTag::APPKIT, "null fullConfig");
        return;
    }
    ETSAbilityStageContext::ConfigurationUpdated(env, fullConfig);
    ani_object configObj = OHOS::AppExecFwk::WrapConfiguration(env, configuration);
    if (configObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null configObj");
        return;
    }
    CallObjectMethod(false, "onConfigurationUpdate", "L@ohos/app/ability/Configuration/Configuration;:V", configObj);
}

void ETSAbilityStage::OnMemoryLevel(int32_t level)
{
}

bool ETSAbilityStage::CallObjectMethod(bool withResult, const char *name, const char *signature, ...) const
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, std::string("CallObjectMethod:") + name);
    TAG_LOGD(AAFwkTag::ABILITY, "CallObjectMethod: name:%{public}s", name);
    if (etsAbilityStageObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "etsAbilityStageObj_ nullptr");
        return false;
    }
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "env nullptr");
        return false;
    }
    ani_status status = ANI_OK;
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(etsAbilityStageObj_->aniCls, name, signature, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "status: %{public}d", status);
        return false;
    }
    env->ResetError();
    if (withResult) {
        ani_boolean res = ANI_FALSE;
        va_list args;
        va_start(args, signature);
        if ((status = env->Object_CallMethod_Boolean(etsAbilityStageObj_->aniObj, method, &res, args)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::ABILITY, "status: %{public}d", status);
            etsRuntime_.HandleUncaughtError();
        }
        va_end(args);
        return res;
    }
    va_list args;
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(etsAbilityStageObj_->aniObj, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "status: %{public}d", status);
        etsRuntime_.HandleUncaughtError();
        return false;
    }
    va_end(args);
    return false;
}

ani_object ETSAbilityStage::CallObjectMethod(const char *name, const char *signature, ...) const
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, std::string("CallObjectMethod:") + name);
    TAG_LOGD(AAFwkTag::APPKIT, "ETSAbilityStage call ets, name: %{public}s", name);
    if (etsAbilityStageObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null etsAbilityStageObj_");
        return nullptr;
    }
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    auto obj = etsAbilityStageObj_->aniObj;
    auto cls = etsAbilityStageObj_->aniCls;
    ani_status status = ANI_ERROR;

    ani_method method {};
    if ((status = env->Class_FindMethod(cls, name, signature, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status : %{public}d", status);
        env->ResetError();
        return nullptr;
    }
    ani_ref res {};
    va_list args;
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Ref(obj, method, &res, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status : %{public}d", status);
        etsRuntime_.HandleUncaughtError();
        return nullptr;
    }
    va_end(args);
    return reinterpret_cast<ani_object>(res);
}

std::shared_ptr<AppExecFwk::EtsDelegatorAbilityStageProperty> ETSAbilityStage::CreateStageProperty() const
{
    auto property = std::make_shared<AppExecFwk::EtsDelegatorAbilityStageProperty>();
    property->moduleName_ = GetHapModuleProp("name");
    property->srcEntrance_ = GetHapModuleProp("srcEntrance");
    return property;
}

std::string ETSAbilityStage::GetHapModuleProp(const std::string &propName) const
{
    auto context = GetContext();
    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        return std::string();
    }
    auto hapModuleInfo = context->GetHapModuleInfo();
    if (!hapModuleInfo) {
        TAG_LOGE(AAFwkTag::APPKIT, "null hapModuleInfo");
        return std::string();
    }
    if (propName.compare("name") == 0) {
        return hapModuleInfo->name;
    }
    if (propName.compare("srcEntrance") == 0) {
        return hapModuleInfo->srcEntrance;
    }
    TAG_LOGD(AAFwkTag::APPKIT, "name = %{public}s", propName.c_str());
    return std::string();
}

bool ETSAbilityStage::CallAcceptOrRequestSync(ani_env *env, const AAFwk::Want &want, std::string &methodName,
    AppExecFwk::AbilityTransactionCallbackInfo<std::string> *callbackInfo) const
{
    TAG_LOGD(AAFwkTag::APPKIT, "CallAcceptOrRequestSync called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return false;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null wantRef");
        return false;
    }
    if (callbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null callbackInfo");
        return false;
    }
    ani_object resObj = CallObjectMethod(methodName.c_str(), ABILITY_STAGE_SYNC_METHOD_NAME, wantRef);
    if (resObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "CallAcceptOrRequestSync unimplemented");
        return false;
    }
    std::string resultString = "";
    if (!AppExecFwk::GetStdString(env, reinterpret_cast<ani_string>(resObj), resultString)) {
        TAG_LOGE(AAFwkTag::APPKIT, "fail to get resultString");
        return false;
    }
    callbackInfo->Call(resultString);
    AppExecFwk::AbilityTransactionCallbackInfo<std::string>::Destroy(callbackInfo);
    return true;
}

bool ETSAbilityStage::CallAcceptOrRequestAsync(ani_env *env, const AAFwk::Want &want, std::string &methodName,
    bool &isAsync) const
{
    TAG_LOGD(AAFwkTag::APPKIT, "CallAcceptOrRequestAsync called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return false;
    }
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null wantRef");
        return false;
    }
    isAsync = CallObjectMethod(true, methodName.c_str(), ABILITY_STAGE_ASYNC_METHOD_NAME, wantRef);
    return isAsync;
}

bool ETSAbilityStage::BindNativeMethods()
{
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return false;
    }
    std::array functions = {
        ani_native_function{
            "nativeOnAcceptWantCallback", "Lstd/core/String;:V",
            reinterpret_cast<void *>(ETSAbilityStage::OnAcceptWantCallback)},
        ani_native_function{
            "nativeOnNewProcessRequestCallback", "Lstd/core/String;:V",
            reinterpret_cast<void *>(ETSAbilityStage::OnNewProcessRequestCallback)},
    };
    ani_class cls {};
    ani_status status = env->FindClass(ABILITY_STAGE_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass failed status: %{public}d", status);
        return false;
    }
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_BindNativeMethods status: %{public}d", status);
        return false;
    }
    return true;
}

void ETSAbilityStage::SetEtsAbilityStage(const std::shared_ptr<Context> &context)
{
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "context nullptr");
        return;
    }

    if (!etsAbilityStageObj_) {
        TAG_LOGE(AAFwkTag::APPKIT, "Not found AbilityStage.js");
        return;
    }

    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "env nullptr");
        return;
    }

    ani_object stageCtxObj = ETSAbilityStageContext::CreateEtsAbilityStageContext(env, context);
    if (stageCtxObj == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "CreateEtsAbilityStageContext failed");
        return;
    }

    ani_status status = ANI_OK;
    ani_field contextField;
    status = env->Class_FindField(etsAbilityStageObj_->aniCls, "context", &contextField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "Class_GetField context failed");
        return;
    }
    ani_ref stageCtxObjRef = nullptr;
    if (env->GlobalReference_Create(stageCtxObj, &stageCtxObjRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "GlobalReference_Create stageCtxObj failed");
        return;
    }
    if (env->Object_SetField_Ref(etsAbilityStageObj_->aniObj, contextField, stageCtxObjRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "Object_SetField_Ref stageCtxObj failed");
    }
}

}  // namespace AbilityRuntime
}  // namespace OHOS

ETS_EXPORT extern "C" OHOS::AbilityRuntime::AbilityStage *OHOS_ETS_Ability_Stage_Create(
    const std::unique_ptr<OHOS::AbilityRuntime::Runtime> &runtime,
    const OHOS::AppExecFwk::HapModuleInfo &hapModuleInfo)
{
    return OHOS::AbilityRuntime::ETSAbilityStage::Create(runtime, hapModuleInfo);
}