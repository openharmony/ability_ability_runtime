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

#include "sts_ui_ability.h"
#include <cstdlib>
#include <regex>
#include <vector>

#include "ability_business_error.h"
#include "ability_delegator_registry.h"
#include "ability_manager_client.h"
#include "ability_recovery.h"
#include "ability_start_setting.h"
#include "ani_remote_object.h"
#include "app_recovery.h"
#include "connection_manager.h"
#include "context/application_context.h"
#include "context/context.h"
#include "display_util.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "if_system_ability_manager.h"
#include "insight_intent_executor_info.h"
#include "insight_intent_executor_mgr.h"
#include "insight_intent_execute_param.h"
#include "ohos_application.h"
#include "sts_ability_context.h"
#include "sts_caller_complex.h"
#include "sts_data_struct_converter.h"
#ifdef SUPPORT_SCREEN
#include "ani_window_stage.h"
#include "distributed_client.h"
#include "scene_board_judgement.h"
#endif
#include "ani_common_want.h"
#include "string_wrapper.h"
#include "system_ability_definition.h"
#include "time_util.h"

namespace OHOS {
namespace AbilityRuntime {
std::once_flag StsUIAbility::singletonFlag_;
namespace {
#ifdef SUPPORT_GRAPHICS
const std::string PAGE_STACK_PROPERTY_NAME = "pageStack";
const std::string SUPPORT_CONTINUE_PAGE_STACK_PROPERTY_NAME = "ohos.extra.param.key.supportContinuePageStack";
const std::string METHOD_NAME = "WindowScene::GoForeground";
#endif
// Numerical base (radix) that determines the valid characters and their interpretation.
#ifdef SUPPORT_SCREEN
const int32_t BASE_DISPLAY_ID_NUM(10);
enum CollaborateResult {
    ACCEPT = 0,
    REJECT,
};
[[maybe_unused]] static CollaborateResult CollaborateResult_ConvertStsToNative(const int32_t index)
{
    return static_cast<CollaborateResult>(index);
}
[[maybe_unused]] static int32_t CollaborateResult_ConvertNativeToSts(const CollaborateResult value)
{
    return value;
}
#endif
constexpr const int32_t API12 = 12;
constexpr const int32_t API_VERSION_MOD = 100;
constexpr const char* UI_ABILITY_CONTEXT_CLASS_NAME = "Lapplication/UIAbilityContext/UIAbilityContext;";
constexpr const char* UI_ABILITY_CLASS_NAME = "L@ohos/app/ability/UIAbility/UIAbility;";

void OnDestroyPromiseCallback(ani_env* env, ani_object aniObj)
{
    TAG_LOGI(AAFwkTag::UIABILITY, "OnDestroyPromiseCallback");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    ani_long destroyCallbackPoint = 0;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Long(aniObj, "destroyCallbackPoint", &destroyCallbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return;
    }
    auto *callbackInfo = reinterpret_cast<AppExecFwk::AbilityTransactionCallbackInfo<> *>(destroyCallbackPoint);
    if (callbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null callbackInfo");
        return;
    }
    callbackInfo->Call();
    AppExecFwk::AbilityTransactionCallbackInfo<>::Destroy(callbackInfo);
}
} // namespace

UIAbility *StsUIAbility::Create(const std::unique_ptr<Runtime> &runtime)
{
    return new (std::nothrow) StsUIAbility(static_cast<STSRuntime&>(*runtime));
}

StsUIAbility::StsUIAbility(STSRuntime &stsRuntime) : stsRuntime_(stsRuntime)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
}

StsUIAbility::~StsUIAbility()
{
    TAG_LOGI(AAFwkTag::UIABILITY, "called");
    if (abilityContext_ != nullptr) {
        abilityContext_->Unbind<ani_ref>();
    }
}

void StsUIAbility::Init(std::shared_ptr<AppExecFwk::AbilityLocalRecord> record,
    const std::shared_ptr<OHOSApplication> application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (record == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null localAbilityRecord");
        return;
    }
    auto abilityInfo = record->GetAbilityInfo();
    if (abilityInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null abilityInfo");
        return;
    }
    UIAbility::Init(record, application, handler, token);
#ifdef SUPPORT_GRAPHICS
    if (abilityContext_ != nullptr) {
        AppExecFwk::AppRecovery::GetInstance().AddAbility(
            shared_from_this(), abilityContext_->GetAbilityInfo(), abilityContext_->GetToken());
    }
#endif
    std::string srcPath(abilityInfo->package);
    if (!abilityInfo->isModuleJson) {
        /* temporary compatibility api8 + config.json */
        srcPath.append("/assets/js/");
        if (!abilityInfo->srcPath.empty()) {
            srcPath.append(abilityInfo->srcPath);
        }
        srcPath.append("/").append(abilityInfo->name).append(".abc");
    } else {
        if (abilityInfo->srcEntrance.empty()) {
            TAG_LOGE(AAFwkTag::UIABILITY, "empty srcEntrance");
            return;
        }
        srcPath.append("/");
        srcPath.append(abilityInfo->srcEntrance);
        auto pos = srcPath.rfind(".");
        if (pos != std::string::npos) {
            srcPath.erase(pos);
            srcPath.append(".abc");
        }
        TAG_LOGD(AAFwkTag::UIABILITY, "stsAbility srcPath: %{public}s", srcPath.c_str());
    }

    std::string moduleName(abilityInfo->moduleName);
    moduleName.append("::").append(abilityInfo->name);

    SetAbilityContext(abilityInfo, record->GetWant(), moduleName, srcPath, application);
}

bool StsUIAbility::BindNativeMethods()
{
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "env null");
        return false;
    }
    ani_class cls {};
    ani_status status = env->FindClass(UI_ABILITY_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "FindClass failed status: %{public}d", status);
        return false;
    }
    std::call_once(singletonFlag_, [&status, env, cls]() {
        std::array functions = {
            ani_native_function { "nativeOnDestroyCallback", ":V", reinterpret_cast<void*>(OnDestroyPromiseCallback) },
        };
        status = env->Class_BindNativeMethods(cls, functions.data(), functions.size());
    });
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "Class_BindNativeMethods failed status: %{public}d", status);
        return false;
    }
    return true;
}

void StsUIAbility::UpdateAbilityObj(
    std::shared_ptr<AbilityInfo> abilityInfo, const std::string &moduleName, const std::string &srcPath)
{
    std::string key = moduleName + "::" + srcPath;
    std::unique_ptr<NativeReference> moduleObj = nullptr;
    stsAbilityObj_ = stsRuntime_.LoadModule(
        moduleName, srcPath, abilityInfo->hapPath, abilityInfo->compileMode == AppExecFwk::CompileMode::ES_MODULE,
        false, abilityInfo->srcEntrance);

    if (!BindNativeMethods()) {
        TAG_LOGE(AAFwkTag::UIABILITY, "BindNativeMethods failed");
        return;
    }
    ani_status status = ANI_ERROR;
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    auto callee = CreateEtsCallee(env);
    if ((status = env->Object_SetFieldByName_Ref(stsAbilityObj_->aniObj, "callee", callee)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "set callee status : %{public}d", status);
    }
}

void StsUIAbility::CreateAndBindContext(const std::shared_ptr<AppExecFwk::OHOSApplication> application,
    const std::shared_ptr<AppExecFwk::AbilityLocalRecord> record,
    const std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext,
    const std::unique_ptr<Runtime>& runtime)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (application == nullptr || record == nullptr || abilityContext == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null application or record or abilityContext");
        return;
    }
    if (runtime == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null runtime");
        return;
    }
    auto& stsRuntime = static_cast<STSRuntime&>(*runtime);
    auto env = stsRuntime.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    auto want = record->GetWant();
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null want");
        return;
    }

    int32_t screenMode = want->GetIntParam(AAFwk::SCREEN_MODE_KEY, AAFwk::ScreenMode::IDLE_SCREEN_MODE);
    abilityContext->SetScreenMode(screenMode);
    if (screenMode == AAFwk::IDLE_SCREEN_MODE) {
        ani_ref contextObj = CreateStsAbilityContext(env, abilityContext, application);
        ani_ref* contextGlobalRef = new ani_ref;
        ani_status status = ANI_ERROR;
        if ((status = env->GlobalReference_Create(contextObj, contextGlobalRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
            return;
        }
        abilityContext->Bind(stsRuntime, contextGlobalRef);
    }
    // no CreateAniEmbeddableUIAbilityContext
}

void StsUIAbility::SetAbilityContext(std::shared_ptr<AbilityInfo> abilityInfo, std::shared_ptr<AAFwk::Want> want,
    const std::string &moduleName, const std::string &srcPath, const std::shared_ptr<OHOSApplication> &application)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    UpdateAbilityObj(abilityInfo, moduleName, srcPath);
    if (stsAbilityObj_ == nullptr || abilityContext_ == nullptr || want == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsAbilityObj_ or abilityContext_ or want");
        return;
    }
    ani_ref contextObj = nullptr;
    int32_t screenMode = want->GetIntParam(AAFwk::SCREEN_MODE_KEY, AAFwk::ScreenMode::IDLE_SCREEN_MODE);
    CreateAniContext(env, contextObj, screenMode, application);
}

void StsUIAbility::CreateAniContext(
    ani_env *env, ani_ref contextGlobalRef, int32_t screenMode, const std::shared_ptr<OHOSApplication> &application)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    if (screenMode == AAFwk::IDLE_SCREEN_MODE) {
        ani_ref contextObj = CreateStsAbilityContext(env, abilityContext_, application);
        if (contextObj == nullptr) {
            TAG_LOGE(AAFwkTag::UIABILITY, "null contextObj");
            return;
        }
        ani_field field = nullptr;
        ani_status status = ANI_ERROR;
        if ((status = env->GlobalReference_Create(contextObj, &contextGlobalRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
            return;
        }
        if ((status = env->Class_FindField(stsAbilityObj_->aniCls, "context", &field)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
            return;
        }
        if ((status = env->Object_SetField_Ref(stsAbilityObj_->aniObj, field, contextGlobalRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
            return;
        }
        shellContextRef_ = std::make_shared<STSNativeReference>();
        ani_class cls {};
        if ((status = env->FindClass(UI_ABILITY_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
            return;
        }
        shellContextRef_->aniCls = cls;
        shellContextRef_->aniObj = reinterpret_cast<ani_object>(contextGlobalRef);
        shellContextRef_->aniRef = contextGlobalRef;
        abilityContext_->Bind(stsRuntime_, &(shellContextRef_->aniRef));
    }
    // no CreateAniEmbeddableUIAbilityContext
}

void StsUIAbility::OnStart(const Want &want, sptr<AAFwk::SessionInfo> sessionInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "ability: %{public}s", GetAbilityName().c_str());
    UIAbility::OnStart(want, sessionInfo);

    if (!stsAbilityObj_) {
        TAG_LOGE(AAFwkTag::UIABILITY, "not found Ability.js");
        return;
    }
    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::UIABILITY, "env not found Ability.sts");
        return;
    }

    ani_status status = ANI_ERROR;
    ani_ref wantObj = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantObj == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null wantObj");
        return;
    }
    ani_ref wantRef = nullptr;
    if ((status = env->GlobalReference_Create(wantObj, &wantRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }

    ani_field field = nullptr;
    if ((status = env->Class_FindField(stsAbilityObj_->aniCls, "launchWant", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_SetField_Ref(stsAbilityObj_->aniObj, field, wantRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Class_FindField(stsAbilityObj_->aniCls, "lastRequestWant", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_SetField_Ref(stsAbilityObj_->aniObj, field, wantRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    auto launchParam = GetLaunchParam();
    if (InsightIntentExecuteParam::IsInsightIntentExecute(want)) {
        launchParam.launchReason = AAFwk::LaunchReason::LAUNCHREASON_INSIGHT_INTENT;
    }
    ani_ref launchParamRef = CreateStsLaunchParam(env, launchParam);
    const char *signature =
        "L@ohos/app/ability/Want/Want;L@ohos/app/ability/AbilityConstant/AbilityConstant/LaunchParam;:V";

    std::string methodName = "OnStart";
    auto applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }
    AddLifecycleEventBeforeJSCall(FreezeUtil::TimeoutState::FOREGROUND, methodName);
    CallObjectMethod(false, "onCreate", signature, wantRef, launchParamRef);
    AddLifecycleEventAfterJSCall(FreezeUtil::TimeoutState::FOREGROUND, methodName);
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(
        AbilityRuntime::Runtime::Language::STS);
    if (delegator) {
        TAG_LOGD(AAFwkTag::UIABILITY, "call PostPerformStart");
        delegator->PostPerformStart(CreateADelegatorAbilityProperty());
    }
    applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }
    TAG_LOGD(AAFwkTag::UIABILITY, "end");
}

void StsUIAbility::AddLifecycleEventBeforeJSCall(FreezeUtil::TimeoutState state, const std::string &methodName) const
{
    auto entry = std::string("StsUIAbility::") + methodName + " begin";
    FreezeUtil::GetInstance().AddLifecycleEvent(AbilityContext::token_, entry);
}

void StsUIAbility::AddLifecycleEventAfterJSCall(FreezeUtil::TimeoutState state, const std::string &methodName) const
{
    auto entry = std::string("StsUIAbility::") + methodName + " end";
    FreezeUtil::GetInstance().AddLifecycleEvent(AbilityContext::token_, entry);
}

int32_t StsUIAbility::OnShare(WantParams &wantParam)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (stsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsAbilityObj_");
        return ERR_INVALID_VALUE;
    }
    TAG_LOGD(AAFwkTag::UIABILITY, "end");
    return ERR_OK;
}

void StsUIAbility::OnStop()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (abilityContext_) {
        TAG_LOGD(AAFwkTag::UIABILITY, "set terminating true");
        abilityContext_->SetTerminating(true);
    }
    UIAbility::OnStop();

    auto applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }
    CallObjectMethod(false, "onDestroy", nullptr);
    OnStopCallback();
    TAG_LOGD(AAFwkTag::UIABILITY, "end");
}

void StsUIAbility::OnStop(AppExecFwk::AbilityTransactionCallbackInfo<> *callbackInfo, bool &isAsyncCallback)
{
    if (callbackInfo == nullptr) {
        isAsyncCallback = false;
        OnStop();
        return;
    }

    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "Begin");
    if (abilityContext_) {
        TAG_LOGD(AAFwkTag::UIABILITY, "set terminating true");
        abilityContext_->SetTerminating(true);
    }

    UIAbility::OnStop();

    auto applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }
    std::weak_ptr<UIAbility> weakPtr = shared_from_this();
    auto asyncCallback = [abilityWeakPtr = weakPtr]() {
        auto ability = abilityWeakPtr.lock();
        if (ability == nullptr) {
            TAG_LOGE(AAFwkTag::UIABILITY, "null ability");
            return;
        }
        ability->OnStopCallback();
    };
    callbackInfo->Push(asyncCallback);

    ani_long destroyCallbackPoint = (ani_long)callbackInfo;
    ani_status status = ANI_ERROR;
    ani_field field = nullptr;
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr || stsAbilityObj_ == nullptr) {
        isAsyncCallback = false;
        OnStop();
        return;
    }
    if ((status = env->Class_FindField(stsAbilityObj_->aniCls, "destroyCallbackPoint", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_SetField_Long(stsAbilityObj_->aniObj, field, destroyCallbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }

    isAsyncCallback = CallObjectMethod(true, "callOnDestroy", ":Z");
    TAG_LOGI(AAFwkTag::UIABILITY, "callOnDestroy isAsyncCallback: %{public}d", isAsyncCallback);
    if (!isAsyncCallback) {
        OnStopCallback();
        return;
    }
    TAG_LOGD(AAFwkTag::UIABILITY, "end");
}

void StsUIAbility::OnStopCallback()
{
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(
        AbilityRuntime::Runtime::Language::STS);
    if (delegator) {
        TAG_LOGD(AAFwkTag::UIABILITY, "call PostPerformStop");
        delegator->PostPerformStop(CreateADelegatorAbilityProperty());
    }

    bool ret = ConnectionManager::GetInstance().DisconnectCaller(AbilityContext::token_);
    if (ret) {
        ConnectionManager::GetInstance().ReportConnectionLeakEvent(getpid(), gettid());
        TAG_LOGD(AAFwkTag::UIABILITY, "the service connection is not disconnected");
    }

    auto applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }
}

#ifdef SUPPORT_SCREEN
void StsUIAbility::OnSceneCreated()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "ability: %{public}s", GetAbilityName().c_str());
    UIAbility::OnSceneCreated();
    auto stsAppWindowStage = CreateAppWindowStage();
    if (stsAppWindowStage == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsAppWindowStage");
        return;
    }

    UpdateStsWindowStage(reinterpret_cast<ani_ref>(stsAppWindowStage));
    stsWindowStageObj_ = std::make_shared<STSNativeReference>();
    stsWindowStageObj_->aniObj = stsAppWindowStage;
    ani_ref entryObjectRef = nullptr;
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    if (env->GlobalReference_Create(stsAppWindowStage, &entryObjectRef) !=
        ANI_OK) {
      TAG_LOGE(AAFwkTag::UIABILITY, "GlobalReference_Create failed");
      return;
    }
    stsWindowStageObj_->aniRef = entryObjectRef;

    auto applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, "onWindowStageCreate");
        std::string methodName = "OnSceneCreated";
        AddLifecycleEventBeforeJSCall(FreezeUtil::TimeoutState::FOREGROUND, methodName);
        const char *signature = "L@ohos/window/window/WindowStage;:V";
        CallObjectMethod(false, "onWindowStageCreate", signature, stsAppWindowStage);
        AddLifecycleEventAfterJSCall(FreezeUtil::TimeoutState::FOREGROUND, methodName);
    }

    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(
        AbilityRuntime::Runtime::Language::STS);
    if (delegator) {
        TAG_LOGD(AAFwkTag::UIABILITY, "call PostPerformScenceCreated");
        delegator->PostPerformScenceCreated(CreateADelegatorAbilityProperty());
    }

    applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }

    TAG_LOGD(AAFwkTag::UIABILITY, "end");
}

void StsUIAbility::OnSceneRestored()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    UIAbility::OnSceneRestored();
    TAG_LOGD(AAFwkTag::UIABILITY, "OnSceneRestored called");

    auto stsAppWindowStage = CreateAppWindowStage();
    if (stsAppWindowStage == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsAppWindowStage");
        return;
    }
    UpdateStsWindowStage(reinterpret_cast<ani_ref>(stsAppWindowStage));
    stsWindowStageObj_ = std::make_shared<STSNativeReference>();
    stsWindowStageObj_->aniObj = stsAppWindowStage;
    CallObjectMethod(false, "onWindowStageRestore", nullptr, stsAppWindowStage);
}

void StsUIAbility::OnSceneWillDestroy()
{
    TAG_LOGD(AAFwkTag::UIABILITY, "ability: %{public}s", GetAbilityName().c_str());
    if (stsWindowStageObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsWindowStageObj_");
        return;
    }
    CallObjectMethod(false, "onWindowStageWillDestroy", nullptr, stsWindowStageObj_->aniRef);
}

void StsUIAbility::onSceneDestroyed()
{
    TAG_LOGD(AAFwkTag::UIABILITY, "ability: %{public}s", GetAbilityName().c_str());
    UIAbility::onSceneDestroyed();

    auto applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }

    UpdateStsWindowStage(nullptr);
    const char *signature = ":V";
    CallObjectMethod(false, "onWindowStageDestroy", signature);

    if (scene_ != nullptr) {
        auto window = scene_->GetMainWindow();
        if (window != nullptr) {
            TAG_LOGD(AAFwkTag::UIABILITY, "unRegisterDisplaymovelistener");
            window->UnregisterDisplayMoveListener(abilityDisplayMoveListener_);
        }
    }

    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(
        AbilityRuntime::Runtime::Language::STS);
    if (delegator) {
        TAG_LOGD(AAFwkTag::UIABILITY, "call PostPerformScenceDestroyed");
        delegator->PostPerformScenceDestroyed(CreateADelegatorAbilityProperty());
    }

    applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }
    TAG_LOGD(AAFwkTag::UIABILITY, "end");
}

void StsUIAbility::OnForeground(const Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "ability: %{public}s", GetAbilityName().c_str());
    if (abilityInfo_) {
    }

    UIAbility::OnForeground(want);

    if (CheckIsSilentForeground()) {
        TAG_LOGD(AAFwkTag::UIABILITY, "silent foreground, do not call 'onForeground'");
        return;
    }
    CallOnForegroundFunc(want);
}

void StsUIAbility::CallOnForegroundFunc(const Want &want)
{
    if (stsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsAbilityObj_");
        return;
    }
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_field field = nullptr;
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null wantObj");
        return;
    }
    auto applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }

    if ((status = env->Class_FindField(stsAbilityObj_->aniCls, "lastRequestWant", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_SetField_Ref(stsAbilityObj_->aniObj, field, wantRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    std::string methodName = "OnForeground";
    AddLifecycleEventBeforeJSCall(FreezeUtil::TimeoutState::FOREGROUND, methodName);
    CallObjectMethod(false, "onForeground", nullptr, wantRef);
    AddLifecycleEventAfterJSCall(FreezeUtil::TimeoutState::FOREGROUND, methodName);

    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(
        AbilityRuntime::Runtime::Language::STS);
    if (delegator) {
        TAG_LOGD(AAFwkTag::UIABILITY, "call PostPerformForeground");
        delegator->PostPerformForeground(CreateADelegatorAbilityProperty());
    }

    applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }
    TAG_LOGD(AAFwkTag::UIABILITY, "end");
}

void StsUIAbility::OnBackground()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "ability: %{public}s", GetAbilityName().c_str());
    auto applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }
    std::string methodName = "OnBackground";

    AddLifecycleEventBeforeJSCall(FreezeUtil::TimeoutState::BACKGROUND, methodName);
    const char *signature = ":V";
    CallObjectMethod(false, "onBackground", signature);
    AddLifecycleEventAfterJSCall(FreezeUtil::TimeoutState::BACKGROUND, methodName);

    UIAbility::OnBackground();

    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(
        AbilityRuntime::Runtime::Language::STS);
    if (delegator) {
        TAG_LOGD(AAFwkTag::UIABILITY, "call PostPerformBackground");
        delegator->PostPerformBackground(CreateADelegatorAbilityProperty());
    }

    applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }
    TAG_LOGD(AAFwkTag::UIABILITY, "end");
}

bool StsUIAbility::OnBackPress()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "ability: %{public}s", GetAbilityName().c_str());
    UIAbility::OnBackPress();
    bool ret = CallObjectMethod(true, "onBackPressed", nullptr);
    TAG_LOGD(AAFwkTag::UIABILITY, "ret: %{public}d", ret);
    return ret;
}

ani_object StsUIAbility::CreateAppWindowStage()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::UIABILITY, "env not found Ability.sts");
        return nullptr;
    }
    TAG_LOGE(AAFwkTag::UIABILITY, "CreateAppWindowStage start");
    auto scene = GetScene();
    if (!scene) {
        TAG_LOGE(AAFwkTag::UIABILITY, "scene not found");
        return nullptr;
    }
    ani_object stsWindowStage = CreateAniWindowStage(env, scene);
    if (stsWindowStage == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsWindowStage");
        return nullptr;
    }
    TAG_LOGE(AAFwkTag::UIABILITY, "CreateAppWindowStage end");
    return stsWindowStage;
}

void StsUIAbility::GetPageStackFromWant(const Want &want, std::string &pageStack)
{
    auto stringObj = AAFwk::IString::Query(want.GetParams().GetParam(PAGE_STACK_PROPERTY_NAME));
    if (stringObj != nullptr) {
        pageStack = AAFwk::String::Unbox(stringObj);
    }
}

bool StsUIAbility::IsRestorePageStack(const Want &want)
{
    return want.GetBoolParam(SUPPORT_CONTINUE_PAGE_STACK_PROPERTY_NAME, true);
}

void StsUIAbility::RestorePageStack(const Want &want)
{
    if (IsRestorePageStack(want)) {
        std::string pageStack;
        GetPageStackFromWant(want, pageStack);
        auto window = scene_->GetMainWindow();
        if (window == nullptr) {
            TAG_LOGE(AAFwkTag::UIABILITY, "null window");
        }
        auto wrapper = static_cast<STSNativeReferenceWrapper*>(abilityContext_->GetContentStorage().release());
        if (wrapper != nullptr) {
            auto env = stsRuntime_.GetAniEnv();
            if (!env) {
                TAG_LOGE(AAFwkTag::UIABILITY, "env not found Ability.sts");
                return;
            }
            if (wrapper->ref_ == nullptr) {
                TAG_LOGE(AAFwkTag::UIABILITY, "null STSNativeReference");
                return;
            }
            if (wrapper->ref_->aniRef == nullptr) {
                TAG_LOGE(AAFwkTag::UIABILITY, "null aniRef");
                return;
            }
            TAG_LOGD(AAFwkTag::UIABILITY, "NapiSetUIContent");
            window->NapiSetUIContent(pageStack, env, reinterpret_cast<ani_object>(wrapper->ref_->aniRef),
                Rosen::BackupAndRestoreType::CONTINUATION);
        } else {
            TAG_LOGE(AAFwkTag::UIABILITY, "null content storage");
        }
    }
}

void StsUIAbility::AbilityContinuationOrRecover(const Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "launch reason: %{public}d, last exit reasion: %{public}d", launchParam_.launchReason,
        launchParam_.lastExitReason);
    if (IsRestoredInContinuation()) {
        RestorePageStack(want);
        OnSceneRestored();
        NotifyContinuationResult(want, true);
    } else if (ShouldRecoverState(want)) {
        std::string pageStack = abilityRecovery_->GetSavedPageStack(AppExecFwk::StateReason::DEVELOPER_REQUEST);

        auto mainWindow = scene_->GetMainWindow();
        if (mainWindow != nullptr) {
        } else {
            TAG_LOGE(AAFwkTag::UIABILITY, "null mainWindow");
        }
        OnSceneRestored();
    } else {
        if (ShouldDefaultRecoverState(want) &&abilityRecovery_ != nullptr &&scene_ != nullptr) {
            TAG_LOGD(AAFwkTag::UIABILITY, "need restore");
            std::string pageStack = abilityRecovery_->GetSavedPageStack(AppExecFwk::StateReason::DEVELOPER_REQUEST);
            auto mainWindow = scene_->GetMainWindow();
            if (!pageStack.empty() &&mainWindow != nullptr) {
                mainWindow->SetRestoredRouterStack(pageStack);
            }
        }
        OnSceneCreated();
    }
}

void StsUIAbility::DoOnForeground(const Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (scene_ == nullptr) {
        if ((abilityContext_ == nullptr) || (sceneListener_ == nullptr)) {
            TAG_LOGE(AAFwkTag::UIABILITY, "null abilityContext or sceneListener_");
            return;
        }
        DoOnForegroundForSceneIsNull(want);
    } else {
        auto window = scene_->GetMainWindow();
        if (window != nullptr &&want.HasParameter(Want::PARAM_RESV_WINDOW_MODE)) {
            auto windowMode = want.GetIntParam(
                Want::PARAM_RESV_WINDOW_MODE, AAFwk::AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_UNDEFINED);
            window->SetWindowMode(static_cast<Rosen::WindowMode>(windowMode));
            windowMode_ = windowMode;
            TAG_LOGD(AAFwkTag::UIABILITY, "set window mode: %{public}d", windowMode);
        }
    }

    auto window = scene_->GetMainWindow();
    if (window != nullptr &&securityFlag_) {
        window->SetSystemPrivacyMode(true);
    }

    if (CheckIsSilentForeground()) {
        TAG_LOGI(AAFwkTag::UIABILITY, "silent foreground, do not show window");
        return;
    }

    TAG_LOGD(AAFwkTag::UIABILITY, "move scene to foreground, sceneFlag_: %{public}d", UIAbility::sceneFlag_);
    AddLifecycleEventBeforeJSCall(FreezeUtil::TimeoutState::FOREGROUND, METHOD_NAME);
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, "scene_->GoForeground");
    scene_->GoForeground(UIAbility::sceneFlag_);
    TAG_LOGD(AAFwkTag::UIABILITY, "end");
}

void StsUIAbility::DoOnForegroundForSceneIsNull(const Want &want)
{
    scene_ = std::make_shared<Rosen::WindowScene>();
    int32_t displayId = AAFwk::DisplayUtil::GetDefaultDisplayId();
    if (setting_ != nullptr) {
        std::string strDisplayId = setting_->GetProperty(OHOS::AppExecFwk::AbilityStartSetting::WINDOW_DISPLAY_ID_KEY);
        std::regex formatRegex("[0-9]{0,9}$");
        std::smatch sm;
        bool flag = std::regex_match(strDisplayId, sm, formatRegex);
        if (flag &&!strDisplayId.empty()) {
            displayId = strtol(strDisplayId.c_str(), nullptr, BASE_DISPLAY_ID_NUM);
            TAG_LOGD(AAFwkTag::UIABILITY, "displayId: %{public}d", displayId);
        } else {
            TAG_LOGW(AAFwkTag::UIABILITY, "formatRegex: [%{public}s] failed", strDisplayId.c_str());
        }
    }
    auto option = GetWindowOption(want);
    Rosen::WMError ret = Rosen::WMError::WM_OK;
    auto sessionToken = GetSessionToken();
    auto identityToken = GetIdentityToken();
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, "scene_->Init");
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled() &&sessionToken != nullptr) {
        abilityContext_->SetWeakSessionToken(sessionToken);
        ret = scene_->Init(displayId, abilityContext_, sceneListener_, option, sessionToken, identityToken);
    } else {
        ret = scene_->Init(displayId, abilityContext_, sceneListener_, option);
    }
    if (ret != Rosen::WMError::WM_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "init window scene failed");
        FreezeUtil::GetInstance().AppendLifecycleEvent(AbilityContext::token_,
            std::string("JsUIAbility::DoOnForegroundForSceneIsNull; error ") + std::to_string(static_cast<int>(ret)));
        return;
    }

    AbilityContinuationOrRecover(want);
    auto window = scene_->GetMainWindow();
    if (window) {
        TAG_LOGD(AAFwkTag::UIABILITY, "registerDisplayMoveListener, windowId: %{public}d", window->GetWindowId());
        abilityDisplayMoveListener_ = new AbilityDisplayMoveListener(weak_from_this());
        if (abilityDisplayMoveListener_ == nullptr) {
            TAG_LOGE(AAFwkTag::UIABILITY, "null abilityDisplayMoveListener_");
            return;
        }
        window->RegisterDisplayMoveListener(abilityDisplayMoveListener_);
    }
}

void StsUIAbility::RequestFocus(const Want &want)
{
    TAG_LOGI(AAFwkTag::UIABILITY, "called");
    if (scene_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null scene_");
        return;
    }
    auto window = scene_->GetMainWindow();
    if (window != nullptr &&want.HasParameter(Want::PARAM_RESV_WINDOW_MODE)) {
        auto windowMode = want.GetIntParam(
            Want::PARAM_RESV_WINDOW_MODE, AAFwk::AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_UNDEFINED);
        window->SetWindowMode(static_cast<Rosen::WindowMode>(windowMode));
        TAG_LOGD(AAFwkTag::UIABILITY, "set window mode: %{public}d", windowMode);
    }
    AddLifecycleEventBeforeJSCall(FreezeUtil::TimeoutState::FOREGROUND, METHOD_NAME);
    scene_->GoForeground(UIAbility::sceneFlag_);
    TAG_LOGI(AAFwkTag::UIABILITY, "end");
}

void StsUIAbility::ContinuationRestore(const Want &want)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (!IsRestoredInContinuation()) {
        TAG_LOGE(AAFwkTag::UIABILITY, "not in continuation");
        return;
    }
    if (scene_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null scene_");
        return;
    }
    RestorePageStack(want);
    OnSceneRestored();
    NotifyContinuationResult(want, true);
}

std::shared_ptr<STSNativeReference> StsUIAbility::GetJsWindowStage()
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (stsWindowStageObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsWindowStageObj_");
    }
    return stsWindowStageObj_;
}

const STSRuntime &StsUIAbility::GetSTSRuntime()
{
    return stsRuntime_;
}

void StsUIAbility::ExecuteInsightIntentRepeateForeground(const Want &want,
    const std::shared_ptr<InsightIntentExecuteParam> &executeParam,
    std::unique_ptr<InsightIntentExecutorAsyncCallback> callback)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (executeParam == nullptr) {
        TAG_LOGW(AAFwkTag::UIABILITY, "null executeParam");
        RequestFocus(want);
        InsightIntentExecutorMgr::TriggerCallbackInner(std::move(callback), ERR_OK);
        return;
    }

    auto asyncCallback = [weak = weak_from_this(), want](InsightIntentExecuteResult result) {
        TAG_LOGD(AAFwkTag::UIABILITY, "request focus");
        auto ability = weak.lock();
        if (ability == nullptr) {
            TAG_LOGE(AAFwkTag::UIABILITY, "null ability");
            return;
        }
        ability->RequestFocus(want);
    };
    callback->Push(asyncCallback);

    InsightIntentExecutorInfo executeInfo;
    auto ret = GetInsightIntentExecutorInfo(want, executeParam, executeInfo);
    if (!ret) {
        TAG_LOGE(AAFwkTag::UIABILITY, "get intentExecutor failed");
        InsightIntentExecutorMgr::TriggerCallbackInner(
            std::move(callback), static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_PARAM));
        return;
    }

    ret = DelayedSingleton<InsightIntentExecutorMgr>::GetInstance()->ExecuteInsightIntent(
        stsRuntime_, executeInfo, std::move(callback));
    if (!ret) {
        // callback has removed, release in insight intent executor.
        TAG_LOGE(AAFwkTag::UIABILITY, "execute insightIntent failed");
    }
}

void StsUIAbility::ExecuteInsightIntentMoveToForeground(const Want &want,
    const std::shared_ptr<InsightIntentExecuteParam> &executeParam,
    std::unique_ptr<InsightIntentExecutorAsyncCallback> callback)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (executeParam == nullptr) {
        TAG_LOGW(AAFwkTag::UIABILITY, "null executeParam");
        OnForeground(want);
        InsightIntentExecutorMgr::TriggerCallbackInner(std::move(callback), ERR_OK);
        return;
    }

    if (abilityInfo_) {
    }
    UIAbility::OnForeground(want);

    auto asyncCallback = [weak = weak_from_this(), want](InsightIntentExecuteResult result) {
        TAG_LOGD(AAFwkTag::UIABILITY, "begin call onForeground");
        auto ability = weak.lock();
        if (ability == nullptr) {
            TAG_LOGE(AAFwkTag::UIABILITY, "null ability");
            return;
        }
        ability->CallOnForegroundFunc(want);
    };
    callback->Push(asyncCallback);

    InsightIntentExecutorInfo executeInfo;
    auto ret = GetInsightIntentExecutorInfo(want, executeParam, executeInfo);
    if (!ret) {
        TAG_LOGE(AAFwkTag::UIABILITY, "get intentExecutor failed");
        InsightIntentExecutorMgr::TriggerCallbackInner(
            std::move(callback), static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_PARAM));
        return;
    }

    ret = DelayedSingleton<InsightIntentExecutorMgr>::GetInstance()->ExecuteInsightIntent(
        stsRuntime_, executeInfo, std::move(callback));
    if (!ret) {
        // callback has removed, release in insight intent executor.
        TAG_LOGE(AAFwkTag::UIABILITY, "execute insightIntent failed");
    }
}

void StsUIAbility::ExecuteInsightIntentBackground(const Want &want,
    const std::shared_ptr<InsightIntentExecuteParam> &executeParam,
    std::unique_ptr<InsightIntentExecutorAsyncCallback> callback)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (executeParam == nullptr) {
        TAG_LOGW(AAFwkTag::UIABILITY, "null executeParam");
        InsightIntentExecutorMgr::TriggerCallbackInner(std::move(callback), ERR_OK);
        return;
    }

    if (abilityInfo_) {
    }

    InsightIntentExecutorInfo executeInfo;
    auto ret = GetInsightIntentExecutorInfo(want, executeParam, executeInfo);
    if (!ret) {
        TAG_LOGE(AAFwkTag::UIABILITY, "get intentExecutor failed");
        InsightIntentExecutorMgr::TriggerCallbackInner(
            std::move(callback), static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_PARAM));
        return;
    }

    ret = DelayedSingleton<InsightIntentExecutorMgr>::GetInstance()->ExecuteInsightIntent(
        stsRuntime_, executeInfo, std::move(callback));
    if (!ret) {
        // callback has removed, release in insight intent executor.
        TAG_LOGE(AAFwkTag::UIABILITY, "execute insightIntent failed");
    }
}

bool StsUIAbility::GetInsightIntentExecutorInfo(const Want &want,
    const std::shared_ptr<InsightIntentExecuteParam> &executeParam, InsightIntentExecutorInfo &executeInfo)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");

    auto context = GetAbilityContext();
    if (executeParam == nullptr || context == nullptr || abilityInfo_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "param invalid");
        return false;
    }

    if (executeParam->executeMode_ == AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND &&stsWindowStageObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "param invalid");
        return false;
    }

    const WantParams &wantParams = want.GetParams();
    executeInfo.srcEntry = wantParams.GetStringParam("ohos.insightIntent.srcEntry");
    executeInfo.hapPath = abilityInfo_->hapPath;
    executeInfo.esmodule = abilityInfo_->compileMode == AppExecFwk::CompileMode::ES_MODULE;
    executeInfo.windowMode = windowMode_;
    executeInfo.token = context->GetToken();
    if (stsWindowStageObj_ != nullptr) {
        std::shared_ptr<STSNativeReferenceWrapper> etsNativeRef = std::make_shared<STSNativeReferenceWrapper>();
        etsNativeRef->ref_ = stsWindowStageObj_;
        executeInfo.pageLoader = etsNativeRef;
    }
    executeInfo.executeParam = executeParam;
    return true;
}

int32_t StsUIAbility::OnCollaborate(WantParams &wantParam)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "OnCollaborate: %{public}s", GetAbilityName().c_str());
    int32_t ret = CollaborateResult::REJECT;

    if (stsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsAbilityObj_");
        return ret;
    }
    ret = (ret == CollaborateResult::ACCEPT) ? CollaborateResult::ACCEPT : CollaborateResult::REJECT;
    return ret;
}

#endif

int32_t StsUIAbility::OnContinue(
    WantParams &wantParams, bool &isAsyncOnContinue, const AppExecFwk::AbilityInfo &abilityInfo)
{
    TAG_LOGI(AAFwkTag::UIABILITY, "called");
    if (stsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsAbilityObj_");
        return AppExecFwk::ContinuationManagerStage::OnContinueResult::ON_CONTINUE_ERR;
    }
    TAG_LOGI(AAFwkTag::UIABILITY, "end");
    return 0;
}

int32_t StsUIAbility::OnSaveState(int32_t reason, WantParams &wantParams)
{
    if (stsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsAbilityObj_");
        return -1;
    }
    return -1;
}

void StsUIAbility::OnConfigurationUpdated(const Configuration &configuration)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    UIAbility::OnConfigurationUpdated(configuration);
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (abilityContext_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null abilityContext");
        return;
    }
    auto fullConfig = abilityContext_->GetConfiguration();
    if (fullConfig == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null fullConfig");
        return;
    }

    TAG_LOGD(AAFwkTag::UIABILITY, "fullConfig: %{public}s", fullConfig->GetName().c_str());
}

void StsUIAbility::OnMemoryLevel(int level)
{
    UIAbility::OnMemoryLevel(level);
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (stsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsAbilityObj_");
        return;
    }
}

void StsUIAbility::UpdateContextConfiguration()
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (abilityContext_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null abilityContext_");
        return;
    }
}

void StsUIAbility::OnNewWant(const Want &want)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    UIAbility::OnNewWant(want);

#ifdef SUPPORT_SCREEN
    if (scene_) {
        scene_->OnNewWant(want);
    }
#endif
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    if (stsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsAbilityObj_");
        return;
    }
    ani_status status = ANI_OK;
    ani_field field = nullptr;
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null wantObj");
        return;
    }

    auto applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }
    if ((status = env->Class_FindField(stsAbilityObj_->aniCls, "lastRequestWant", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    if ((status = env->Object_SetField_Ref(stsAbilityObj_->aniObj, field, wantRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
    }
    auto launchParam = GetLaunchParam();
    if (InsightIntentExecuteParam::IsInsightIntentExecute(want)) {
        launchParam.launchReason = AAFwk::LaunchReason::LAUNCHREASON_INSIGHT_INTENT;
    }
    ani_ref launchParamRef = CreateStsLaunchParam(env, launchParam);
    std::string methodName = "OnNewWant";
    AddLifecycleEventBeforeJSCall(FreezeUtil::TimeoutState::FOREGROUND, methodName);
    const char *signature =
        "L@ohos/app/ability/Want/Want;L@ohos/app/ability/AbilityConstant/AbilityConstant/LaunchParam;:V";
    CallObjectMethod(false, "onNewWant", signature, wantRef, launchParamRef);
    AddLifecycleEventAfterJSCall(FreezeUtil::TimeoutState::FOREGROUND, methodName);

    applicationContext = AbilityRuntime::Context::GetApplicationContext();
    if (applicationContext != nullptr) {
    }
    TAG_LOGD(AAFwkTag::UIABILITY, "end");
}

void StsUIAbility::OnAbilityResult(int requestCode, int resultCode, const Want &resultData)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    UIAbility::OnAbilityResult(requestCode, resultCode, resultData);
    if (abilityContext_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null abilityContext_");
        return;
    }
    abilityContext_->OnAbilityResult(requestCode, resultCode, resultData);
    TAG_LOGD(AAFwkTag::UIABILITY, "end");
}

sptr<IRemoteObject> StsUIAbility::CallRequest()
{
    TAG_LOGI(AAFwkTag::UIABILITY, "CallRequest");
    if (stsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null abilityContext_");
        return nullptr;
    }

    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return nullptr;
    }
    auto obj = stsAbilityObj_->aniObj;
    ani_status status = ANI_ERROR;
    ani_ref calleeRef = nullptr;
    status = env->Object_GetFieldByName_Ref(obj, "callee", &calleeRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "get callee: %{public}d", status);
        return nullptr;
    }
    auto remoteObj = AniGetNativeRemoteObject(env, reinterpret_cast<ani_object>(calleeRef));
    if (remoteObj == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "AniGetNativeRemoteObject null");
    }
    return remoteObj;
}

bool StsUIAbility::CallObjectMethod(bool withResult, const char *name, const char *signature, ...)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, std::string("CallObjectMethod:") + name);
    TAG_LOGI(AAFwkTag::UIABILITY, "StsUIAbility call sts, name: %{public}s", name);
    if (stsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsAbilityObj");
        return false;
    }
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return false;
    }
    auto obj = stsAbilityObj_->aniObj;
    auto cls = stsAbilityObj_->aniCls;
    ani_status status = ANI_ERROR;

    ani_method method {};
    if ((status = env->Class_FindMethod(cls, name, signature, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return false;
    }
    env->ResetError();
    if (withResult) {
        ani_boolean res = false;
        va_list args;
        va_start(args, signature);
        if ((status = env->Object_CallMethod_Boolean_V(obj, method, &res, args)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
            stsRuntime_.HandleUncaughtError();
            return false;
        }
        va_end(args);
        return res;
    }
    int64_t timeStart = AbilityRuntime::TimeUtil::SystemTimeMillisecond();
    va_list args;
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(obj, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        stsRuntime_.HandleUncaughtError();
        return false;
    }
    va_end(args);
    int64_t timeEnd = AbilityRuntime::TimeUtil::SystemTimeMillisecond();
    TAG_LOGI(AAFwkTag::UIABILITY, "end, name: %{public}s, time: %{public}s", name,
        std::to_string(timeEnd - timeStart).c_str());
    return false;
}

std::shared_ptr<AppExecFwk::ETSDelegatorAbilityProperty> StsUIAbility::CreateADelegatorAbilityProperty()
{
    if (abilityContext_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null abilityContext_");
        return nullptr;
    }
    auto property = std::make_shared<AppExecFwk::ETSDelegatorAbilityProperty>();
    property->token_ = abilityContext_->GetToken();
    property->name_ = GetAbilityName();
    property->moduleName_ = GetModuleName();
    if (GetApplicationInfo() == nullptr || GetApplicationInfo()->bundleName.empty()) {
        property->fullName_ = GetAbilityName();
    } else {
        std::string::size_type pos = GetAbilityName().find(GetApplicationInfo()->bundleName);
        if (pos == std::string::npos || pos != 0) {
            property->fullName_ = GetApplicationInfo()->bundleName + "." + GetAbilityName();
        } else {
            property->fullName_ = GetAbilityName();
        }
    }
    property->lifecycleState_ = GetState();
    property->object_ = stsAbilityObj_;
    return property;
}

void StsUIAbility::Dump(const std::vector<std::string> &params, std::vector<std::string> &info)
{
    UIAbility::Dump(params, info);
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    TAG_LOGD(AAFwkTag::UIABILITY, "dump info size: %{public}zu", info.size());
}

std::shared_ptr<STSNativeReference> StsUIAbility::GetStsAbility()
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (stsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null stsAbilityObj_");
    }
    return stsAbilityObj_;
}

#ifdef SUPPORT_SCREEN
void StsUIAbility::UpdateStsWindowStage(ani_ref windowStage)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "called");
    if (shellContextRef_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null shellContextRef_");
        return;
    }
    ani_object contextObj = shellContextRef_->aniObj;
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    ani_field field = nullptr;
    ani_class cls = shellContextRef_->aniCls;
    ani_status status = ANI_ERROR;
    if (windowStage == nullptr) {
        if ((status = env->Class_FindField(cls, "windowStage", &field)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
            return;
        }
        ani_ref nullRef = nullptr;
        env->GetNull(&nullRef);
        if ((status = env->Object_SetField_Ref(contextObj, field, nullRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
            return;
        }
        return;
    }
    if ((status = env->Class_FindField(cls, "windowStage", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return;
    }
    if ((status = env->Object_SetField_Ref(contextObj, field, windowStage)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return;
    }
}
#endif
bool StsUIAbility::CheckSatisfyTargetAPIVersion(int32_t version)
{
    auto applicationInfo = GetApplicationInfo();
    if (!applicationInfo) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null targetAPIVersion");
        return false;
    }
    TAG_LOGD(AAFwkTag::UIABILITY, "targetAPIVersion: %{public}d", applicationInfo->apiTargetVersion);
    return applicationInfo->apiTargetVersion % API_VERSION_MOD >= version;
}

bool StsUIAbility::BackPressDefaultValue()
{
    return CheckSatisfyTargetAPIVersion(API12) ? true : false;
}

void StsUIAbility::OnAfterFocusedCommon(bool isFocused)
{
    auto abilityContext = GetAbilityContext();
    if (abilityContext == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null abilityContext");
        return;
    }
    auto applicationContext = abilityContext->GetApplicationContext();
    if (applicationContext == nullptr || applicationContext->IsAbilityLifecycleCallbackEmpty()) {
        TAG_LOGD(AAFwkTag::UIABILITY, "null applicationContext or lifecycleCallback");
        return;
    }
    if (isFocused) {
    } else {
    }
}
} // namespace AbilityRuntime
} // namespace OHOS
