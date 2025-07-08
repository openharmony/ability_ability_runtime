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

#include "ets_ui_ability.h"

#include <regex>

#include "ability_delegator_registry.h"
#include "ani_common_want.h"
#ifdef SUPPORT_SCREEN
#include "ani_window_stage.h"
#endif
#include "app_recovery.h"
#include "connection_manager.h"
#include "display_util.h"
#include "ets_ability_context.h"
#include "ets_data_struct_converter.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "string_wrapper.h"

#ifdef WINDOWS_PLATFORM
#define ETS_EXPORT __declspec(dllexport)
#else
#define ETS_EXPORT __attribute__((visibility("default")))
#endif

namespace OHOS {
namespace AbilityRuntime {
std::once_flag EtsUIAbility::singletonFlag_;
namespace {
#ifdef SUPPORT_GRAPHICS
const std::string PAGE_STACK_PROPERTY_NAME = "pageStack";
const std::string SUPPORT_CONTINUE_PAGE_STACK_PROPERTY_NAME = "ohos.extra.param.key.supportContinuePageStack";
const std::string METHOD_NAME = "WindowScene::GoForeground";
#endif
#ifdef SUPPORT_SCREEN
constexpr int32_t BASE_DISPLAY_ID_NUM(10);
#endif
constexpr const char *UI_ABILITY_CLASS_NAME = "L@ohos/app/ability/UIAbility/UIAbility;";

void OnDestroyPromiseCallback(ani_env *env, ani_object aniObj)
{
    TAG_LOGI(AAFwkTag::UIABILITY, "OnDestroyPromiseCallback called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    ani_long destroyCallbackPtr = 0;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Long(aniObj, "destroyCallbackPoint", &destroyCallbackPtr)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "Object_GetFieldByName_Long status: %{public}d", status);
        return;
    }
    if (destroyCallbackPtr == 0) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null destroyCallbackPtr");
        return;
    }
    auto *callbackInfo = reinterpret_cast<AppExecFwk::AbilityTransactionCallbackInfo<> *>(destroyCallbackPtr);
    if (callbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null callbackInfo");
        return;
    }
    callbackInfo->Call();
    AppExecFwk::AbilityTransactionCallbackInfo<>::Destroy(callbackInfo);
}
} // namespace

UIAbility *EtsUIAbility::Create(const std::unique_ptr<Runtime> &runtime)
{
    return new (std::nothrow) EtsUIAbility(static_cast<ETSRuntime &>(*runtime));
}

EtsUIAbility::EtsUIAbility(ETSRuntime &etsRuntime) : etsRuntime_(etsRuntime)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "EtsUIAbility called");
}

EtsUIAbility::~EtsUIAbility()
{
    TAG_LOGI(AAFwkTag::UIABILITY, "~EtsUIAbility called");
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    if (shellContextRef_ && shellContextRef_->aniRef) {
        env->GlobalReference_Delete(shellContextRef_->aniRef);
    }
    if (etsWindowStageObj_ && etsWindowStageObj_->aniRef) {
        env->GlobalReference_Delete(etsWindowStageObj_->aniRef);
    }
}

void EtsUIAbility::Init(std::shared_ptr<AppExecFwk::AbilityLocalRecord> record,
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
    std::string srcPath(abilityInfo->package);
    if (!abilityInfo->isModuleJson) {
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
        TAG_LOGD(AAFwkTag::UIABILITY, "etsAbility srcPath: %{public}s", srcPath.c_str());
    }

    std::string moduleName(abilityInfo->moduleName);
    moduleName.append("::").append(abilityInfo->name);
    SetAbilityContext(abilityInfo, record->GetWant(), moduleName, srcPath, application);
}

bool EtsUIAbility::BindNativeMethods()
{
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return false;
    }
    ani_class cls = nullptr;
    ani_status status = env->FindClass(UI_ABILITY_CLASS_NAME, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "FindClass failed status: %{public}d", status);
        return false;
    }
    std::call_once(singletonFlag_, [&status, env, cls]() {
        std::array functions = {
            ani_native_function { "nativeOnDestroyCallback", ":V", reinterpret_cast<void *>(OnDestroyPromiseCallback) },
        };
        status = env->Class_BindNativeMethods(cls, functions.data(), functions.size());
    });
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "Class_BindNativeMethods failed status: %{public}d", status);
        return false;
    }
    return true;
}

void EtsUIAbility::UpdateAbilityObj(
    std::shared_ptr<AbilityInfo> abilityInfo, const std::string &moduleName, const std::string &srcPath)
{
    std::string key = moduleName + "::" + srcPath;
    std::unique_ptr<NativeReference> moduleObj = nullptr;
    etsAbilityObj_ = etsRuntime_.LoadModule(moduleName, srcPath, abilityInfo->hapPath,
        abilityInfo->compileMode == AppExecFwk::CompileMode::ES_MODULE, false, abilityInfo->srcEntrance);
    if (!BindNativeMethods()) {
        TAG_LOGE(AAFwkTag::UIABILITY, "BindNativeMethods failed");
        return;
    }
}

void EtsUIAbility::SetAbilityContext(std::shared_ptr<AbilityInfo> abilityInfo, std::shared_ptr<Want> want,
    const std::string &moduleName, const std::string &srcPath, const std::shared_ptr<OHOSApplication> &application)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "SetAbilityContext called");
    UpdateAbilityObj(abilityInfo, moduleName, srcPath);
    if (etsAbilityObj_ == nullptr || abilityContext_ == nullptr || want == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null etsAbilityObj_ or abilityContext_ or want");
        return;
    }
    int32_t screenMode = want->GetIntParam(AAFwk::SCREEN_MODE_KEY, AAFwk::ScreenMode::IDLE_SCREEN_MODE);
    CreateEtsContext(screenMode, application);
}

void EtsUIAbility::CreateEtsContext(int32_t screenMode, const std::shared_ptr<OHOSApplication> &application)
{
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    if (screenMode == AAFwk::IDLE_SCREEN_MODE) {
        ani_object contextObj = CreateEtsAbilityContext(env, abilityContext_, application);
        if (contextObj == nullptr) {
            TAG_LOGE(AAFwkTag::UIABILITY, "null contextObj");
            return;
        }
        ani_ref contextGlobalRef = nullptr;
        env->GlobalReference_Create(contextObj, &contextGlobalRef);
        ani_status status = env->Object_SetFieldByName_Ref(etsAbilityObj_->aniObj, "context", contextGlobalRef);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::UIABILITY, "Object_SetFieldByName_Ref status: %{public}d", status);
            return;
        }
        shellContextRef_ = std::make_shared<AppExecFwk::ETSNativeReference>();
        shellContextRef_->aniObj = contextObj;
        shellContextRef_->aniRef = contextGlobalRef;
    }
    // to be done: CreateAniEmbeddableUIAbilityContext
}

void EtsUIAbility::OnStart(const Want &want, sptr<AAFwk::SessionInfo> sessionInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "ability: %{public}s", GetAbilityName().c_str());
    UIAbility::OnStart(want, sessionInfo);

    if (!etsAbilityObj_) {
        TAG_LOGE(AAFwkTag::UIABILITY, "not found Ability.js");
        return;
    }
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    ani_object wantObj = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantObj == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null wantObj");
        return;
    }
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetFieldByName_Ref(etsAbilityObj_->aniObj, "launchWant", wantObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "launchWant Object_SetFieldByName_Ref status: %{public}d", status);
        return;
    }
    if ((status = env->Object_SetFieldByName_Ref(etsAbilityObj_->aniObj, "lastRequestWant", wantObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "lastRequestWant Object_SetFieldByName_Ref status: %{public}d", status);
        return;
    }
    auto launchParam = GetLaunchParam();
    if (InsightIntentExecuteParam::IsInsightIntentExecute(want)) {
        launchParam.launchReason = AAFwk::LaunchReason::LAUNCHREASON_INSIGHT_INTENT;
    }
    ani_object launchParamObj = nullptr;
    if (!WrapLaunchParam(env, launchParam, launchParamObj)) {
        TAG_LOGE(AAFwkTag::UIABILITY, "WrapLaunchParam failed");
        return;
    }
    CallObjectMethod(false, "onCreate", nullptr, wantObj, launchParamObj);
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(
        AbilityRuntime::Runtime::Language::ETS);
    if (delegator) {
        TAG_LOGD(AAFwkTag::UIABILITY, "call PostPerformStart");
        delegator->PostPerformStart(CreateADelegatorAbilityProperty());
    }
    TAG_LOGD(AAFwkTag::UIABILITY, "OnStart end");
}

void EtsUIAbility::OnStop()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "OnStop called");
    if (abilityContext_) {
        TAG_LOGD(AAFwkTag::UIABILITY, "set terminating true");
        abilityContext_->SetTerminating(true);
    }
    UIAbility::OnStop();

    CallObjectMethod(false, "onDestroy", nullptr);
    OnStopCallback();
    TAG_LOGD(AAFwkTag::UIABILITY, "OnStop end");
}

void EtsUIAbility::OnStop(AppExecFwk::AbilityTransactionCallbackInfo<> *callbackInfo, bool &isAsyncCallback)
{
    if (callbackInfo == nullptr) {
        isAsyncCallback = false;
        OnStop();
        return;
    }
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "OnStop Begin");
    if (abilityContext_) {
        TAG_LOGD(AAFwkTag::UIABILITY, "set terminating true");
        abilityContext_->SetTerminating(true);
    }
    UIAbility::OnStop();
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

    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr || etsAbilityObj_ == nullptr) {
        isAsyncCallback = false;
        OnStop();
        return;
    }

    ani_long destroyCallbackPoint = reinterpret_cast<ani_long>(callbackInfo);
    ani_status status =
        env->Object_SetFieldByName_Long(etsAbilityObj_->aniObj, "destroyCallbackPoint", destroyCallbackPoint);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "Object_SetFieldByName_Long status: %{public}d", status);
        return;
    }
    isAsyncCallback = CallObjectMethod(true, "callOnDestroy", ":Z");
    TAG_LOGD(AAFwkTag::UIABILITY, "callOnDestroy isAsyncCallback: %{public}d", isAsyncCallback);
    if (!isAsyncCallback) {
        OnStopCallback();
        return;
    }
    TAG_LOGD(AAFwkTag::UIABILITY, "OnStop end");
}

void EtsUIAbility::OnStopCallback()
{
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(
        AbilityRuntime::Runtime::Language::ETS);
    if (delegator) {
        TAG_LOGD(AAFwkTag::UIABILITY, "call PostPerformStop");
        delegator->PostPerformStop(CreateADelegatorAbilityProperty());
    }

    bool ret = ConnectionManager::GetInstance().DisconnectCaller(AbilityContext::token_);
    if (ret) {
        ConnectionManager::GetInstance().ReportConnectionLeakEvent(getpid(), gettid());
        TAG_LOGD(AAFwkTag::UIABILITY, "the service connection is not disconnected");
    }
}

#ifdef SUPPORT_SCREEN
void EtsUIAbility::OnSceneCreated()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "ability: %{public}s", GetAbilityName().c_str());
    UIAbility::OnSceneCreated();
    auto etsAppWindowStage = CreateAppWindowStage();
    if (etsAppWindowStage == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null etsAppWindowStage");
        return;
    }
    UpdateEtsWindowStage(reinterpret_cast<ani_ref>(etsAppWindowStage));
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    etsWindowStageObj_ = std::make_shared<AppExecFwk::ETSNativeReference>();
    etsWindowStageObj_->aniObj = etsAppWindowStage;
    ani_ref entryObjectRef = nullptr;
    env->GlobalReference_Create(etsAppWindowStage, &entryObjectRef);
    etsWindowStageObj_->aniRef = entryObjectRef;
    CallObjectMethod(false, "onWindowStageCreate", nullptr, etsAppWindowStage);
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(
        AbilityRuntime::Runtime::Language::ETS);
    if (delegator) {
        TAG_LOGD(AAFwkTag::UIABILITY, "call PostPerformScenceCreated");
        delegator->PostPerformScenceCreated(CreateADelegatorAbilityProperty());
    }
    TAG_LOGD(AAFwkTag::UIABILITY, "OnSceneCreated end");
}

void EtsUIAbility::onSceneDestroyed()
{
    TAG_LOGD(AAFwkTag::UIABILITY, "ability: %{public}s", GetAbilityName().c_str());
    UIAbility::onSceneDestroyed();
    UpdateEtsWindowStage(nullptr);
    CallObjectMethod(false, "onWindowStageDestroy", nullptr);
    if (scene_ != nullptr) {
        auto window = scene_->GetMainWindow();
        if (window != nullptr) {
            TAG_LOGD(AAFwkTag::UIABILITY, "unRegisterDisplaymovelistener");
            window->UnregisterDisplayMoveListener(abilityDisplayMoveListener_);
        }
    }
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(
        AbilityRuntime::Runtime::Language::ETS);
    if (delegator) {
        TAG_LOGD(AAFwkTag::UIABILITY, "call PostPerformScenceDestroyed");
        delegator->PostPerformScenceDestroyed(CreateADelegatorAbilityProperty());
    }
    TAG_LOGD(AAFwkTag::UIABILITY, "onSceneDestroyed end");
}

void EtsUIAbility::OnForeground(const Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "ability: %{public}s", GetAbilityName().c_str());
    UIAbility::OnForeground(want);
    if (CheckIsSilentForeground()) {
        TAG_LOGD(AAFwkTag::UIABILITY, "silent foreground, do not call 'onForeground'");
        return;
    }
    CallOnForegroundFunc(want);
}

void EtsUIAbility::CallOnForegroundFunc(const Want &want)
{
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    if (etsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null etsAbilityObj_");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_ref wantRef = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantRef == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null wantObj");
        return;
    }
    if ((status = env->Object_SetFieldByName_Ref(etsAbilityObj_->aniObj, "lastRequestWant", wantRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "lastRequestWant Object_SetFieldByName_Ref status: %{public}d", status);
        return;
    }
    CallObjectMethod(false, "onForeground", nullptr, wantRef);
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(
        AbilityRuntime::Runtime::Language::ETS);
    if (delegator) {
        TAG_LOGD(AAFwkTag::UIABILITY, "call PostPerformForeground");
        delegator->PostPerformForeground(CreateADelegatorAbilityProperty());
    }
    TAG_LOGD(AAFwkTag::UIABILITY, "CallOnForegroundFunc end");
}

void EtsUIAbility::OnBackground()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "ability: %{public}s", GetAbilityName().c_str());
    CallObjectMethod(false, "onBackground", nullptr);
    UIAbility::OnBackground();
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(
        AbilityRuntime::Runtime::Language::ETS);
    if (delegator) {
        TAG_LOGD(AAFwkTag::UIABILITY, "call PostPerformBackground");
        delegator->PostPerformBackground(CreateADelegatorAbilityProperty());
    }
    TAG_LOGD(AAFwkTag::UIABILITY, "OnBackground end");
}

ani_object EtsUIAbility::CreateAppWindowStage()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return nullptr;
    }
    auto scene = GetScene();
    if (scene == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "scene not found");
        return nullptr;
    }
    ani_object etsWindowStage = CreateAniWindowStage(env, scene);
    if (etsWindowStage == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null etsWindowStage");
        return nullptr;
    }
    return etsWindowStage;
}

void EtsUIAbility::GetPageStackFromWant(const Want &want, std::string &pageStack)
{
    auto stringObj = AAFwk::IString::Query(want.GetParams().GetParam(PAGE_STACK_PROPERTY_NAME));
    if (stringObj != nullptr) {
        pageStack = AAFwk::String::Unbox(stringObj);
    }
}

bool EtsUIAbility::IsRestorePageStack(const Want &want)
{
    return want.GetBoolParam(SUPPORT_CONTINUE_PAGE_STACK_PROPERTY_NAME, true);
}

void EtsUIAbility::RestorePageStack(const Want &want)
{
    if (IsRestorePageStack(want)) {
        std::string pageStack;
        GetPageStackFromWant(want, pageStack);
        // to be done: AniSetUIContent
    }
}

void EtsUIAbility::AbilityContinuationOrRecover(const Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UIABILITY, "launch reason: %{public}d, last exit reasion: %{public}d", launchParam_.launchReason,
        launchParam_.lastExitReason);
    if (IsRestoredInContinuation()) {
        RestorePageStack(want);
        NotifyContinuationResult(want, true);
        return;
    }
    if (ShouldDefaultRecoverState(want) && abilityRecovery_ != nullptr && scene_ != nullptr) {
        TAG_LOGD(AAFwkTag::UIABILITY, "need restore");
        std::string pageStack = abilityRecovery_->GetSavedPageStack(AppExecFwk::StateReason::DEVELOPER_REQUEST);
        auto mainWindow = scene_->GetMainWindow();
        if (!pageStack.empty() && mainWindow != nullptr) {
            mainWindow->SetRestoredRouterStack(pageStack);
        }
    }
    OnSceneCreated();
}

void EtsUIAbility::DoOnForeground(const Want &want)
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
        if (window != nullptr && want.HasParameter(Want::PARAM_RESV_WINDOW_MODE)) {
            auto windowMode = want.GetIntParam(
                Want::PARAM_RESV_WINDOW_MODE, AAFwk::AbilityWindowConfiguration::MULTI_WINDOW_DISPLAY_UNDEFINED);
            window->SetWindowMode(static_cast<Rosen::WindowMode>(windowMode));
            windowMode_ = windowMode;
            TAG_LOGD(AAFwkTag::UIABILITY, "set window mode: %{public}d", windowMode);
        }
    }

    auto window = scene_->GetMainWindow();
    if (window != nullptr && securityFlag_) {
        window->SetSystemPrivacyMode(true);
    }

    if (CheckIsSilentForeground()) {
        TAG_LOGI(AAFwkTag::UIABILITY, "silent foreground, do not show window");
        return;
    }

    TAG_LOGD(AAFwkTag::UIABILITY, "move scene to foreground, sceneFlag_: %{public}d", UIAbility::sceneFlag_);
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, "scene_->GoForeground");
    scene_->GoForeground(UIAbility::sceneFlag_);
    TAG_LOGD(AAFwkTag::UIABILITY, "DoOnForeground end");
}

void EtsUIAbility::DoOnForegroundForSceneIsNull(const Want &want)
{
    scene_ = std::make_shared<Rosen::WindowScene>();
    int32_t displayId = AAFwk::DisplayUtil::GetDefaultDisplayId();
    if (setting_ != nullptr) {
        std::string strDisplayId = setting_->GetProperty(OHOS::AppExecFwk::AbilityStartSetting::WINDOW_DISPLAY_ID_KEY);
        std::regex formatRegex("[0-9]{0,9}$");
        std::smatch sm;
        bool flag = std::regex_match(strDisplayId, sm, formatRegex);
        if (flag && !strDisplayId.empty()) {
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
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled() && sessionToken != nullptr) {
        abilityContext_->SetWeakSessionToken(sessionToken);
        ret = scene_->Init(displayId, abilityContext_, sceneListener_, option, sessionToken, identityToken);
    } else {
        ret = scene_->Init(displayId, abilityContext_, sceneListener_, option);
    }
    if (ret != Rosen::WMError::WM_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "init window scene failed");
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

void EtsUIAbility::ContinuationRestore(const Want &want)
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
    NotifyContinuationResult(want, true);
}

void EtsUIAbility::UpdateEtsWindowStage(ani_ref windowStage)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "UpdateEtsWindowStage called");
    if (shellContextRef_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null shellContextRef_");
        return;
    }
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    if (windowStage == nullptr) {
        ani_ref undefinedRef = nullptr;
        env->GetUndefined(&undefinedRef);
        if ((status = env->Object_SetFieldByName_Ref(shellContextRef_->aniObj, "windowStage", undefinedRef)) !=
            ANI_OK) {
            TAG_LOGE(AAFwkTag::UIABILITY, "Object_SetFieldByName_Ref status: %{public}d", status);
            return;
        }
        return;
    }
    if ((status = env->Object_SetFieldByName_Ref(shellContextRef_->aniObj, "windowStage", windowStage)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "Object_SetFieldByName_Ref status: %{public}d", status);
        return;
    }
}
#endif

void EtsUIAbility::OnNewWant(const Want &want)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "OnNewWant called");
    UIAbility::OnNewWant(want);

#ifdef SUPPORT_SCREEN
    if (scene_) {
        scene_->OnNewWant(want);
    }
#endif
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return;
    }
    if (etsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null etsAbilityObj_");
        return;
    }
    ani_object wantObj = OHOS::AppExecFwk::WrapWant(env, want);
    if (wantObj == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null wantObj");
        return;
    }
    ani_status status = env->Object_SetFieldByName_Ref(etsAbilityObj_->aniObj, "lastRequestWant", wantObj);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "lastRequestWant Object_SetFieldByName_Ref status: %{public}d", status);
        return;
    }
    auto launchParam = GetLaunchParam();
    if (InsightIntentExecuteParam::IsInsightIntentExecute(want)) {
        launchParam.launchReason = AAFwk::LaunchReason::LAUNCHREASON_INSIGHT_INTENT;
    }
    ani_object launchParamObj = nullptr;
    if (!WrapLaunchParam(env, launchParam, launchParamObj)) {
        TAG_LOGE(AAFwkTag::UIABILITY, "WrapLaunchParam failed");
        return;
    }
    std::string methodName = "OnNewWant";
    CallObjectMethod(false, "onNewWant", nullptr, wantObj, launchParamObj);
    TAG_LOGD(AAFwkTag::UIABILITY, "OnNewWant end");
}

void EtsUIAbility::OnAbilityResult(int requestCode, int resultCode, const Want &resultData)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "OnAbilityResult called");
    UIAbility::OnAbilityResult(requestCode, resultCode, resultData);
    if (abilityContext_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null abilityContext_");
        return;
    }
    abilityContext_->OnAbilityResult(requestCode, resultCode, resultData);
    TAG_LOGD(AAFwkTag::UIABILITY, "OnAbilityResult end");
}

bool EtsUIAbility::CallObjectMethod(bool withResult, const char *name, const char *signature, ...)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, std::string("CallObjectMethod:") + name);
    TAG_LOGI(AAFwkTag::UIABILITY, "EtsUIAbility call ets, name: %{public}s", name);
    if (etsAbilityObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null etsAbilityObj");
        return false;
    }
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return false;
    }
    auto obj = etsAbilityObj_->aniObj;
    auto cls = etsAbilityObj_->aniCls;

    ani_method method = nullptr;
    ani_status status = env->Class_FindMethod(cls, name, signature, &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "Class_FindMethod status: %{public}d", status);
        env->ResetError();
        return false;
    }
    if (withResult) {
        ani_boolean res = ANI_FALSE;
        va_list args;
        va_start(args, signature);
        if ((status = env->Object_CallMethod_Boolean_V(obj, method, &res, args)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UIABILITY, "Object_CallMethod_Boolean_V status: %{public}d", status);
            etsRuntime_.HandleUncaughtError();
            return false;
        }
        va_end(args);
        return res;
    }
    va_list args;
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(obj, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "Object_CallMethod_Void_V status: %{public}d", status);
        etsRuntime_.HandleUncaughtError();
        return false;
    }
    va_end(args);
    TAG_LOGI(AAFwkTag::UIABILITY, "CallObjectMethod end, name: %{public}s", name);
    return false;
}

std::shared_ptr<AppExecFwk::ETSDelegatorAbilityProperty> EtsUIAbility::CreateADelegatorAbilityProperty()
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
    property->object_ = etsAbilityObj_;
    return property;
}
} // namespace AbilityRuntime
} // namespace OHOS

ETS_EXPORT extern "C" OHOS::AbilityRuntime::UIAbility *OHOS_ETS_Ability_Create(
    const std::unique_ptr<OHOS::AbilityRuntime::Runtime> &runtime)
{
    return OHOS::AbilityRuntime::EtsUIAbility::Create(runtime);
}