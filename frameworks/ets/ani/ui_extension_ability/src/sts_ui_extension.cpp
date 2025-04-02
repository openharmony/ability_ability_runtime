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

#include "sts_ui_extension.h"
#include "ability_context.h"
#include "ability_delegator_registry.h"
#include "ability_info.h"
#include "ability_manager_client.h"
#include "ability_start_setting.h"
#include "configuration_utils.h"
#include "connection_manager.h"
#include "context.h"
#include "hitrace_meter.h"
#include "hilog_tag_wrapper.h"
#include "insight_intent_executor_info.h"
#include "insight_intent_executor_mgr.h"
#include "int_wrapper.h"
#include "sts_runtime.h"
#include "ani_common_want.h"
#include "ui_extension_window_command.h"
#include "want_params_wrapper.h"
#include "sts_data_struct_converter.h"
#include "sts_ui_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;

static constexpr char UIEXTENSION_CLASS_NAME[] = "L@ohos/app/ability/UIExtensionAbility/UIExtensionAbility;";

StsUIExtension* StsUIExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    return new (std::nothrow) StsUIExtension(static_cast<STSRuntime&>(*runtime));
}

StsUIExtension::StsUIExtension(STSRuntime &stsRuntime) : stsRuntime_(stsRuntime)
{
}

StsUIExtension::~StsUIExtension()
{
    TAG_LOGI(AAFwkTag::UI_EXT, "Js ui extension destructor");
    auto context = GetContext();
    if (context) {
        context->Unbind();
    }
	//need runtime free reference
    contentSessions_.clear();
}

void StsUIExtension::ResetEnv(ani_env* env)
{
    env->DescribeError();  // 打印异常信息
    env->ResetError();  // 清除异常，避免影响后续 ANI 调用
}

static void PromiseCallback(ani_env* env, ani_object aniObj)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "PromiseCallback");
    if (env == nullptr || aniObj == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env or null aniObj");
        return;
    }
    ani_long destroyCallbackPoint = 0;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Long(aniObj, "destroyCallbackPoint", &destroyCallbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        return;
    }
    auto *callbackInfo = reinterpret_cast<AppExecFwk::AbilityTransactionCallbackInfo<> *>(destroyCallbackPoint);
    if (callbackInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null callbackInfo");
        return;
    }
    callbackInfo->Call();
    AppExecFwk::AbilityTransactionCallbackInfo<>::Destroy(callbackInfo);

    if ((status = env->Object_SetFieldByName_Long(aniObj, "destroyCallbackPoint",
        static_cast<ani_long>(0))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        return;
    }
}

void StsUIExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension init");
    if (record == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "record null");
        return;
    }
    UIExtension::Init(record, application, handler, token);
    if (Extension::abilityInfo_ == nullptr || Extension::abilityInfo_->srcEntrance.empty()) {
        TAG_LOGE(AAFwkTag::UI_EXT, "StsUIExtension Init abilityInfo error");
        return;
    }

    if (record != nullptr) {
        token_ = record->GetToken();
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
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to get stsObj_");
        return;
    }

    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    std::array functions = {
        ani_native_function { "nativeOnDestroyCallback", ":V", reinterpret_cast<void*>(PromiseCallback) },
    };
    ani_status status = ANI_ERROR;
    if ((status = env->Class_BindNativeMethods(stsObj_->aniCls, functions.data(), functions.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
    }
    BindContext(env, record->GetWant(), application);
    RegisterDisplayInfoChangedListener();
}

std::shared_ptr<STSNativeReference> StsUIExtension::LoadModule(ani_env *env)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::LoadModule");
    std::shared_ptr<STSNativeReference> stsNativeReference = std::make_shared<STSNativeReference>();
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(UIEXTENSION_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "status: %{public}d", status);
    }

    ani_method entryMethod = nullptr;
    if (env->Class_FindMethod(cls, "<ctor>", ":V", &entryMethod) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Class_FindMethod ctor failed");
    }

    ani_object entryObject = nullptr;
    if (env->Object_New(cls, entryMethod, &entryObject) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Object_New AbcRuntimeLinker failed");
    }

    ani_ref entryObjectRef = nullptr;
    if (env->GlobalReference_Create(entryObject, &entryObjectRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "GlobalReference_Create failed");
    }
    stsNativeReference->aniCls = cls;
    stsNativeReference->aniObj = entryObject;
    stsNativeReference->aniRef = entryObjectRef;
    return stsNativeReference;
}

ani_object StsUIExtension::CreateSTSContext(ani_env* env, std::shared_ptr<UIExtensionContext> context,
    int32_t screenMode, const std::shared_ptr<OHOSApplication> &application)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "CreateSTSContext");
    ani_object obj = CreateStsUIExtensionContext(env, context, application);
    return obj;
}

void StsUIExtension::BindContext(ani_env*env, std::shared_ptr<AAFwk::Want> want,
    const std::shared_ptr<OHOSApplication> &application)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension BindContext");

    if (env == nullptr || want == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Want info is null or env is null");
        return;
    }

    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to get context");
        return;
    }

    int32_t screenMode = want->GetIntParam(AAFwk::SCREEN_MODE_KEY, AAFwk::IDLE_SCREEN_MODE);
    ani_object contextObj = CreateSTSContext(env, context, screenMode, application);
    if (contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null contextObj");
        return;
    }

    //bind uiExtenstionContext
    ani_field contextField;
    auto status = env->Class_FindField(stsObj_->aniCls, "context", &contextField);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_GetField context failed");
        ResetEnv(env);
        return;
    }

    ani_ref contextRef = nullptr;
    if (env->GlobalReference_Create(contextObj, &contextRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GlobalReference_Create stageCtxObj failed");
        return;
    }

    if (env->Object_SetField_Ref(stsObj_->aniObj, contextField, contextRef) != ANI_OK) {
        TAG_LOGI(AAFwkTag::UI_EXT, "Object_SetField_Ref stageCtxObj failed");
        ResetEnv(env);
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "BindContext end");
}

ani_object StsUIExtension::CreateStsLaunchParam(ani_env* env, const AAFwk::LaunchParam& param)
{
    ani_object obj = nullptr;
    return obj;
}

void StsUIExtension::OnStart(const AAFwk::Want &want, sptr<AAFwk::SessionInfo> sessionInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension OnStart begin");
    //file /native/ability/native/extension.cpp:44 null pointer of abilityInfo_
    //Extension::OnStart(want);
    auto context = GetContext();
#ifdef SUPPORT_GRAPHICS
    if (context != nullptr && sessionInfo != nullptr) {
        auto configUtils = std::make_shared<ConfigurationUtils>();
        configUtils->InitDisplayConfig(context->GetConfiguration(), context->GetResourceManager(),
            sessionInfo->displayId, sessionInfo->density, sessionInfo->orientation);
    }
#endif // SUPPORT_GRAPHICS

    auto env = stsRuntime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::UI_EXT, "env not found Ability.sts");
        return;
    }

    const char *signature =
        "L@ohos/app/ability/AbilityConstant/AbilityConstant/LaunchParam;:V";

    auto launchParam = Extension::GetLaunchParam();
    if (InsightIntentExecuteParam::IsInsightIntentExecute(want)) {
        launchParam.launchReason = AAFwk::LaunchReason::LAUNCHREASON_INSIGHT_INTENT;
    }
    ani_object launchParamRef = CreateStsLaunchParam(env, launchParam);

    CallObjectMethod(false, "onCreate", signature, launchParamRef);

    TAG_LOGI(AAFwkTag::UI_EXT, "OnStart end");
}

void StsUIExtension::OnStop()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    // FILE Extension abilityInfo_ is nullptr
    //UIExtension::OnStop();
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension onStop");
    //HandleScope handleScope(jsRuntime_);
    CallObjectMethod(false, "onDestroy", nullptr);
#ifdef SUPPORT_GRAPHICS
    UnregisterDisplayInfoChangedListener();
#endif // SUPPORT_GRAPHICS
    OnStopCallBack();
    TAG_LOGD(AAFwkTag::UI_EXT, "end");
}

void StsUIExtension::OnStop(AppExecFwk::AbilityTransactionCallbackInfo<> *callbackInfo, bool &isAsyncCallback)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension onStop");
    if (callbackInfo == nullptr) {
        isAsyncCallback = false;
        OnStop();
        return;
    }
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::UI_EXT, "begin");
    UIExtension::OnStop();
#ifdef SUPPORT_GRAPHICS
    UnregisterDisplayInfoChangedListener();
#endif // SUPPORT_GRAPHICS

    std::weak_ptr<Extension> weakPtr = shared_from_this();
    auto asyncCallback = [extensionWeakPtr = weakPtr]() {
        auto stsUIExtension = extensionWeakPtr.lock();
        if (stsUIExtension == nullptr) {
            TAG_LOGE(AAFwkTag::UI_EXT, "extension is nullptr");
            return;
        }
        stsUIExtension->OnStopCallBack();
    };
    callbackInfo->Push(asyncCallback);
    ani_long destroyCallbackPoint = (ani_long)callbackInfo;
    ani_status status = ANI_ERROR;
    ani_field field = nullptr;
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr || stsObj_ == nullptr) {
        isAsyncCallback = false;
        OnStop();
        return;
    }
    if ((status = env->Class_FindField(stsObj_->aniCls, "destroyCallbackPoint", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
    }
    if ((status = env->Object_SetField_Long(stsObj_->aniObj, field, destroyCallbackPoint)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
    }

    isAsyncCallback = CallObjectMethod(true, "callOnDestroy", ":Z");
    TAG_LOGI(AAFwkTag::UI_EXT, "callOnDestroy isAsyncCallback: %{public}d", isAsyncCallback);
    if (!isAsyncCallback) {
        OnStopCallBack();
        return;
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "end");
}

void StsUIExtension::OnStopCallBack()
{
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::OnStopCallBack called");
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to get context");
        return;
    }
    bool ret = ConnectionManager::GetInstance().DisconnectCaller(context->GetToken());
    if (ret) {
        ConnectionManager::GetInstance().ReportConnectionLeakEvent(getpid(), gettid());
        TAG_LOGD(AAFwkTag::UI_EXT, "The service connection is not disconnected");
    }
    // auto applicationContext = Context::GetApplicationContext();
    // if (applicationContext != nullptr) {
    //     applicationContext->DispatchOnAbilityDestroy(jsObj_);
    // }
}

sptr<IRemoteObject> StsUIExtension::OnConnect(const AAFwk::Want &want)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::OnConnect called");
    // NAPI_ohos_rpc_getNativeRemoteObject
    // HandleScope handleScope(jsRuntime_);
    // napi_value result = CallOnConnect(want);
    // napi_env env = jsRuntime_.GetNapiEnv();
    // auto remoteObj = NAPI_ohos_rpc_getNativeRemoteObject(env, result);
    // if (remoteObj == nullptr) {
    //     TAG_LOGE(AAFwkTag::UI_EXT, "remoteObj is nullptr");
    // }
    sptr<IRemoteObject> remoteObj = nullptr;
    return remoteObj;
}

void StsUIExtension::OnDisconnect(const AAFwk::Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::OnDisconnect called");
    Extension::OnDisconnect(want);
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension OnDisconnect begin");
    // HandleScope handleScope(jsRuntime_);
    // CallOnDisconnect(want, false);
    // TAG_LOGD(AAFwkTag::UI_EXT, "StsUIExtension OnDisconnect end");
}

ani_status StsUIExtension::CallOnDisconnect(const AAFwk::Want &want, bool withResult)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "CallOnDisconnect called");
    // imp onDisconnect
    // HandleEscape handleEscape(jsRuntime_);
    // napi_env env = jsRuntime_.GetNapiEnv();
    // napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
    // napi_value argv[] = { napiWant };
    // if (!jsObj_) {
    //     TAG_LOGE(AAFwkTag::UI_EXT, "Not found UIExtension.js");
    //     return nullptr;
    // }

    // napi_value obj = jsObj_->GetNapiValue();
    // if (!CheckTypeForNapiValue(env, obj, napi_object)) {
    //     TAG_LOGE(AAFwkTag::UI_EXT, "Failed to get UIExtension object");
    //     return nullptr;
    // }

    // napi_value method = nullptr;
    // napi_get_named_property(env, obj, "onDisconnect", &method);
    // if (method == nullptr) {
    //     TAG_LOGE(AAFwkTag::UI_EXT, "Failed to get onDisconnect from UIExtension object");
    //     return nullptr;
    // }

    // if (withResult) {
    //     napi_value result = nullptr;
    //     napi_call_function(env, obj, method, ARGC_ONE, argv, &result);
    //     return handleEscape.Escape(result);
    // } else {
    //     napi_call_function(env, obj, method, ARGC_ONE, argv, nullptr);
    //     return nullptr;
    // }
    return ANI_OK;
}

void StsUIExtension::OnCommandWindow(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo,
    AAFwk::WindowCommand winCmd)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::OnCommandWindow called");
    if (sessionInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "sessionInfo is nullptr");
        return;
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "begin. persistentId: %{private}d, winCmd: %{public}d",
        sessionInfo->persistentId, winCmd);
    Extension::OnCommandWindow(want, sessionInfo, winCmd);
    if (InsightIntentExecuteParam::IsInsightIntentExecute(want) && winCmd == AAFwk::WIN_CMD_FOREGROUND) {
        if (ForegroundWindowWithInsightIntent(want, sessionInfo, false)) {
            return;
        }
    }
    switch (winCmd) {
        case AAFwk::WIN_CMD_FOREGROUND:
            ForegroundWindow(want, sessionInfo);
            break;
        case AAFwk::WIN_CMD_BACKGROUND:
            BackgroundWindow(sessionInfo);
            break;
        case AAFwk::WIN_CMD_DESTROY:
            DestroyWindow(sessionInfo);
            break;
        default:
            TAG_LOGD(AAFwkTag::UI_EXT, "unsupported cmd");
            break;
    }
    OnCommandWindowDone(sessionInfo, winCmd);
}

bool StsUIExtension::ForegroundWindowWithInsightIntent(const AAFwk::Want &want,
    const sptr<AAFwk::SessionInfo> &sessionInfo, bool needForeground)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::ForegroundWindowWithInsightIntent called");
    if (!HandleSessionCreate(want, sessionInfo)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "HandleSessionCreate failed");
        return false;
    }

    std::unique_ptr<InsightIntentExecutorAsyncCallback> executorCallback = nullptr;
    executorCallback.reset(InsightIntentExecutorAsyncCallback::Create());
    if (executorCallback == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Create async callback failed");
        return false;
    }

    auto uiExtension = std::static_pointer_cast<StsUIExtension>(shared_from_this());
    executorCallback->Push([uiExtension, sessionInfo, needForeground](AppExecFwk::InsightIntentExecuteResult result) {
        TAG_LOGI(AAFwkTag::UI_EXT, "Execute post insightintent");
        if (uiExtension == nullptr) {
            TAG_LOGE(AAFwkTag::UI_EXT, "UI extension is nullptr");
            return;
        }

        uiExtension->PostInsightIntentExecuted(sessionInfo, result, needForeground);
    });

    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to get context");
        return false;
    }
    InsightIntentExecutorInfo executorInfo;
    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = context->GetAbilityInfo();
    if (abilityInfo != nullptr) {
        executorInfo.hapPath = abilityInfo->hapPath;
        executorInfo.windowMode = abilityInfo->compileMode == AppExecFwk::CompileMode::ES_MODULE;
    }
    executorInfo.token = context->GetToken();
    executorInfo.pageLoader = contentSessions_[sessionInfo->uiExtensionComponentId];
    executorInfo.executeParam = std::make_shared<InsightIntentExecuteParam>();
    InsightIntentExecuteParam::GenerateFromWant(want, *executorInfo.executeParam);
    executorInfo.executeParam->executeMode_ = UI_EXTENSION_ABILITY;
    executorInfo.srcEntry = want.GetStringParam(INSIGHT_INTENT_SRC_ENTRY);
    TAG_LOGD(AAFwkTag::UI_EXT, "executorInfo, insightIntentId: %{public}" PRIu64,
        executorInfo.executeParam->insightIntentId_);
    TAG_LOGD(AAFwkTag::UI_EXT, "end");
    return true;
}

void StsUIExtension::PostInsightIntentExecuted(const sptr<AAFwk::SessionInfo> &sessionInfo,
    const AppExecFwk::InsightIntentExecuteResult &result, bool needForeground)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::PostInsightIntentExecuted called");
    if (needForeground) {
        // If uiextensionability is started for the first time or need move background to foreground.
        CallObjectMethod(false, "onForeground", nullptr);
    }

    OnInsightIntentExecuteDone(sessionInfo, result);

    if (needForeground) {
        // If need foreground, that means triggered by onForeground.
        TAG_LOGI(AAFwkTag::UI_EXT, "call abilityms");
        AAFwk::PacMap restoreData;
        AAFwk::AbilityManagerClient::GetInstance()->AbilityTransitionDone(token_, AAFwk::ABILITY_STATE_FOREGROUND_NEW,
            restoreData);
    } else {
        // If uiextensionability has displayed in the foreground.
        OnCommandWindowDone(sessionInfo, AAFwk::WIN_CMD_FOREGROUND);
    }
}

void StsUIExtension::OnCommandWindowDone(const sptr<AAFwk::SessionInfo> &sessionInfo, AAFwk::WindowCommand winCmd)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::OnCommandWindowDone called");
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to get context");
        return;
    }
    AAFwk::AbilityCommand abilityCmd;
    std::lock_guard<std::mutex> lock(uiWindowMutex_);
    if (uiWindowMap_.empty()) {
        abilityCmd = AAFwk::ABILITY_CMD_DESTROY;
    } else if (foregroundWindows_.empty()) {
        abilityCmd = AAFwk::ABILITY_CMD_BACKGROUND;
    } else {
        abilityCmd = AAFwk::ABILITY_CMD_FOREGROUND;
    }
    AAFwk::AbilityManagerClient::GetInstance()->ScheduleCommandAbilityWindowDone(
        context->GetToken(), sessionInfo, winCmd, abilityCmd);
    TAG_LOGD(AAFwkTag::UI_EXT, "end");
}

void StsUIExtension::OnInsightIntentExecuteDone(const sptr<AAFwk::SessionInfo> &sessionInfo,
    const AppExecFwk::InsightIntentExecuteResult &result)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::OnInsightIntentExecuteDone called");
    if (sessionInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Invalid sessionInfo");
        return;
    }
    std::lock_guard<std::mutex> lock(uiWindowMutex_);
    TAG_LOGD(AAFwkTag::UI_EXT, "UIExtension component id: %{public}" PRId64, sessionInfo->uiExtensionComponentId);
    auto componentId = sessionInfo->uiExtensionComponentId;
    auto res = uiWindowMap_.find(componentId);
    if (res != uiWindowMap_.end() && res->second != nullptr) {
        WantParams params;
        params.SetParam(INSIGHT_INTENT_EXECUTE_RESULT_CODE, Integer::Box(result.innerErr));
        WantParams resultParams;
        resultParams.SetParam("code", Integer::Box(result.code));
        if (result.result != nullptr) {
            sptr<AAFwk::IWantParams> pWantParams = WantParamWrapper::Box(*result.result);
            if (pWantParams != nullptr) {
                resultParams.SetParam("result", pWantParams);
            }
        }
        sptr<AAFwk::IWantParams> pWantParams = WantParamWrapper::Box(resultParams);
        if (pWantParams != nullptr) {
            params.SetParam(INSIGHT_INTENT_EXECUTE_RESULT, pWantParams);
        }

        Rosen::WMError ret = res->second->TransferExtensionData(params);
        if (ret == Rosen::WMError::WM_OK) {
            TAG_LOGD(AAFwkTag::UI_EXT, "TransferExtensionData success");
        } else {
            TAG_LOGE(AAFwkTag::UI_EXT, "TransferExtensionData failed, ret=%{public}d", ret);
        }

        res->second->Show();
        foregroundWindows_.emplace(componentId);
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "end");
}

void StsUIExtension::OnCommand(const AAFwk::Want &want, bool restart, int startId)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::OnCommand called");
    TAG_LOGD(AAFwkTag::UI_EXT, "OnCommand end");
}

void StsUIExtension::OnForeground(const Want &want, sptr<AAFwk::SessionInfo> sessionInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::OnForeground called");
    if (sessionInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "sessionInfo nullptr");
        return;
    }
    //  FILE Extension 116 abilityInfo_ is nullptr
    //Extension::OnForeground(want, sessionInfo);

    if (InsightIntentExecuteParam::IsInsightIntentExecute(want)) {
        bool finish = ForegroundWindowWithInsightIntent(want, sessionInfo, true);
        if (finish) {
            return;
        }
    }
    ForegroundWindow(want, sessionInfo);
    CallObjectMethod(false, "onForeground", nullptr);
    TAG_LOGI(AAFwkTag::UI_EXT, "onForeground");
}

void StsUIExtension::OnBackground()
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::OnBackground called");
    CallObjectMethod(false, "onBackground", nullptr);
    //  FILE Extension abilityInfo_ is nullptr
    //Extension::OnBackground();
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::OnBackground end");
}

bool StsUIExtension::HandleSessionCreate(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::HandleSessionCreate called");
    if (sessionInfo == nullptr || sessionInfo->uiExtensionComponentId == 0) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Invalid sessionInfo");
        return false;
    }
    std::lock_guard<std::mutex> lock(uiWindowMutex_);
    TAG_LOGD(AAFwkTag::UI_EXT, "UIExtension component id: %{public}" PRId64 ", element: %{public}s",
        sessionInfo->uiExtensionComponentId, want.GetElement().GetURI().c_str());
    auto compId = sessionInfo->uiExtensionComponentId;
    if (uiWindowMap_.find(compId) == uiWindowMap_.end()) {
        auto context = GetContext();
        auto uiWindow = CreateUIWindow(context, sessionInfo);
        if (uiWindow == nullptr) {
            TAG_LOGE(AAFwkTag::UI_EXT, "create ui window error");
            return false;
        }
        auto env = stsRuntime_.GetAniEnv();
        // napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
        ani_ref wantObj = OHOS::AppExecFwk::WrapWant(env, want);
        if (wantObj == nullptr) {
            TAG_LOGE(AAFwkTag::UI_EXT, "null wantObj");
            return false;
        }
        ani_ref wantRef = nullptr;
        ani_status status = ANI_OK;
        if ((status = env->GlobalReference_Create(wantObj, &wantRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        }
        // create UIExtensionContentSession
        std::weak_ptr<Context> wkctx = context;
        stsUiExtContentSession_ = std::make_shared<StsUIExtensionContentSession>(sessionInfo, uiWindow,
            wkctx, abilityResultListeners_);
        ani_object sessonObj = StsUIExtensionContentSession::CreateStsUIExtensionContentSession(env,
            sessionInfo, uiWindow, context, abilityResultListeners_, stsUiExtContentSession_);
        // napi_value nativeContentSession = JsUIExtensionContentSession::CreateJsUIExtensionContentSession(
        //     env, sessionInfo, uiWindow, context, abilityResultListeners_);
        // napi_ref ref = nullptr;
        // napi_create_reference(env, nativeContentSession, 1, &ref);
        // contentSessions_.emplace(compId, std::shared_ptr<NativeReference>(reinterpret_cast<NativeReference*>(ref)));
        if ((status = env->GlobalReference_Create(sessonObj, &contentSession_)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        }
        int32_t screenMode = want.GetIntParam(AAFwk::SCREEN_MODE_KEY, AAFwk::IDLE_SCREEN_MODE);
        if (screenMode == AAFwk::EMBEDDED_FULL_SCREEN_MODE) {
            screenMode_ = AAFwk::EMBEDDED_FULL_SCREEN_MODE;
            auto jsAppWindowStage = CreateAppWindowStage(uiWindow, sessionInfo);
            if (jsAppWindowStage == nullptr) {
                TAG_LOGE(AAFwkTag::UI_EXT, "JsAppWindowStage is nullptr");
                return false;
            }
            //napi_value argv[] = {jsAppWindowStage->GetNapiValue()};
            //CallObjectMethod("onWindowStageCreate", argv, ARGC_ONE);
        } else {
            CallObjectMethod(false, "onSessionCreate", nullptr, wantObj, sessonObj);
        }
        uiWindowMap_[compId] = uiWindow;
#ifdef SUPPORT_GRAPHICS
        if (context && context->GetWindow() == nullptr) {
            // UIExtensionContext::window_ is nullptr
            context->SetWindow(uiWindow);
        }
#endif // SUPPORT_GRAPHICS
    }
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::HandleSessionCreate end");
    return true;
}

sptr<Rosen::Window> StsUIExtension::CreateUIWindow(const std::shared_ptr<UIExtensionContext> context,
    const sptr<AAFwk::SessionInfo> &sessionInfo)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::CreateUIWindow start");
    if (context == nullptr || context->GetAbilityInfo() == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to get context");
        return nullptr;
    }
    auto option = sptr<Rosen::WindowOption>::MakeSptr();
    if (option == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "make option failed");
        return nullptr;
    }
    option->SetWindowName(context->GetBundleName() + context->GetAbilityInfo()->name);
    option->SetWindowType(Rosen::WindowType::WINDOW_TYPE_UI_EXTENSION);
    option->SetWindowSessionType(Rosen::WindowSessionType::EXTENSION_SESSION);
    option->SetParentId(sessionInfo->hostWindowId);
    option->SetRealParentId(sessionInfo->realHostWindowId);
    option->SetParentWindowType(static_cast<Rosen::WindowType>(sessionInfo->parentWindowType));
    option->SetUIExtensionUsage(static_cast<uint32_t>(sessionInfo->uiExtensionUsage));
    HITRACE_METER_NAME(HITRACE_TAG_APP, "Rosen::Window::Create");
    return Rosen::Window::Create(option, GetContext(), sessionInfo->sessionToken);
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::CreateUIWindow end");
}

std::unique_ptr<STSNativeReference> StsUIExtension::CreateAppWindowStage(sptr<Rosen::Window> uiWindow,
    sptr<AAFwk::SessionInfo> sessionInfo)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::CreateAppWindowStage start");
    // create window stage
    // auto env = jsRuntime_.GetNapiEnv();
    // napi_value jsWindowStage = Rosen::JsEmbeddableWindowStage::CreateJsEmbeddableWindowStage(
    //     env, uiWindow, sessionInfo);
    // if (jsWindowStage == nullptr) {
    //     TAG_LOGE(AAFwkTag::UI_EXT, "Failed to create jsWindowSatge object");
    //     return nullptr;
    // }
    // return JsRuntime::LoadSystemModuleByEngine(env, "application.embeddablewindowstage", &jsWindowStage, 1);
    TAG_LOGI(AAFwkTag::UI_EXT, "StsUIExtension::CreateAppWindowStage end");
    return std::make_unique<STSNativeReference>();
}

void StsUIExtension::ForegroundWindow(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "ForegroundWindow called");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!HandleSessionCreate(want, sessionInfo)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "HandleSessionCreate failed");
        return;
    }
    std::lock_guard<std::mutex> lock(uiWindowMutex_);
    TAG_LOGI(AAFwkTag::UI_EXT, "Before window show UIExtcomponent id: %{public}" PRId64,
        sessionInfo->uiExtensionComponentId);
    auto componentId = sessionInfo->uiExtensionComponentId;
    auto& uiWindow = uiWindowMap_[componentId];
    if (uiWindow) {
        HITRACE_METER_NAME(HITRACE_TAG_APP, "Rosen::Window::show");
        uiWindow->Show();
        foregroundWindows_.emplace(componentId);
    }
    TAG_LOGI(AAFwkTag::UI_EXT, "ForegroundWindow end");
}

void StsUIExtension::BackgroundWindow(const sptr<AAFwk::SessionInfo> &sessionInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::UI_EXT, "BackgroundWindow called");
    if (sessionInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Invalid sessionInfo");
        return;
    }
    std::lock_guard<std::mutex> lock(uiWindowMutex_);
    auto componentId = sessionInfo->uiExtensionComponentId;
    if (uiWindowMap_.find(componentId) == uiWindowMap_.end()) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Fail to find uiWindow");
        return;
    }
    auto& uiWindow = uiWindowMap_[componentId];
    TAG_LOGI(AAFwkTag::UI_EXT, "Befor window hide UIExtcomponent id: %{public}" PRId64,
        sessionInfo->uiExtensionComponentId);
    if (uiWindow) {
        uiWindow->Hide();
        foregroundWindows_.erase(componentId);
    }
    TAG_LOGI(AAFwkTag::UI_EXT, "BackgroundWindow called end");
}

void StsUIExtension::DestroyWindow(const sptr<AAFwk::SessionInfo> &sessionInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::UI_EXT, "DestroyWindow called start");
    if (sessionInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Invalid sessionInfo");
        return;
    }
    std::lock_guard<std::mutex> lock(uiWindowMutex_);
    auto componentId = sessionInfo->uiExtensionComponentId;
    if (uiWindowMap_.find(componentId) == uiWindowMap_.end()) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Wrong to find uiWindow");
        return;
    }
    // need to write sts contentSessions_
    // if (contentSessions_.find(componentId) != contentSessions_.end() && contentSessions_[componentId] != nullptr) {
    //     //HandleScope handleScope(jsRuntime_);
    //     if (screenMode_ == AAFwk::EMBEDDED_FULL_SCREEN_MODE) {
    //         screenMode_ = AAFwk::IDLE_SCREEN_MODE;
    //         //CallObjectMethod("onWindowStageDestroy");
    //     } else {
    //         //create UIEXtensionSessioni obj
    //         auto uiWindow = uiWindowMap_[componentId];
    //         auto env = stsRuntime_.GetAniEnv();
    //         ani_object sessionObj = StsUIExtensionContentSession::CreateStsUIExtensionContentSession(env,
    //             sessionInfo, uiWindow, GetContext(), abilityResultListeners_);
    //         CallObjectMethod(false, "onSessionDestroy", nullptr, sessionObj);
    //     }
    // }
    ani_object contenSessionObj = static_cast<ani_object>(contentSession_);
    if (contenSessionObj == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "contenSessionObj null ptr");
    } else {
        CallObjectMethod(false, "onSessionDestroy", nullptr, contenSessionObj);
    }
    TAG_LOGI(AAFwkTag::UI_EXT, "Befor window destory, UIExtcomponent id: %{public}" PRId64,
        sessionInfo->uiExtensionComponentId);
    auto uiWindow = uiWindowMap_[componentId];
    if (uiWindow) {
        uiWindow->Destroy();
    }
    uiWindowMap_.erase(componentId);
#ifdef SUPPORT_GRAPHICS
    auto context = GetContext();
    if (context != nullptr && context->GetWindow() == uiWindow) {
        context->SetWindow(nullptr);
        for (auto it : uiWindowMap_) {
            context->SetWindow(it.second);
            break;
        }
    }
#endif // SUPPORT_GRAPHICS
    foregroundWindows_.erase(componentId);
    contentSessions_.erase(componentId);
    if (abilityResultListeners_) {
        abilityResultListeners_->RemoveListener(componentId);
    }
    TAG_LOGI(AAFwkTag::UI_EXT, "DestroyWindow called end");
}

bool StsUIExtension::CallObjectMethod(bool withResult, const char *name, const char *signature, ...)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, std::string("CallObjectMethod:") + name);
    TAG_LOGI(AAFwkTag::UI_EXT, "CallObjectMethod call sts, name: %{public}s", name);
    if (stsObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "stsObj_ nullptr");
        return false;
    }

    auto env = stsRuntime_.GetAniEnv();
    ResetEnv(env);
    ani_status status = ANI_OK;
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(stsObj_->aniCls, name, signature, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Class_FindMethod status : %{public}d", status);
        return false;
    }
    env->ResetError();
    if (withResult) {
        ani_boolean res = 0;
        va_list args;
        va_start(args, signature);
        if ((status = env->Object_CallMethod_Boolean(stsObj_->aniObj, method, &res, args)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UI_EXT, "Object_CallMethod_Ref_V status : %{public}d", status);
            stsRuntime_.HandleUncaughtError();
        }
        va_end(args);
        return res;
    }
    va_list args;
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(stsObj_->aniObj, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Object_CallMethod_Void_V status : %{public}d", status);
        stsRuntime_.HandleUncaughtError();
    }
    va_end(args);
    TAG_LOGI(AAFwkTag::UI_EXT, "CallObjectMethod call sts, name: %{public}s end", name);
    return false;
}

void StsUIExtension::OnConfigurationUpdated(const AppExecFwk::Configuration& configuration)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    Extension::OnConfigurationUpdated(configuration);
    TAG_LOGI(AAFwkTag::UI_EXT, "OnConfigurationUpdated called start");

    // Notify extension context
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to get context");
        return;
    }

    auto configUtils = std::make_shared<ConfigurationUtils>();
    configUtils->UpdateGlobalConfig(configuration, context->GetConfiguration(), context->GetResourceManager());

    ConfigurationUpdated();
    TAG_LOGI(AAFwkTag::UI_EXT, "OnConfigurationUpdated called end");
}

void StsUIExtension::Dump(const std::vector<std::string> &params, std::vector<std::string> &info)
{
    Extension::Dump(params, info);
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
}

void StsUIExtension::OnAbilityResult(int requestCode, int resultCode, const Want &resultData)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "OnAbilityResult start");
    Extension::OnAbilityResult(requestCode, resultCode, resultData);
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGW(AAFwkTag::UI_EXT, "not attached to any runtime context");
        return;
    }
    context->OnAbilityResult(requestCode, resultCode, resultData);
    if (abilityResultListeners_ == nullptr) {
        TAG_LOGW(AAFwkTag::UI_EXT, "abilityResultListensers is nullptr");
        return;
    }
    abilityResultListeners_->OnAbilityResult(requestCode, resultCode, resultData);
    TAG_LOGI(AAFwkTag::UI_EXT, "OnAbilityResult end");
}

void StsUIExtension::ConfigurationUpdated()
{
    TAG_LOGI(AAFwkTag::UI_EXT, "ConfigurationUpdated begin");
    ani_env* env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGD(AAFwkTag::UI_EXT, "begin");
    }

    // Notify extension context
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to get context");
        return;
    }

    auto fullConfig = context->GetConfiguration();
    if (fullConfig == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Configuration is nullptr");
        return;
    }
    //wrap configuration and send onConfigurationUpdate
    //napi_value napiConfiguration = OHOS::AppExecFwk::WrapConfiguration(env, *fullConfig);
    //CallObjectMethod(false, "onConfigurationUpdate", &napiConfiguration, ARGC_ONE);
    TAG_LOGI(AAFwkTag::UI_EXT, "ConfigurationUpdated end");
}

#ifdef SUPPORT_GRAPHICS
void StsUIExtension::OnDisplayInfoChange(
    const sptr<IRemoteObject> &token, Rosen::DisplayId displayId, float density, Rosen::DisplayOrientation orientation)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "OnDisplayInfoChange: %{public}" PRIu64 "", displayId);
    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Context is invalid");
        return;
    }

    auto contextConfig = context->GetConfiguration();
    if (contextConfig == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Configuration is invalid");
        return;
    }

    TAG_LOGD(AAFwkTag::UI_EXT, "Config dump: %{public}s", contextConfig->GetName().c_str());
    auto configUtils = std::make_shared<ConfigurationUtils>();
    auto result =
        configUtils->UpdateDisplayConfig(contextConfig, context->GetResourceManager(), displayId, density, orientation);
    TAG_LOGD(AAFwkTag::UI_EXT, "Config dump after update: %{public}s", contextConfig->GetName().c_str());
    if (result) {
        auto stsUiExtension = std::static_pointer_cast<StsUIExtension>(shared_from_this());
        auto task = [stsUiExtension]() {
            if (stsUiExtension) {
                stsUiExtension->ConfigurationUpdated();
            }
        };
        if (handler_ != nullptr) {
            handler_->PostTask(task, "StsUIExtension:OnChange");
        }
    }
}

void StsUIExtension::RegisterDisplayInfoChangedListener()
{
    // register displayid change callback
    // auto jsUiExtension = std::static_pointer_cast<StsUIExtension>(shared_from_this());
    // jsUiExtensionAbilityDisplayListener_ = sptr<JsUIExtensionAbilityDisplayListener>::MakeSptr(jsUiExtension);
    // if (jsUiExtensionAbilityDisplayListener_ == nullptr) {
    //     TAG_LOGE(AAFwkTag::UI_EXT, "jsUiExtensionAbilityDisplayListener is nullptr");
    //     return;
    // }
    auto context = GetContext();
    if (context == nullptr || context->GetToken() == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Param is invalid");
        return;
    }
    TAG_LOGI(AAFwkTag::UI_EXT, "RegisterDisplayInfoChangedListener start");
    Rosen::WindowManager::GetInstance().RegisterDisplayInfoChangedListener(
        context->GetToken(), StsUIExtensionAbilityDisplayListener_);
}

void StsUIExtension::UnregisterDisplayInfoChangedListener()
{
    TAG_LOGI(AAFwkTag::UI_EXT, "UnregisterDisplayInfoChangedListener start");
    auto context = GetContext();
    if (context == nullptr || context->GetToken() == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Param is invalid");
        return;
    }
    Rosen::WindowManager::GetInstance().UnregisterDisplayInfoChangedListener(
        context->GetToken(), StsUIExtensionAbilityDisplayListener_);
}
#endif // SUPPORT_GRAPHICS

} // AbilityRuntime
} // OHOS


