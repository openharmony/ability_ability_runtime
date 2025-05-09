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

#include "ets_insight_intent_executor.h"
#include "hitrace_meter.h"
#include "ability_transaction_callback_info.h"
#include "hilog_tag_wrapper.h"
#include "insight_intent_constant.h"
#include "insight_intent_execute_result.h"
#include "sts_runtime.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ani_common_execute_result.h"

#undef STATE_PATTERN_NAIVE_H
#define STATE_PATTERN_NAIVE_STATE state_
#include "state_pattern_naive.h"

namespace OHOS::AbilityRuntime {

std::shared_ptr<EtsInsightIntentExecutor> EtsInsightIntentExecutor::Create(STSRuntime& runtime)
{
    std::shared_ptr<EtsInsightIntentExecutor> ptr = std::make_shared<EtsInsightIntentExecutor>(runtime);
    return ptr;
}

using State = EtsInsightIntentExecutor::State;

EtsInsightIntentExecutor::EtsInsightIntentExecutor(STSRuntime& runtime) : runtime_(runtime)
{ }

EtsInsightIntentExecutor::~EtsInsightIntentExecutor()
{
    state_ = State::DESTROYED;
    TAG_LOGD(AAFwkTag::INTENT, "~EtsInsightIntentExecutor called");

    if (contextObj_ && contextObj_->aniRef) {
        ani_env *env = runtime_.GetAniEnv();
        if (env != nullptr) {
            env->GlobalReference_Delete(contextObj_->aniRef);
        }
    }
    if (etsObj_ && etsObj_->aniRef) {
        ani_env *env = runtime_.GetAniEnv();
        if (env != nullptr) {
            env->GlobalReference_Delete(etsObj_->aniRef);
        }
    }
}

bool EtsInsightIntentExecutor::Init(const InsightIntentExecutorInfo& insightIntentInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentExecutor::Init called");
    STATE_PATTERN_NAIVE_ACCEPT(State::CREATED, false);
    state_ = State::INITIALIZED;
    InsightIntentExecutor::Init(insightIntentInfo);

    auto env = runtime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }

    etsObj_ = EtsInsightIntentExecutor::LoadEtsCode(insightIntentInfo, runtime_);
    if (etsObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null etsObj_");
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }

    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null Context");
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }
    contextCpp_ = std::make_shared<EtsInsightIntentContext>(context);
    contextObj_ = CreateEtsInsightIntentContext(env, contextCpp_);
    if (contextObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null contextObj_");
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }

    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetFieldByName_Ref(etsObj_->aniObj, "context", contextObj_->aniRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }

    ani_class executorClass = nullptr;
    if ((status = env->FindClass("L@ohos/app/ability/InsightIntentExecutor/InsightIntentExecutor;",
        &executorClass)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "find InsightIntentExecutor failed status: %{public}d", status);
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }
    etsObj_->aniCls = executorClass;

    std::array functions = {
        ani_native_function {"nativeOnExecuteResult", nullptr, reinterpret_cast<void *>(OnExecuteResult)},
    };
    if ((status = env->Class_BindNativeMethods(etsObj_->aniCls, functions.data(), functions.size())) != ANI_OK) {
        if (status != ANI_ALREADY_BINDED) {
            TAG_LOGE(AAFwkTag::INTENT, "Class_BindNativeMethods failed status: %{public}d", status);
            STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
        }
    }
    if ((status = env->Object_SetFieldByName_Long(etsObj_->aniObj, "nativeExecutor",
        reinterpret_cast<ani_long>(this))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }

    return true;
}

bool EtsInsightIntentExecutor::ExecuteIntentCheckError()
{
    ReplyFailedInner();
    STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
}

bool EtsInsightIntentExecutor::HandleExecuteEtsIntent(
    InsightIntentExecuteMode mode,
    const std::string& name,
    const AAFwk::WantParams& param,
    const std::shared_ptr<STSNativeReference>& pageLoader,
    std::unique_ptr<InsightIntentExecutorAsyncCallback> callback,
    bool& isAsync)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentExecutor::HandleExecuteEtsIntent called");
    STATE_PATTERN_NAIVE_ACCEPT(State::INITIALIZED, false);
    state_ = State::EXECUTING;

    if (callback == nullptr || callback->IsEmpty()) {
        TAG_LOGE(AAFwkTag::INTENT, "null callback");
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }
    callback_ = std::move(callback);
    bool successful = false;
    switch (mode) {
        case InsightIntentExecuteMode::UIABILITY_FOREGROUND:
            if (!EtsInsightIntentExecutor::CheckParametersUIAbilityForeground(pageLoader)) {
                TAG_LOGE(AAFwkTag::INTENT, "CheckParametersUIAbilityForeground error");
                return ExecuteIntentCheckError();
            }
            successful = ExecuteInsightIntentUIAbilityForeground(name, param, pageLoader);
            break;
        case InsightIntentExecuteMode::UIABILITY_BACKGROUND:
            if (!EtsInsightIntentExecutor::CheckParametersUIAbilityBackground()) {
                TAG_LOGE(AAFwkTag::INTENT, "CheckParametersUIAbilityBackground error");
                return ExecuteIntentCheckError();
            }
            successful = ExecuteInsightIntentUIAbilityBackground(name, param);
            break;
        case InsightIntentExecuteMode::UIEXTENSION_ABILITY:
            if (!EtsInsightIntentExecutor::CheckParametersUIExtension(pageLoader)) {
                TAG_LOGE(AAFwkTag::INTENT, "CheckParametersUIExtension error");
                return ExecuteIntentCheckError();
            }
            successful = ExecuteInsightIntentUIExtension(name, param, pageLoader);
            break;
        case InsightIntentExecuteMode::SERVICE_EXTENSION_ABILITY:
            if (!EtsInsightIntentExecutor::CheckParametersServiceExtension()) {
                TAG_LOGE(AAFwkTag::INTENT, "CheckParametersServiceExtension error");
                return ExecuteIntentCheckError();
            }
            successful = ExecuteInsightIntentServiceExtension(name, param);
            break;
        default:
            TAG_LOGE(AAFwkTag::INTENT, "InsightIntentExecuteMode not supported yet");
            return ExecuteIntentCheckError();
    }
    isAsync = isAsync_;
    if (!successful) {
        ReplyFailedInner();
    }
    return successful;
}

std::unique_ptr<STSNativeReference> EtsInsightIntentExecutor::LoadEtsCode(
    const InsightIntentExecutorInfo& info,
    STSRuntime& runtime)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentExecutor::LoadEtsCode called");
    auto executeParam = info.executeParam;
    if (executeParam == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null executeParam");
        return std::make_unique<STSNativeReference>();
    }

    std::string moduleName(executeParam->moduleName_);
    std::string srcPath(executeParam->moduleName_ + "/" + info.srcEntry);

    auto pos = srcPath.rfind('.');
    if (pos == std::string::npos) {
        return std::make_unique<STSNativeReference>();
    }
    srcPath.erase(pos);
    srcPath.append(".abc");

    std::unique_ptr<STSNativeReference> etsObj =
        runtime.LoadModule(moduleName, srcPath, info.hapPath, info.esmodule, false, info.srcEntry);
    return etsObj;
}

void EtsInsightIntentExecutor::ReplyFailed(InsightIntentExecutorAsyncCallback* callback,
    InsightIntentInnerErr innerErr)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentExecutor::ReplyFailed called");
    if (callback == nullptr) {
        return;
    }
    AppExecFwk::InsightIntentExecuteResult errorResult{};
    errorResult.innerErr = innerErr;
    callback->Call(errorResult);
    delete callback;
}

void EtsInsightIntentExecutor::ReplySucceeded(InsightIntentExecutorAsyncCallback* callback,
    std::shared_ptr<AppExecFwk::InsightIntentExecuteResult> resultCpp)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentExecutor::ReplySucceeded called");
    if (callback == nullptr) {
        return;
    }
    if (resultCpp == nullptr) {
        ReplyFailed(callback);
        return;
    }
    resultCpp->innerErr = InsightIntentInnerErr::INSIGHT_INTENT_ERR_OK;
    callback->Call(*resultCpp);
    delete callback;
}

void EtsInsightIntentExecutor::ReplyFailedInner(InsightIntentInnerErr innerErr)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentExecutor::ReplyFailedInner called");
    state_ = EtsInsightIntentExecutor::State::INVALID;
    auto* callback = callback_.release();
    EtsInsightIntentExecutor::ReplyFailed(callback, innerErr);
}

void EtsInsightIntentExecutor::ReplySucceededInner(std::shared_ptr<AppExecFwk::InsightIntentExecuteResult> resultCpp)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentExecutor::ReplySucceededInner called");
    state_ = EtsInsightIntentExecutor::State::EXECUTATION_DONE;
    auto* callback = callback_.release();
    EtsInsightIntentExecutor::ReplySucceeded(callback, resultCpp);
}

bool EtsInsightIntentExecutor::HandleResultReturnedFromEtsFunc(ani_env *env, ani_ref result, bool isAsync)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentExecutor::HandleResultReturnedFromEtsFunc called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }

    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null intent result");
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }

    AppExecFwk::InsightIntentExecuteResult resultInner;
    ani_object resultObject = static_cast<ani_object>(result);
    if (!OHOS::AbilityRuntime::UnwrapExecuteResult(env, resultObject, resultInner)) {
        TAG_LOGE(AAFwkTag::INTENT, "UnwrapExecuteResult failed");
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }
    std::shared_ptr<AppExecFwk::InsightIntentExecuteResult> resultCpp =
        std::make_shared<AppExecFwk::InsightIntentExecuteResult>(resultInner);
    if (isAsync) {
        TAG_LOGI(AAFwkTag::INTENT, "Is promise");
        auto* callback = callback_.release();
        EtsInsightIntentExecutor::ReplySucceeded(callback, resultCpp);
    } else {
        TAG_LOGI(AAFwkTag::INTENT, "Not promise");
        ReplySucceededInner(resultCpp);
    }
    return true;
}

bool EtsInsightIntentExecutor::CheckParametersUIAbilityForeground(
    const std::shared_ptr<STSNativeReference>& windowStage)
{
    return windowStage != nullptr;
}

ani_ref EtsInsightIntentExecutor::CallObjectMethod(bool withResult, const char* name, const char* signature, ...)
{
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    auto env = runtime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(etsObj_->aniCls, name, signature, &method)) != ANI_OK) {
        return nullptr;
    }
    if (method == nullptr) {
        return nullptr;
    }
    ani_ref result = nullptr;
    va_list args;
    if (withResult) {
        va_start(args, signature);
        if ((status = env->Object_CallMethod_Ref_V(etsObj_->aniObj, method, &result, args)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
        }
        va_end(args);
        return result;
    }
    va_start(args, signature);
    if ((status = env->Object_CallMethod_Void_V(etsObj_->aniObj, method, args)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "status: %{public}d", status);
    }
    va_end(args);
    return nullptr;
}

bool EtsInsightIntentExecutor::ExecuteInsightIntentUIAbilityForeground(
    const std::string& name,
    const AAFwk::WantParams& param,
    const std::shared_ptr<STSNativeReference>& windowStage)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentExecutor::ExecuteInsightIntentUIAbilityForeground called");
    auto env = runtime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return false;
    }
    
    ani_string aniName = AppExecFwk::GetAniString(env, name);
    ani_ref aniWantParams = OHOS::AppExecFwk::WrapWantParams(env, param);
    ani_ref result = CallObjectMethod(true, "callOnExecuteInUIAbilityForegroundMode", nullptr, aniName,
        aniWantParams, windowStage->aniObj);
    if (result == nullptr) {
        return false;
    }

    ani_boolean isAsync  = false;
    if (env->Object_GetFieldByName_Boolean(etsObj_->aniObj, "isOnExecuteInUIAbilityForegroundModeAsync",
        &isAsync) != ANI_OK) {
        return false;
    }

    isAsync_ = static_cast<bool>(isAsync);
    if (isAsync_) {
        return true;
    } else {
        return HandleResultReturnedFromEtsFunc(env, result, isAsync_);
    }
}

bool EtsInsightIntentExecutor::CheckParametersUIAbilityBackground()
{
    return true;
}

bool EtsInsightIntentExecutor::ExecuteInsightIntentUIAbilityBackground(
    const std::string& name,
    const AAFwk::WantParams& param)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentExecutor::ExecuteInsightIntentUIAbilityBackground called");
    auto env = runtime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return false;
    }
    
    ani_string aniName = AppExecFwk::GetAniString(env, name);
    ani_ref aniWantParams = OHOS::AppExecFwk::WrapWantParams(env, param);
    ani_ref result = CallObjectMethod(true, "callOnExecuteInUIAbilityBackgroundMode", nullptr, aniName,
        aniWantParams);
    if (result == nullptr) {
        return false;
    }

    ani_boolean isAsync  = false;
    if (env->Object_GetFieldByName_Boolean(etsObj_->aniObj, "isOnExecuteInUIAbilityBackgroundModeAsync",
        &isAsync) != ANI_OK) {
        return false;
    }

    isAsync_ = static_cast<bool>(isAsync);
    if (isAsync_) {
        return true;
    } else {
        return HandleResultReturnedFromEtsFunc(env, result, isAsync_);
    }
}

bool EtsInsightIntentExecutor::CheckParametersUIExtension(
    const std::shared_ptr<STSNativeReference>& UIExtensionContentSession)
{
    return UIExtensionContentSession != nullptr;
}

bool EtsInsightIntentExecutor::ExecuteInsightIntentUIExtension(
    const std::string& name,
    const AAFwk::WantParams& param,
    const std::shared_ptr<STSNativeReference>& UIExtensionContentSession)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentExecutor::ExecuteInsightIntentUIExtension called");
    auto env = runtime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return false;
    }
    
    ani_string aniName = AppExecFwk::GetAniString(env, name);
    ani_ref aniWantParams = OHOS::AppExecFwk::WrapWantParams(env, param);
    ani_ref result = CallObjectMethod(true, "callOnExecuteInUIExtensionAbility", nullptr, aniName,
        aniWantParams, UIExtensionContentSession->aniObj);
    if (result == nullptr) {
        return false;
    }

    ani_boolean isAsync  = false;
    if (env->Object_GetFieldByName_Boolean(etsObj_->aniObj, "isOnExecuteInUIExtensionAbilityAsync",
        &isAsync) != ANI_OK) {
        return false;
    }

    isAsync_ = static_cast<bool>(isAsync);
    if (isAsync_) {
        return true;
    } else {
        return HandleResultReturnedFromEtsFunc(env, result, isAsync_);
    }
}

bool EtsInsightIntentExecutor::CheckParametersServiceExtension()
{
    return true;
}

bool EtsInsightIntentExecutor::ExecuteInsightIntentServiceExtension(
    const std::string& name,
    const AAFwk::WantParams& param)
{
    TAG_LOGD(AAFwkTag::INTENT, "EtsInsightIntentExecutor::ExecuteInsightIntentServiceExtension called");
    auto env = runtime_.GetAniEnv();
    if (!env) {
        TAG_LOGE(AAFwkTag::INTENT, "null env");
        return false;
    }
    
    ani_string aniName = AppExecFwk::GetAniString(env, name);
    ani_ref aniWantParams = OHOS::AppExecFwk::WrapWantParams(env, param);
    ani_ref result = CallObjectMethod(true, "callOnExecuteInServiceExtensionAbility", nullptr, aniName,
        aniWantParams);
    if (result == nullptr) {
        return false;
    }

    ani_boolean isAsync  = false;
    if (env->Object_GetFieldByName_Boolean(etsObj_->aniObj, "isOnExecuteInServiceExtensionAbilityAsync",
        &isAsync) != ANI_OK) {
        return false;
    }
    isAsync_ = static_cast<bool>(isAsync);
    if (isAsync_) {
        return true;
    } else {
        return HandleResultReturnedFromEtsFunc(env, result, isAsync_);
    }
}

void EtsInsightIntentExecutor::OnExecuteResult(ani_env *env, [[maybe_unused]]ani_object aniObj, ani_object result)
{
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null result");
        return;
    }

    ani_long nativeExecutor = 0;
    if (env->Object_GetFieldByName_Long(aniObj, "nativeExecutor", &nativeExecutor) != ANI_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "nativeExecutor failed");
        return;
    }
    ((EtsInsightIntentExecutor*)nativeExecutor)->HandleResultReturnedFromEtsFunc(env, result, true);
}
} // namespace OHOS::AbilityRuntime
