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

#include "cj_insight_intent_executor_impl.h"

#include <want_params.h>

#include "ability_transaction_callback_info.h"
#include "cj_insight_intent_executor_impl_object.h"
#include "event_report.h"
#include "hilog_tag_wrapper.h"
#include "insight_intent_constant.h"
#include "insight_intent_execute_result.h"
#include "want_params_wrapper.h"

#undef STATE_PATTERN_NAIVE_H
#define STATE_PATTERN_NAIVE_STATE state_
#include "state_pattern_naive.h"

#define TMP_NAPI_ANONYMOUS_FUNC "_"

namespace OHOS::AbilityRuntime {

std::shared_ptr<CJInsightIntentExecutorImpl> CJInsightIntentExecutorImpl::Create()
{
    return std::make_shared<CJInsightIntentExecutorImpl>();
}

using State = CJInsightIntentExecutorImpl::State;

CJInsightIntentExecutorImpl::CJInsightIntentExecutorImpl() {}

CJInsightIntentExecutorImpl::~CJInsightIntentExecutorImpl()
{
    state_ = State::DESTROYED;
    TAG_LOGD(AAFwkTag::INTENT, "called");
    cjObj_.Destroy();
}

bool CJInsightIntentExecutorImpl::Init(const CJInsightIntentExecutorInfo& insightIntentInfo)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    STATE_PATTERN_NAIVE_ACCEPT(State::CREATED, false);
    state_ = State::INITIALIZED;
    CJInsightIntentExecutor::Init(insightIntentInfo);
    auto pos = insightIntentInfo.srcEntry.rfind('.');
    if (pos == std::string::npos) {
        TAG_LOGE(AAFwkTag::INTENT, "Init failed");
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }
    auto executorName = insightIntentInfo.srcEntry.substr(pos + 1);

    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null Context");
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }

    int32_t ret = cjObj_.Init(executorName, this);
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::INTENT, "null cjObj_");
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }

    if (contextObj_ == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null contextObj_");
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }
    return true;
}

bool CJInsightIntentExecutorImpl::ExecuteIntentCheckError()
{
    ReplyFailedInner();
    STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
}

bool CJInsightIntentExecutorImpl::HandleExecuteIntent(InsightIntentExecuteMode mode, const std::string& name,
    const AAFwk::WantParams& param, CJPageLoader pageLoader,
    std::unique_ptr<InsightIntentExecutorAsyncCallback> callback)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
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
            if (!CJInsightIntentExecutorImpl::CheckParametersUIAbilityForeground(pageLoader.windowPageLoader)) {
                TAG_LOGE(AAFwkTag::INTENT, "CheckParametersUIAbilityForeground error");
                return ExecuteIntentCheckError();
            }
            successful = ExecuteInsightIntentUIAbilityForeground(name, param, pageLoader.windowPageLoader);
            break;
        case InsightIntentExecuteMode::UIABILITY_BACKGROUND:
            if (!CJInsightIntentExecutorImpl::CheckParametersUIAbilityBackground()) {
                TAG_LOGE(AAFwkTag::INTENT, "CheckParametersUIAbilityBackground error");
                return ExecuteIntentCheckError();
            }
            successful = ExecuteInsightIntentUIAbilityBackground(name, param);
            break;
        case InsightIntentExecuteMode::UIEXTENSION_ABILITY:
            if (!CJInsightIntentExecutorImpl::CheckParametersUIExtension(pageLoader.sessionPageLoader)) {
                TAG_LOGE(AAFwkTag::INTENT, "CheckParametersUIExtension error");
                return ExecuteIntentCheckError();
            }
            successful = ExecuteInsightIntentUIExtension(name, param, pageLoader.sessionPageLoader);
            break;
        default:
            TAG_LOGE(AAFwkTag::INTENT, "InsightIntentExecuteMode not supported yet");
            return ExecuteIntentCheckError();
    }
    return successful;
}

std::shared_ptr<AppExecFwk::InsightIntentExecuteResult> CJInsightIntentExecutorImpl::GetResultFromCj(
    CJExecuteResult resultCj)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    auto resultCpp = std::make_shared<AppExecFwk::InsightIntentExecuteResult>();
    if (resultCpp == nullptr) {
        return nullptr;
    }
    resultCpp->code = resultCj.code;
    auto resultString = std::string(resultCj.result);
    AAFwk::WantParams wantParams = OHOS::AAFwk::WantParamWrapper::ParseWantParamsWithBrackets(resultString);
    resultCpp->result = std::make_shared<AAFwk::WantParams>(wantParams);
    if (resultCj.uris.head != nullptr && resultCj.uris.size > 0) {
        std::vector<std::string> uris;
        for (int64_t i = 0; i < resultCj.uris.size; i++) {
            uris.push_back(std::string(resultCj.uris.head[i]));
        }
        resultCpp->uris = uris;
    }
    resultCpp->flags = resultCj.flags;
    return resultCpp;
}

void CJInsightIntentExecutorImpl::ReplyFailed(
    std::unique_ptr<InsightIntentExecutorAsyncCallback> callback, InsightIntentInnerErr innerErr)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    if (callback == nullptr) {
        return;
    }
    AppExecFwk::InsightIntentExecuteResult errorResult {};
    errorResult.innerErr = innerErr;
    AAFwk::EventInfo eventInfo;
    eventInfo.errCode = innerErr;
    eventInfo.errReason = "ReplyFailed";
    AAFwk::EventReport::SendExecuteIntentEvent(
        AAFwk::EventName::EXECUTE_INSIGHT_INTENT_ERROR, HISYSEVENT_FAULT, eventInfo);
    callback->Call(errorResult);
}

void CJInsightIntentExecutorImpl::ReplySucceeded(
    std::unique_ptr<InsightIntentExecutorAsyncCallback> callback,
    std::shared_ptr<AppExecFwk::InsightIntentExecuteResult> resultCpp)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    if (callback == nullptr) {
        return;
    }
    if (resultCpp == nullptr) {
        ReplyFailed(std::move(callback));
        return;
    }
    resultCpp->innerErr = InsightIntentInnerErr::INSIGHT_INTENT_ERR_OK;
    callback->Call(*resultCpp);
}

void CJInsightIntentExecutorImpl::ReplyFailedInner(InsightIntentInnerErr innerErr)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    state_ = CJInsightIntentExecutorImpl::State::INVALID;
    CJInsightIntentExecutorImpl::ReplyFailed(std::move(callback_), innerErr);
}

void CJInsightIntentExecutorImpl::ReplySucceededInner(std::shared_ptr<AppExecFwk::InsightIntentExecuteResult> resultCpp)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    state_ = CJInsightIntentExecutorImpl::State::EXECUTATION_DONE;
    CJInsightIntentExecutorImpl::ReplySucceeded(std::move(callback_), resultCpp);
}

bool CJInsightIntentExecutorImpl::HandleResultReturnedFromCjFunc(CJExecuteResult resultJs)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    auto resultCpp = CJInsightIntentExecutorImpl::GetResultFromCj(resultJs);
    if (resultCpp == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null resultCpp");
        ReplyFailedInner();
        STATE_PATTERN_NAIVE_STATE_SET_AND_RETURN(State::INVALID, false);
    }
    TAG_LOGD(AAFwkTag::INTENT, "Call succeed");
    ReplySucceededInner(resultCpp);
    cjObj_.FreeCJExecuteResult(resultJs);
    return true;
}

bool CJInsightIntentExecutorImpl::CheckParametersUIAbilityForeground(Rosen::CJWindowStageImpl* windowStage)
{
    return windowStage != nullptr;
}

bool CJInsightIntentExecutorImpl::ExecuteInsightIntentUIAbilityForeground(
    const std::string& name, const AAFwk::WantParams& param, Rosen::CJWindowStageImpl* cjWindowStage)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    auto result = cjObj_.OnExecuteInUIAbilityForegroundMode(name, param, cjWindowStage);
    if (result.code == CALL_ERROR) {
        return false;
    }
    return HandleResultReturnedFromCjFunc(result);
}

bool CJInsightIntentExecutorImpl::CheckParametersUIAbilityBackground()
{
    return true;
}

bool CJInsightIntentExecutorImpl::ExecuteInsightIntentUIAbilityBackground(
    const std::string& name, const AAFwk::WantParams& param)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    auto result = cjObj_.OnExecuteInUIAbilityBackgroundMode(name, param);
    if (result.code == CALL_ERROR) {
        return false;
    }
    return HandleResultReturnedFromCjFunc(result);
}

bool CJInsightIntentExecutorImpl::CheckParametersUIExtension(int64_t sessionId)
{
    return sessionId > 0;
}

bool CJInsightIntentExecutorImpl::ExecuteInsightIntentUIExtension(
    const std::string& name, const AAFwk::WantParams& param, int64_t sessionId)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    auto result = cjObj_.OnExecuteInsightIntentUIExtension(name, param, sessionId);
    if (result.code == CALL_ERROR) {
        return false;
    }
    return HandleResultReturnedFromCjFunc(result);
}

} // namespace OHOS::AbilityRuntime
