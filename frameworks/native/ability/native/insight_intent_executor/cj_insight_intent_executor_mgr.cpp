/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "cj_insight_intent_executor_mgr.h"

#include "ability_business_error.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
CJInsightIntentExecutorMgr::CJInsightIntentExecutorMgr()
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
}

CJInsightIntentExecutorMgr::~CJInsightIntentExecutorMgr()
{
    TAG_LOGI(AAFwkTag::INTENT, "called");
}

bool CJInsightIntentExecutorMgr::ExecuteInsightIntent(Runtime& runtime, const CJInsightIntentExecutorInfo& executeInfo,
    std::unique_ptr<InsightIntentExecutorAsyncCallback> callback)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    auto executeParam = executeInfo.executeParam;
    if (callback == nullptr) {
        return false;
    }
    if (executeParam == nullptr || executeParam->insightIntentParam_ == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null executeParam or insightIntentParam_");
        TriggerCallbackInner(std::move(callback), static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_PARAM));
        return false;
    }

    auto asyncCallback = [weak = weak_from_this(), intentId = executeParam->insightIntentId_](
                             InsightIntentExecuteResult result) {
        // erase map when called
        TAG_LOGD(AAFwkTag::INTENT, "called");
        auto executorMgr = weak.lock();
        if (executorMgr == nullptr) {
            TAG_LOGE(AAFwkTag::INTENT, "null executorMgr");
            return;
        }
        executorMgr->RemoveInsightIntentExecutor(intentId);
    };
    callback->Push(asyncCallback);

    // Create insight intent executor
    auto intentExecutor = CJInsightIntentExecutor::Create(runtime);
    if (intentExecutor == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null intentExecutor");
        TriggerCallbackInner(std::move(callback), static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_PARAM));
        return false;
    }

    if (!intentExecutor->Init(executeInfo)) {
        TAG_LOGE(AAFwkTag::INTENT, "Init intent executor failed");
        TriggerCallbackInner(std::move(callback), static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_PARAM));
        return false;
    }
    AddInsightIntentExecutor(executeParam->insightIntentId_, intentExecutor);

    auto ret = intentExecutor->HandleExecuteIntent(static_cast<InsightIntentExecuteMode>(executeParam->executeMode_),
        executeParam->insightIntentName_, *executeParam->insightIntentParam_, executeInfo.pageLoader,
        std::move(callback));
    if (!ret) {
        TAG_LOGE(AAFwkTag::INTENT, "Handle Execute intent failed");
        // callback has removed, if execute insight intent failed, call in sub function.
        return false;
    }

    return true;
}

void CJInsightIntentExecutorMgr::AddInsightIntentExecutor(
    uint64_t intentId, const std::shared_ptr<CJInsightIntentExecutor>& executor)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    std::lock_guard<std::mutex> lock(mutex_);
    insightIntentExecutors_[intentId] = executor;
}

void CJInsightIntentExecutorMgr::RemoveInsightIntentExecutor(uint64_t intentId)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    std::lock_guard<std::mutex> lock(mutex_);
    insightIntentExecutors_.erase(intentId);
}

void CJInsightIntentExecutorMgr::TriggerCallbackInner(
    std::unique_ptr<InsightIntentExecutorAsyncCallback> callback, int32_t errCode)
{
    TAG_LOGD(AAFwkTag::INTENT, "called");
    AppExecFwk::InsightIntentExecuteResult result;
    result.innerErr = errCode;
    if (callback) {
        callback->Call(result);
    }
    callback.reset();
}

extern "C" __attribute__((visibility("default"))) void OHOS_CallTriggerCallbackInner(void* callbackPtr, int32_t errCode)
{
    if (callbackPtr == nullptr) {
        return;
    }
    auto& callback = *reinterpret_cast<std::unique_ptr<InsightIntentExecutorAsyncCallback>*>(callbackPtr);
    CJInsightIntentExecutorMgr::TriggerCallbackInner(std::move(callback), errCode);
}

extern "C" __attribute__((visibility("default"))) bool OHOS_CallExecuteInsightIntent(
    void* runtimePtr, void* executeInfoPtr, void* callbackPtr)
{
    if (runtimePtr == nullptr || executeInfoPtr == nullptr || callbackPtr == nullptr) {
        return false;
    }
    auto& runtime = *reinterpret_cast<Runtime*>(runtimePtr);
    auto& executeInfo = *reinterpret_cast<CJInsightIntentExecutorInfo*>(executeInfoPtr);
    auto& callback = *reinterpret_cast<std::unique_ptr<InsightIntentExecutorAsyncCallback>*>(callbackPtr);
    return DelayedSingleton<CJInsightIntentExecutorMgr>::GetInstance()->ExecuteInsightIntent(
        runtime, executeInfo, std::move(callback));
}

} // namespace AbilityRuntime
} // namespace OHOS
