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

#include "insight_intent_delay_result_callback_mgr.h"
#include "event_report.h"
#include "hilog_tag_wrapper.h"
 
namespace OHOS {
namespace AbilityRuntime {
namespace {
    constexpr int ERROR_CODE_INVALID_ID = 16000003;
}
InsightIntentDelayResultCallbackMgr &InsightIntentDelayResultCallbackMgr::GetInstance()
{
    static InsightIntentDelayResultCallbackMgr instance;
    return instance;
}

void InsightIntentDelayResultCallbackMgr::AddDelayResultCallback(const uint64_t intentId,
    InsightIntentDelayResultCallbackWrapper delayResultCallback)
{
    TAG_LOGD(AAFwkTag::INTENT, "AddDelayResultCallback");
    std::lock_guard lock(delayResultCallbackLock_);
    delayResultCallbackMap_.emplace(intentId, delayResultCallback);
}

void InsightIntentDelayResultCallbackMgr::RemoveDelayResultCallback(const uint64_t intentId)
{
    TAG_LOGD(AAFwkTag::INTENT, "RemoveDelayResultCallback");
    std::lock_guard<std::mutex> lock(delayResultCallbackLock_);
    auto iter = delayResultCallbackMap_.find(intentId);
    if (iter != delayResultCallbackMap_.end()) {
        delayResultCallbackMap_.erase(intentId);
    }
}

int32_t InsightIntentDelayResultCallbackMgr::HandleExecuteDone(const uint64_t intentId,
    const InsightIntentExecuteResult& result, bool isDecorator)
{
    TAG_LOGD(AAFwkTag::INTENT, "HandleExecuteDone");
    std::function<int32_t(const InsightIntentExecuteResult&)> callback;
    {
        std::lock_guard lock(delayResultCallbackLock_);
        auto it = delayResultCallbackMap_.find(intentId);
        if (it != delayResultCallbackMap_.end() && it->second.isDecorator == isDecorator) {
            callback = std::move(it->second.callback);
            delayResultCallbackMap_.erase(it);
        }
    }
    if (callback) {
        auto ret = callback(result);
        return ret;
    }
    return ERROR_CODE_INVALID_ID;
}
} // namespace AbilityRuntime
} // namespace OHOS