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

#include "caller_callback.h"

#include "hilog_tag_wrapper.h"

namespace OHOS::AbilityRuntime {
namespace {
constexpr int32_t CALLER_TIME_OUT = 10; // 10s
} // namespace

void CallUtil::GenerateCallerCallBack(std::shared_ptr<StartAbilityByCallData> calls,
    std::shared_ptr<CallerCallBack> callerCallBack)
{
    if (calls == nullptr || callerCallBack == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null calls or null callerCallBack");
        return;
    }
    auto callBackDone = [weakData = std::weak_ptr<StartAbilityByCallData>(calls)] (const sptr<IRemoteObject> &obj) {
        TAG_LOGI(AAFwkTag::CONTEXT, "callBackDone called start");
        auto calldata = weakData.lock();
        if (calldata == nullptr) {
            TAG_LOGW(AAFwkTag::CONTEXT, "calldata released");
            return;
        }
        std::lock_guard lock(calldata->mutexlock);
        calldata->remoteCallee = obj;
        calldata->condition.notify_all();
    };

    callerCallBack->SetCallBack(callBackDone);
}

void CallUtil::SetOnReleaseOfCallerCallBack(std::shared_ptr<CallerCallBack> callerCallBack)
{
    if (callerCallBack == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "callerCallBack");
        return;
    }
    auto releaseListen = [](const std::string &str) {
        TAG_LOGD(AAFwkTag::CONTEXT, "called, %{public}s", str.c_str());
    };

    callerCallBack->SetOnRelease(releaseListen);
}

void CallUtil::WaitForCalleeObj(std::shared_ptr<StartAbilityByCallData> callData)
{
    if (callData == nullptr) {
        return;
    }
    if (callData->remoteCallee == nullptr) {
        std::unique_lock lock(callData->mutexlock);
        if (callData->remoteCallee != nullptr) {
            return;
        }
        if (callData->condition.wait_for(lock, std::chrono::seconds(CALLER_TIME_OUT)) == std::cv_status::timeout) {
            callData->err = -1;
            TAG_LOGE(AAFwkTag::CONTEXT, "callExecute waiting callee timeout");
        }
    }
}
} // namespace OHOS::AbilityRuntime
