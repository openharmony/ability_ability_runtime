/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cj_application_state_change_callback.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {

int32_t CjApplicationStateChangeCallback::serialNumber_ = 0;

CjApplicationStateChangeCallback::CjApplicationStateChangeCallback()
{
}

void CjApplicationStateChangeCallback::NotifyApplicationForeground()
{
    TAG_LOGD(AAFwkTag::APPKIT, "MethodName = onApplicationForeground");
    for (auto &callback : foregroundCallbacks_) {
        if (callback.second) {
            callback.second();
        }
    }
}

void CjApplicationStateChangeCallback::NotifyApplicationBackground()
{
    TAG_LOGD(AAFwkTag::APPKIT, "MethodName = onApplicationBackground");
    for (auto &callback : backgroundCallbacks_) {
        if (callback.second) {
            callback.second();
        }
    }
}

int32_t CjApplicationStateChangeCallback::Register(std::function<void(void)> foregroundCallback,
    std::function<void(void)> backgroundCallback)
{
    int32_t callbackId = serialNumber_;
    if (serialNumber_ < INT32_MAX) {
        serialNumber_++;
    } else {
        serialNumber_ = 0;
    }
    foregroundCallbacks_.emplace(callbackId, foregroundCallback);
    backgroundCallbacks_.emplace(callbackId, backgroundCallback);
    return callbackId;
}

bool CjApplicationStateChangeCallback::UnRegister(int32_t callbackId)
{
    if (callbackId < 0) {
        TAG_LOGI(AAFwkTag::APPKIT, "delete all callback");
        foregroundCallbacks_.clear();
        backgroundCallbacks_.clear();
        return true;
    }
    auto it = foregroundCallbacks_.find(callbackId);
    if (it == foregroundCallbacks_.end()) {
        TAG_LOGE(AAFwkTag::APPKIT, "callbackId: %{public}d is not in callbacks_", callbackId);
        return false;
    }
    TAG_LOGD(AAFwkTag::APPKIT, "callbacks_.callbackId : %{public}d", it->first);
    return foregroundCallbacks_.erase(callbackId) == 1 && backgroundCallbacks_.erase(callbackId) == 1;
}

bool CjApplicationStateChangeCallback::IsEmpty() const
{
    return foregroundCallbacks_.empty() && backgroundCallbacks_.empty();
}
} // namespace AbilityRuntime
} // namespace OHOS