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
        if (!callback.second) {
            callback.second();
        }
    }
}

void CjApplicationStateChangeCallback::NotifyApplicationBackground()
{
    TAG_LOGD(AAFwkTag::APPKIT, "MethodName = onApplicationBackground");
    for (auto &callback : backgroundCallbacks_) {
        if (!callback.second) {
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

// bool CjApplicationStateChangeCallback::UnRegister(napi_value jsCallback)
// {
//     if (jsCallback == nullptr) {
//         TAG_LOGI(AAFwkTag::APPKIT, "jsCallback is nullptr, delete all callback");
//         callbacks_.clear();
//         return true;
//     }

//     for (auto &callback : callbacks_) {
//         if (!callback) {
//             TAG_LOGE(AAFwkTag::APPKIT, "Invalid jsCallback");
//             continue;
//         }

//         napi_value value = callback->GetNapiValue();
//         if (value == nullptr) {
//             TAG_LOGE(AAFwkTag::APPKIT, "Failed to get object");
//             continue;
//         }

//         bool isEqual = false;
//         napi_strict_equals(env_, value, jsCallback, &isEqual);
//         if (isEqual) {
//             return callbacks_.erase(callback) == 1;
//         }
//     }
//     return false;
// }

bool CjApplicationStateChangeCallback::IsEmpty() const
{
    return foregroundCallbacks_.empty() && backgroundCallbacks_.empty();
}
} // namespace AbilityRuntime
} // namespace OHOS