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

#include "cj_ability_lifecycle_callback.h"
#include "cj_lambda.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
CjAbilityLifecycleCallback::CjAbilityLifecycleCallback()
{
}

int32_t CjAbilityLifecycleCallback::serialNumber_ = 0;

int32_t CjAbilityLifecycleCallback::Register(CArrI64 cFuncIds, bool isSync)
{
    TAG_LOGD(AAFwkTag::APPKIT, "enter");
    int32_t callbackId = serialNumber_;
    if (serialNumber_ < INT32_MAX) {
        serialNumber_++;
    } else {
        serialNumber_ = 0;
    }
    if (isSync) {
        return -1;
    } else {
        int64_t i = 0;
        // onAbilityCreate
        auto onAbilityCreatecallback = CJLambda::Create(reinterpret_cast<void(*)(int64_t)>(cFuncIds.head[i]));
        onAbilityCreatecallbacks_.emplace(callbackId, onAbilityCreatecallback);
        // onWindowStageCreate
        i++;
        auto onWindowStageCreatecallback = CJLambda::Create(reinterpret_cast<void(*)(int64_t, WindowStagePtr)>(cFuncIds.head[i]));
        onWindowStageCreatecallbacks_.emplace(callbackId, onWindowStageCreatecallback);
        // onWindowStageActive
        i++;
        auto onWindowStageActivecallback = CJLambda::Create(reinterpret_cast<void(*)(int64_t, WindowStagePtr)>(cFuncIds.head[i]));
        onWindowStageActivecallbacks_.emplace(callbackId, onWindowStageActivecallback);
        // onWindowStageInactive
        i++;
        auto onWindowStageInactivecallback = CJLambda::Create(reinterpret_cast<void(*)(int64_t, WindowStagePtr)>(cFuncIds.head[i]));
        onWindowStageInactivecallbacks_.emplace(callbackId, onWindowStageInactivecallback);
        // onWindowStageDestroy
        i++;
        auto onWindowStageDestroycallback = CJLambda::Create(reinterpret_cast<void(*)(int64_t, WindowStagePtr)>(cFuncIds.head[i]));
        onWindowStageDestroycallbacks_.emplace(callbackId, onWindowStageDestroycallback);
        // onAbilityDestroy
        i++;
        auto onAbilityDestroycallback = CJLambda::Create(reinterpret_cast<void(*)(int64_t)>(cFuncIds.head[i]));
        onAbilityDestroycallbacks_.emplace(callbackId, onAbilityDestroycallback);
        // onAbilityForeground
        i++;
        auto onAbilityForegroundcallback = CJLambda::Create(reinterpret_cast<void(*)(int64_t)>(cFuncIds.head[i]));
        onAbilityForegroundcallbacks_.emplace(callbackId, onAbilityForegroundcallback);
        // onAbilityBackground
        i++;
        auto onAbilityBackgroundcallback = CJLambda::Create(reinterpret_cast<void(*)(int64_t)>(cFuncIds.head[i]));
        onAbilityBackgroundcallbacks_.emplace(callbackId, onAbilityBackgroundcallback);
        // onAbilityContinue
        i++;
        auto onAbilityContinuecallback = CJLambda::Create(reinterpret_cast<void(*)(int64_t)>(cFuncIds.head[i]));
        onAbilityContinuecallbacks_.emplace(callbackId, onAbilityContinuecallback);
    }
    return callbackId;
}

bool CjAbilityLifecycleCallback::UnRegister(int32_t callbackId, bool isSync)
{
    TAG_LOGI(AAFwkTag::APPKIT, "callbackId : %{public}d", callbackId);
    if (isSync) {
        return false;
    }
    auto it = onAbilityBackgroundcallbacks_.find(callbackId);
    if (it == onAbilityBackgroundcallbacks_.end()) {
        TAG_LOGE(AAFwkTag::APPKIT, "callbackId: %{public}d is not in callbacks_", callbackId);
        return false;
    }
    onAbilityCreatecallbacks_.erase(callbackId);
    onWindowStageCreatecallbacks_.erase(callbackId);
    onWindowStageActivecallbacks_.erase(callbackId);
    onWindowStageInactivecallbacks_.erase(callbackId);
    onWindowStageDestroycallbacks_.erase(callbackId);
    onAbilityDestroycallbacks_.erase(callbackId);
    onAbilityForegroundcallbacks_.erase(callbackId);
    onAbilityBackgroundcallbacks_.erase(callbackId);
    return onAbilityContinuecallbacks_.erase(callbackId) == 1;
}

void CjAbilityLifecycleCallback::OnAbilityCreate(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnAbilityCreate");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is nullptr");
        return;
    }
    for (auto &callback : onAbilityCreatecallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability);
    }
}

void CjAbilityLifecycleCallback::OnWindowStageCreate(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnWindowStageCreate");
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability or windowStage is nullptr");
        return;
    }
    for (auto &callback : onWindowStageCreatecallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability, windowStage);
    }
}

void CjAbilityLifecycleCallback::OnWindowStageActive(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnWindowStageActive");
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability or windowStage is nullptr");
        return;
    }
    for (auto &callback : onWindowStageActivecallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability, windowStage);
    }
}

void CjAbilityLifecycleCallback::OnWindowStageInactive(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnWindowStageInactive");
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability or windowStage is nullptr");
        return;
    }
    for (auto &callback : onWindowStageInactivecallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability, windowStage);
    }
}

void CjAbilityLifecycleCallback::OnWindowStageDestroy(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnWindowStageDestroy");
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability or windowStage is nullptr");
        return;
    }
    for (auto &callback : onWindowStageDestroycallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability, windowStage);
    }
}

void CjAbilityLifecycleCallback::OnAbilityDestroy(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnAbilityDestroy");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is nullptr");
        return;
    }
    for (auto &callback : onAbilityDestroycallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability);
    }
}

void CjAbilityLifecycleCallback::OnAbilityForeground(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnAbilityForeground");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is nullptr");
        return;
    }
    for (auto &callback : onAbilityForegroundcallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability);
    }
}

void CjAbilityLifecycleCallback::OnAbilityBackground(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnAbilityBackground");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is nullptr");
        return;
    }
    for (auto &callback : onAbilityBackgroundcallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability);
    }
}

void CjAbilityLifecycleCallback::OnAbilityContinue(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnAbilityContinue");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is nullptr");
        return;
    }
    for (auto &callback : onAbilityContinuecallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability);
    }
}

}  // namespace AbilityRuntime
}  // namespace OHOS
