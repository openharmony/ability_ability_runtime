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

#include "cj_ability_lifecycle_callback_impl.h"

#include "cj_lambda.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
int32_t CjAbilityLifecycleCallbackImpl::serialNumber_ = 0;

void EmplaceAbilityFunc(int32_t callbackId, int64_t cFuncId, std::map<int32_t, std::function<void(int64_t)>> &cFuncMap)
{
    auto callback = CJLambda::Create(reinterpret_cast<void (*)(int64_t)>(cFuncId));
    cFuncMap.emplace(callbackId, callback);
}

void EmplaceAbilityWindowStageFunc(int32_t callbackId, int64_t cFuncId,
                                   std::map<int32_t, std::function<void(int64_t, WindowStagePtr)>> &cFuncMap)
{
    auto callback = CJLambda::Create(reinterpret_cast<void (*)(int64_t, WindowStagePtr)>(cFuncId));
    cFuncMap.emplace(callbackId, callback);
}

int32_t CjAbilityLifecycleCallbackImpl::Register(CArrI64 cFuncIds, bool isSync)
{
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
        EmplaceAbilityFunc(callbackId, cFuncIds.head[i++], onAbilityCreatecallbacks_);
        EmplaceAbilityWindowStageFunc(callbackId, cFuncIds.head[i++], onWindowStageCreatecallbacks_);
        EmplaceAbilityWindowStageFunc(callbackId, cFuncIds.head[i++], onWindowStageActivecallbacks_);
        EmplaceAbilityWindowStageFunc(callbackId, cFuncIds.head[i++], onWindowStageInactivecallbacks_);
        EmplaceAbilityWindowStageFunc(callbackId, cFuncIds.head[i++], onWindowStageDestroycallbacks_);
        EmplaceAbilityFunc(callbackId, cFuncIds.head[i++], onAbilityDestroycallbacks_);
        EmplaceAbilityFunc(callbackId, cFuncIds.head[i++], onAbilityForegroundcallbacks_);
        EmplaceAbilityFunc(callbackId, cFuncIds.head[i++], onAbilityBackgroundcallbacks_);
        EmplaceAbilityFunc(callbackId, cFuncIds.head[i++], onAbilityContinuecallbacks_);
        // optional callbacks
        EmplaceAbilityFunc(callbackId, cFuncIds.head[i++], onAbilityWillCreatecallbacks_);
        EmplaceAbilityWindowStageFunc(callbackId, cFuncIds.head[i++], onWindowStageWillCreatecallbacks_);
        EmplaceAbilityWindowStageFunc(callbackId, cFuncIds.head[i++], onWindowStageWillDestroycallbacks_);
        EmplaceAbilityFunc(callbackId, cFuncIds.head[i++], onAbilityWillForegroundcallbacks_);
        EmplaceAbilityFunc(callbackId, cFuncIds.head[i++], onAbilityWillDestroycallbacks_);
        EmplaceAbilityFunc(callbackId, cFuncIds.head[i++], onAbilityWillBackgroundcallbacks_);
        EmplaceAbilityFunc(callbackId, cFuncIds.head[i++], onWillNewWantcallbacks_);
        EmplaceAbilityFunc(callbackId, cFuncIds.head[i++], onNewWantcallbacks_);
        EmplaceAbilityFunc(callbackId, cFuncIds.head[i++], onAbilityWillContinuecallbacks_);
        EmplaceAbilityWindowStageFunc(callbackId, cFuncIds.head[i++], onWindowStageWillRestorecallbacks_);
        EmplaceAbilityWindowStageFunc(callbackId, cFuncIds.head[i++], onWindowStageRestorecallbacks_);
        EmplaceAbilityFunc(callbackId, cFuncIds.head[i++], onAbilityWillSaveStatecallbacks_);
        EmplaceAbilityFunc(callbackId, cFuncIds.head[i++], onAbilitySaveStatecallbacks_);
    }
    return callbackId;
}

bool CjAbilityLifecycleCallbackImpl::UnRegister(int32_t callbackId, bool isSync)
{
    TAG_LOGI(AAFwkTag::APPKIT, "callbackId : %{public}d", callbackId);
    if (isSync) {
        return false;
    }
    auto it = onAbilityCreatecallbacks_.find(callbackId);
    if (it == onAbilityCreatecallbacks_.end()) {
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
    onAbilityContinuecallbacks_.erase(callbackId);
    // optional callbacks
    onAbilityWillCreatecallbacks_.erase(callbackId);
    onWindowStageWillCreatecallbacks_.erase(callbackId);
    onWindowStageWillDestroycallbacks_.erase(callbackId);
    onAbilityWillForegroundcallbacks_.erase(callbackId);
    onAbilityWillDestroycallbacks_.erase(callbackId);
    onAbilityWillBackgroundcallbacks_.erase(callbackId);
    onWillNewWantcallbacks_.erase(callbackId);
    onNewWantcallbacks_.erase(callbackId);
    onAbilityWillContinuecallbacks_.erase(callbackId);
    onWindowStageWillRestorecallbacks_.erase(callbackId);
    onWindowStageRestorecallbacks_.erase(callbackId);
    onAbilityWillSaveStatecallbacks_.erase(callbackId);
    return onAbilitySaveStatecallbacks_.erase(callbackId) == 1;
}

void CjAbilityLifecycleCallbackImpl::OnAbilityCreate(const int64_t &ability)
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

void CjAbilityLifecycleCallbackImpl::OnWindowStageCreate(const int64_t &ability, WindowStagePtr windowStage)
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

void CjAbilityLifecycleCallbackImpl::OnWindowStageActive(const int64_t &ability, WindowStagePtr windowStage)
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

void CjAbilityLifecycleCallbackImpl::OnWindowStageInactive(const int64_t &ability, WindowStagePtr windowStage)
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

void CjAbilityLifecycleCallbackImpl::OnWindowStageDestroy(const int64_t &ability, WindowStagePtr windowStage)
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

void CjAbilityLifecycleCallbackImpl::OnAbilityDestroy(const int64_t &ability)
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

void CjAbilityLifecycleCallbackImpl::OnAbilityForeground(const int64_t &ability)
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

void CjAbilityLifecycleCallbackImpl::OnAbilityBackground(const int64_t &ability)
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

void CjAbilityLifecycleCallbackImpl::OnAbilityContinue(const int64_t &ability)
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

// optional callbacks
void CjAbilityLifecycleCallbackImpl::OnAbilityWillCreate(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnAbilityWillCreate");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is nullptr");
        return;
    }
    for (auto &callback : onAbilityWillCreatecallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability);
    }
}

void CjAbilityLifecycleCallbackImpl::OnWindowStageWillCreate(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnWindowStageWillCreate");
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability or windowStage is nullptr");
        return;
    }
    for (auto &callback : onWindowStageWillCreatecallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability, windowStage);
    }
}

void CjAbilityLifecycleCallbackImpl::OnWindowStageWillDestroy(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnWindowStageWillDestroy");
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability or windowStage is nullptr");
        return;
    }
    for (auto &callback : onWindowStageWillDestroycallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability, windowStage);
    }
}

void CjAbilityLifecycleCallbackImpl::OnAbilityWillDestroy(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnAbilityWillDestroy");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is nullptr");
        return;
    }
    for (auto &callback : onAbilityWillDestroycallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability);
    }
}
void CjAbilityLifecycleCallbackImpl::OnAbilityWillForeground(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnAbilityWillForeground");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is nullptr");
        return;
    }
    for (auto &callback : onAbilityWillForegroundcallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability);
    }
}
void CjAbilityLifecycleCallbackImpl::OnAbilityWillBackground(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnAbilityWillBackground");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is nullptr");
        return;
    }
    for (auto &callback : onAbilityWillBackgroundcallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability);
    }
}

void CjAbilityLifecycleCallbackImpl::OnNewWant(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnNewWant");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is nullptr");
        return;
    }
    for (auto &callback : onNewWantcallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability);
    }
}

void CjAbilityLifecycleCallbackImpl::OnWillNewWant(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnWillNewWant");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is nullptr");
        return;
    }
    for (auto &callback : onWillNewWantcallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability);
    }
}

void CjAbilityLifecycleCallbackImpl::OnAbilityWillContinue(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnAbilityWillContinue");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is nullptr");
        return;
    }
    for (auto &callback : onAbilityWillContinuecallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability);
    }
}

void CjAbilityLifecycleCallbackImpl::OnWindowStageWillRestore(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnWindowStageWillRestore");
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability or windowStage is nullptr");
        return;
    }
    for (auto &callback : onWindowStageWillRestorecallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability, windowStage);
    }
}

void CjAbilityLifecycleCallbackImpl::OnWindowStageRestore(const int64_t &ability, WindowStagePtr windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnWindowStageRestore");
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability or windowStage is nullptr");
        return;
    }
    for (auto &callback : onWindowStageRestorecallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability, windowStage);
    }
}

void CjAbilityLifecycleCallbackImpl::OnAbilityWillSaveState(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnAbilityWillSaveState");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is nullptr");
        return;
    }
    for (auto &callback : onAbilityWillSaveStatecallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability);
    }
}

void CjAbilityLifecycleCallbackImpl::OnAbilitySaveState(const int64_t &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = OnAbilitySaveState");
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability is nullptr");
        return;
    }
    for (auto &callback : onAbilitySaveStatecallbacks_) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid cjCallback");
            return;
        }
        callback.second(ability);
    }
}

} // namespace AbilityRuntime
} // namespace OHOS
