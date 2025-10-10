/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "js_ability_lifecycle_callback.h"

#include "hilog_tag_wrapper.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace AbilityRuntime {
JsAbilityLifecycleCallback::JsAbilityLifecycleCallback(napi_env env)
    : env_(env)
{
    type_ = AbilityLifecycleCallbackType::JS;
}

int32_t JsAbilityLifecycleCallback::serialNumber_ = 0;

void JsAbilityLifecycleCallback::CallJsMethodInnerCommon(const std::string &methodName,
    const std::shared_ptr<NativeReference> &ability, const std::shared_ptr<NativeReference> &windowStage,
    const std::map<int32_t, std::shared_ptr<NativeReference>> callbacks)
{
    auto nativeAbilityObj = CreateJsNull(env_);
    if (ability != nullptr) {
        nativeAbilityObj = ability->GetNapiValue();
    }

    bool isWindowStage = false;
    auto nativeWindowStageObj = CreateJsNull(env_);
    if (windowStage != nullptr) {
        nativeWindowStageObj = windowStage->GetNapiValue();
        isWindowStage = true;
    }

    for (auto &callback : callbacks) {
        if (!callback.second) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid jsCallback");
            return;
        }

        auto obj = callback.second->GetNapiValue();
        if (!CheckTypeForNapiValue(env_, obj, napi_object)) {
            TAG_LOGE(AAFwkTag::APPKIT, "get object failed");
            return;
        }

        napi_value method = nullptr;
        napi_get_named_property(env_, obj, methodName.data(), &method);
        if (method == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null method %{public}s", methodName.data());
            return;
        }

        if (!isWindowStage) {
            napi_value argv[] = { nativeAbilityObj };
            napi_call_function(env_, obj, method, ArraySize(argv), argv, nullptr);
        } else {
            napi_value argv[] = { nativeAbilityObj, nativeWindowStageObj };
            napi_call_function(env_, obj, method, ArraySize(argv), argv, nullptr);
        }
    }
}

void JsAbilityLifecycleCallback::CallJsMethod(
    const std::string &methodName, const std::shared_ptr<NativeReference> &ability)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = %{public}s", methodName.c_str());
    if (!ability) {
        TAG_LOGE(AAFwkTag::APPKIT, "null ability");
        return;
    }
    HandleScope handleScope(env_);
    CallJsMethodInnerCommon(methodName, ability, nullptr, callbacks_);
    CallJsMethodInnerCommon(methodName, ability, nullptr, callbacksSync_);
}

void JsAbilityLifecycleCallback::CallWindowStageJsMethod(const std::string &methodName,
    const std::shared_ptr<NativeReference> &ability, const std::shared_ptr<NativeReference> &windowStage)
{
    TAG_LOGD(AAFwkTag::APPKIT, "methodName = %{public}s", methodName.c_str());
    if (!ability || !windowStage) {
        TAG_LOGE(AAFwkTag::APPKIT, "null ability or windowStage");
        return;
    }
    HandleScope handleScope(env_);
    CallJsMethodInnerCommon(methodName, ability, windowStage, callbacks_);
    CallJsMethodInnerCommon(methodName, ability, windowStage, callbacksSync_);
}

void JsAbilityLifecycleCallback::OnAbilityCreate(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onAbilityCreate", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnWindowStageCreate(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallWindowStageJsMethod("onWindowStageCreate", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_,
        static_cast<const JsAbilityLifecycleCallbackArgs&>(windowStage).ref_);
}

void JsAbilityLifecycleCallback::OnWindowStageDestroy(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallWindowStageJsMethod("onWindowStageDestroy", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_,
        static_cast<const JsAbilityLifecycleCallbackArgs&>(windowStage).ref_);
}

void JsAbilityLifecycleCallback::OnWindowStageActive(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallWindowStageJsMethod("onWindowStageActive", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_,
        static_cast<const JsAbilityLifecycleCallbackArgs&>(windowStage).ref_);
}

void JsAbilityLifecycleCallback::OnWindowStageInactive(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallWindowStageJsMethod("onWindowStageInactive", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_,
        static_cast<const JsAbilityLifecycleCallbackArgs&>(windowStage).ref_);
}

void JsAbilityLifecycleCallback::OnAbilityDestroy(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onAbilityDestroy", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnAbilityForeground(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onAbilityForeground", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnAbilityBackground(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onAbilityBackground", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnAbilityContinue(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onAbilityContinue", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnAbilityWillContinue(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onAbilityWillContinue", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnWindowStageWillRestore(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallWindowStageJsMethod("onWindowStageWillRestore",
        static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_,
        static_cast<const JsAbilityLifecycleCallbackArgs&>(windowStage).ref_);
}

void JsAbilityLifecycleCallback::OnWindowStageRestore(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallWindowStageJsMethod("onWindowStageRestore", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_,
        static_cast<const JsAbilityLifecycleCallbackArgs&>(windowStage).ref_);
}

void JsAbilityLifecycleCallback::OnAbilityWillSaveState(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onAbilityWillSaveState", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnAbilitySaveState(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onAbilitySaveState", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

int32_t JsAbilityLifecycleCallback::Register(napi_value jsCallback, bool isSync)
{
    TAG_LOGD(AAFwkTag::APPKIT, "enter");
    if (env_ == nullptr) {
        return -1;
    }
    int32_t callbackId = serialNumber_;
    if (serialNumber_ < INT32_MAX) {
        serialNumber_++;
    } else {
        serialNumber_ = 0;
    }
    napi_ref ref = nullptr;
    napi_create_reference(env_, jsCallback, 1, &ref);
    if (isSync) {
        callbacksSync_.emplace(callbackId, std::shared_ptr<NativeReference>(reinterpret_cast<NativeReference*>(ref)));
    } else {
        callbacks_.emplace(callbackId, std::shared_ptr<NativeReference>(reinterpret_cast<NativeReference*>(ref)));
    }
    return callbackId;
}

bool JsAbilityLifecycleCallback::UnRegister(int32_t callbackId, bool isSync)
{
    TAG_LOGI(AAFwkTag::APPKIT, "callbackId : %{public}d", callbackId);
    if (isSync) {
        auto it = callbacksSync_.find(callbackId);
        if (it == callbacksSync_.end()) {
            TAG_LOGE(AAFwkTag::APPKIT, "%{public}d not in callbacksSync_", callbackId);
            return false;
        }
        return callbacksSync_.erase(callbackId) == 1;
    }
    auto it = callbacks_.find(callbackId);
    if (it == callbacks_.end()) {
        TAG_LOGE(AAFwkTag::APPKIT, "%{public}d not in callbacks_", callbackId);
        return false;
    }
    return callbacks_.erase(callbackId) == 1;
}

void JsAbilityLifecycleCallback::OnNewWant(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onNewWant", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnWillNewWant(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onWillNewWant", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnAbilityWillCreate(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onAbilityWillCreate", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnWindowStageWillCreate(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallWindowStageJsMethod("onWindowStageWillCreate",
        static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_,
        static_cast<const JsAbilityLifecycleCallbackArgs&>(windowStage).ref_);
}

void JsAbilityLifecycleCallback::OnWindowStageWillDestroy(const AbilityLifecycleCallbackArgs &ability,
    const AbilityLifecycleCallbackArgs &windowStage)
{
    CallWindowStageJsMethod("onWindowStageWillDestroy",
        static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_,
        static_cast<const JsAbilityLifecycleCallbackArgs&>(windowStage).ref_);
}

void JsAbilityLifecycleCallback::OnAbilityWillDestroy(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onAbilityWillDestroy", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnAbilityWillForeground(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onAbilityWillForeground", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnAbilityWillBackground(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onAbilityWillBackground", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

bool JsAbilityLifecycleCallback::IsEmpty() const
{
    return callbacks_.empty() && callbacksSync_.empty();
}

void JsAbilityLifecycleCallback::OnWillForeground(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onWillForeground", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnDidForeground(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onDidForeground", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnWillBackground(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onWillBackground", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}

void JsAbilityLifecycleCallback::OnDidBackground(const AbilityLifecycleCallbackArgs &ability)
{
    CallJsMethod("onDidBackground", static_cast<const JsAbilityLifecycleCallbackArgs&>(ability).ref_);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
