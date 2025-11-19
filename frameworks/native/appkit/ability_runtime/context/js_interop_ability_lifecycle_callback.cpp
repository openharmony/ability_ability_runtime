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

#include "js_interop_ability_lifecycle_callback.h"

#include "hilog_tag_wrapper.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
constexpr size_t INDEX_ONE = 1;
constexpr const int32_t ERROR_CODE_NULL_ENV = -1;
constexpr const int32_t ERROR_CODE_NULL_CALLBACK = -2;
}
JsInteropAbilityLifecycleCallback::JsInteropAbilityLifecycleCallback(napi_env env) : env_(env)
{}

bool JsInteropAbilityLifecycleCallback::Empty()
{
    return callbacks_.empty();
}

void JsInteropAbilityLifecycleCallback::CallObjectMethod(const char *methodName,
    std::shared_ptr<InteropObject> ability, std::shared_ptr<InteropObject> windowStage)
{
    if (env_ == nullptr || ability == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env_ or ability or windowStage");
        return;
    }
    if (!ability->IsFromAni()) {
        TAG_LOGI(AAFwkTag::APPKIT, "not from ets");
        return;
    }
    napi_value jsAbility = ability->GetNapiValue(env_);
    if (jsAbility == nullptr) {
        TAG_LOGI(AAFwkTag::APPKIT, "null napi ability");
        return;
    }

    size_t args = ARGC_ONE;
    napi_value argv[ARGC_TWO] = { jsAbility };
    if (windowStage != nullptr) {
        napi_value jsWindowStage = windowStage->GetNapiValue(env_);
        if (jsAbility == nullptr || jsWindowStage == nullptr) {
            TAG_LOGI(AAFwkTag::APPKIT, "null napi windowStage");
            return;
        }
        argv[INDEX_ONE] = jsWindowStage;
        args = ARGC_TWO;
    }
    for (const auto &callback : callbacks_) {
        if (callback == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null callback");
            continue;
        }
        auto obj = callback->GetNapiValue();
        if (!CheckTypeForNapiValue(env_, obj, napi_object)) {
            TAG_LOGE(AAFwkTag::APPKIT, "get object failed");
            continue;
        }

        napi_value method = nullptr;
        napi_get_named_property(env_, obj, methodName, &method);
        if (method == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null method %{public}s", methodName);
            continue;
        }
        napi_status status = napi_call_function(env_, obj, method, args, argv, nullptr);
        if (status != napi_ok) {
            TAG_LOGE(AAFwkTag::APPKIT, "call method failed %{public}d", status);
        }
    }
}

int32_t JsInteropAbilityLifecycleCallback::Register(napi_value callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "enter JsInteropAbilityLifecycleCallback::Register");
    if (env_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env_");
        return ERROR_CODE_NULL_ENV;
    }
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null callback");
        return ERROR_CODE_NULL_CALLBACK;
    }
    napi_ref ref = nullptr;
    napi_create_reference(env_, callback, 1, &ref);
    callbacks_.push_back(std::shared_ptr<NativeReference>(reinterpret_cast<NativeReference*>(ref)));
    return 0;
}

bool JsInteropAbilityLifecycleCallback::Unregister(napi_value jsCallback)
{
    TAG_LOGI(AAFwkTag::APPKIT, "Unregister");
    if (jsCallback == nullptr) {
        TAG_LOGI(AAFwkTag::APPKIT, "null jsCallback");
        callbacks_.clear();
        return true;
    }

    for (auto iter = callbacks_.begin(); iter != callbacks_.end(); ++iter) {
        if (*iter == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid callback");
            continue;
        }

        napi_value value = (*iter)->GetNapiValue();
        if (value == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null value");
            continue;
        }

        bool isEqual = false;
        napi_strict_equals(env_, value, jsCallback, &isEqual);
        if (isEqual) {
            callbacks_.erase(iter);
            return true;
        }
    }
    return false;
}

void JsInteropAbilityLifecycleCallback::OnAbilityCreate(std::shared_ptr<InteropObject> ability)
{
    CallObjectMethod("onAbilityCreate", ability);
}

void JsInteropAbilityLifecycleCallback::OnWindowStageCreate(std::shared_ptr<InteropObject> ability,
    std::shared_ptr<InteropObject> windowStage)
{
    CallObjectMethod("onWindowStageCreate", ability, windowStage);
}

void JsInteropAbilityLifecycleCallback::OnWindowStageDestroy(std::shared_ptr<InteropObject> ability,
    std::shared_ptr<InteropObject> windowStage)
{
    CallObjectMethod("onWindowStageDestroy", ability, windowStage);
}

void JsInteropAbilityLifecycleCallback::OnAbilityDestroy(std::shared_ptr<InteropObject> ability)
{
    CallObjectMethod("onAbilityDestroy", ability);
}

void JsInteropAbilityLifecycleCallback::OnAbilityForeground(std::shared_ptr<InteropObject> ability)
{
    CallObjectMethod("onAbilityForeground", ability);
}

void JsInteropAbilityLifecycleCallback::OnAbilityBackground(std::shared_ptr<InteropObject> ability)
{
    CallObjectMethod("onAbilityBackground", ability);
}
}  // namespace AbilityRuntime
}  // namespace OHOS