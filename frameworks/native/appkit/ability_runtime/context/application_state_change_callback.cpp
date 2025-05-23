/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "application_state_change_callback.h"

#include "hilog_tag_wrapper.h"
#include "js_data_struct_converter.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace AbilityRuntime {
JsApplicationStateChangeCallback::JsApplicationStateChangeCallback(napi_env env)
    : env_(env)
{
}

void JsApplicationStateChangeCallback::CallJsMethodInnerCommon(
    const std::string &methodName, const std::set<std::shared_ptr<NativeReference>> callbacks)
{
    for (auto &callback : callbacks) {
        if (!callback) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid jsCallback");
            continue;
        }

        auto obj = callback->GetNapiValue();
        if (!CheckTypeForNapiValue(env_, obj, napi_object)) {
            TAG_LOGE(AAFwkTag::APPKIT, "get object failed");
            continue;
        }

        napi_value method = nullptr;
        napi_get_named_property(env_, obj, methodName.data(), &method);
        if (method == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null method %{public}s", methodName.data());
            continue;
        }
        napi_call_function(env_, obj, method, 0, nullptr, nullptr);
    }
}

void JsApplicationStateChangeCallback::CallJsMethod(const std::string &methodName)
{
    TAG_LOGD(AAFwkTag::APPKIT, "MethodName = %{public}s", methodName.c_str());
    std::weak_ptr<JsApplicationStateChangeCallback> thisWeakPtr(shared_from_this());
    std::unique_ptr<NapiAsyncTask::CompleteCallback> complete = std::make_unique<NapiAsyncTask::CompleteCallback>(
        [thisWeakPtr, methodName, callbacks = callbacks_]
        (napi_env env, NapiAsyncTask &task, int32_t status) {
            std::shared_ptr<JsApplicationStateChangeCallback> jsCallback = thisWeakPtr.lock();
            if (jsCallback) {
                jsCallback->CallJsMethodInnerCommon(methodName, callbacks);
            }
        }
    );
    napi_ref callback = nullptr;
    std::unique_ptr<NapiAsyncTask::ExecuteCallback> execute = nullptr;
    NapiAsyncTask::Schedule("JsApplicationStateChangeCallback::CallJsMethod:" + methodName,
        env_, std::make_unique<NapiAsyncTask>(callback, std::move(execute), std::move(complete)));
}

void JsApplicationStateChangeCallback::NotifyApplicationForeground()
{
    CallJsMethod("onApplicationForeground");
}

void JsApplicationStateChangeCallback::NotifyApplicationBackground()
{
    CallJsMethod("onApplicationBackground");
}

void JsApplicationStateChangeCallback::Register(napi_value jsCallback)
{
    if (env_ == nullptr || jsCallback == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env or jsCallback");
        return;
    }
    napi_ref ref = nullptr;
    napi_create_reference(env_, jsCallback, 1, &ref);
    callbacks_.emplace(std::shared_ptr<NativeReference>(reinterpret_cast<NativeReference*>(ref)));
}

bool JsApplicationStateChangeCallback::UnRegister(napi_value jsCallback)
{
    if (jsCallback == nullptr) {
        TAG_LOGI(AAFwkTag::APPKIT, "null jsCallback");
        callbacks_.clear();
        return true;
    }

    for (auto &callback : callbacks_) {
        if (!callback) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid jsCallback");
            continue;
        }

        napi_value value = callback->GetNapiValue();
        if (value == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null value");
            continue;
        }

        bool isEqual = false;
        napi_strict_equals(env_, value, jsCallback, &isEqual);
        if (isEqual) {
            return callbacks_.erase(callback) == 1;
        }
    }
    return false;
}

bool JsApplicationStateChangeCallback::IsEmpty() const
{
    return callbacks_.empty();
}
} // namespace AbilityRuntime
} // namespace OHOS