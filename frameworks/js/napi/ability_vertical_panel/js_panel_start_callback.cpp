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
#include "js_panel_start_callback.h"

#include "ability_business_error.h"
#include "hilog_tag_wrapper.h"
#include "js_runtime_utils.h"
#include "napi/native_api.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#ifdef SUPPORT_SCREEN
#include "ui_content.h"
#include "ws_common.h"
#endif // SUPPORT_SCREEN

namespace OHOS {
namespace AbilityRuntime {
#ifdef SUPPORT_SCREEN
constexpr const char* ERROR_MSG_INNER = "Inner error.";
#endif // SUPPORT_SCREEN
JsPanelStartCallback::~JsPanelStartCallback()
{
    if (jsCallbackObject_ == nullptr) {
        return;
    }

    uv_loop_t *loop = nullptr;
    napi_get_uv_event_loop(env_, &loop);
    if (loop == nullptr) {
        return;
    }

    uv_work_t *work = new (std::nothrow) uv_work_t;
    if (work == nullptr) {
        return;
    }
    work->data = reinterpret_cast<void *>(jsCallbackObject_.release());
    int ret = uv_queue_work(loop, work, [](uv_work_t *work) {},
    [](uv_work_t *work, int status) {
        if (work == nullptr) {
            return;
        }
        if (work->data == nullptr) {
            delete work;
            work = nullptr;
            return;
        }
        delete reinterpret_cast<NativeReference *>(work->data);
        work->data = nullptr;
        delete work;
        work = nullptr;
    });
    if (ret != 0) {
        delete reinterpret_cast<NativeReference *>(work->data);
        work->data = nullptr;
        delete work;
        work = nullptr;
    }
}

void JsPanelStartCallback::SetJsCallbackObject(napi_value jsCallbackObject)
{
    napi_ref ref = nullptr;
    napi_create_reference(env_, jsCallbackObject, 1, &ref);
    jsCallbackObject_ = std::unique_ptr<NativeReference>(reinterpret_cast<NativeReference*>(ref));
    if (jsCallbackObject_ == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null jsCallbackObject_");
    }
}

#ifdef SUPPORT_SCREEN
void JsPanelStartCallback::OnError(int32_t number)
{
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "OnError call");
    if (env_ == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null env_");
        return;
    }
    // js callback should run in js thread
    std::shared_ptr<JsPanelStartCallback> jsPanelStartCallback = shared_from_this();
    std::unique_ptr<NapiAsyncTask::CompleteCallback> complete = std::make_unique<NapiAsyncTask::CompleteCallback>
        ([jsPanelStartCallback, number](napi_env env, NapiAsyncTask &task, int32_t status) {
            if (jsPanelStartCallback != nullptr) {
                jsPanelStartCallback->CallJsError(number);
            }
        });
    napi_ref callback = nullptr;
    std::unique_ptr<NapiAsyncTask::ExecuteCallback> execute = nullptr;
    NapiAsyncTask::Schedule("JsPanelStartCallback::OnError:",
        env_, std::make_unique<NapiAsyncTask>(callback, std::move(execute), std::move(complete)));
    CloseModalUIExtension();
}

void JsPanelStartCallback::OnResult(int32_t resultCode, const AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "OnResult call");
    if (env_ == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null env_");
        return;
    }
    // js callback should run in js thread
    std::shared_ptr<JsPanelStartCallback> jsPanelStartCallback = shared_from_this();
    std::unique_ptr<NapiAsyncTask::CompleteCallback> complete = std::make_unique<NapiAsyncTask::CompleteCallback>
        ([jsPanelStartCallback, resultCode, want](napi_env env, NapiAsyncTask &task, int32_t status) {
            if (jsPanelStartCallback != nullptr) {
                jsPanelStartCallback->CallJsResult(resultCode, want);
            }
        });
    napi_ref callback = nullptr;
    std::unique_ptr<NapiAsyncTask::ExecuteCallback> execute = nullptr;
    NapiAsyncTask::Schedule("JsPanelStartCallback::OnResult:",
        env_, std::make_unique<NapiAsyncTask>(callback, std::move(execute), std::move(complete)));
    CloseModalUIExtension();
}
#endif // SUPPORT_SCREEN

void JsPanelStartCallback::CallJsResult(int32_t resultCode, const AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "CallJsResult call");
    HandleScope handleScope(env_);
    if (env_ == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null env_");
        return;
    }

    napi_value abilityResult = OHOS::AppExecFwk::WrapAbilityResult(env_, resultCode, want);
    if (abilityResult == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null abilityResult");
        return;
    }

    if (jsCallbackObject_ == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null jsCallbackObject_ ");
        return;
    }
    napi_value obj = jsCallbackObject_->GetNapiValue();
    if (obj == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null obj");
        return;
    }
    napi_value method = nullptr;
    napi_get_named_property(env_, obj, "onResult", &method);
    if (method == nullptr || AppExecFwk::IsTypeForNapiValue(env_, method, napi_undefined)
        || AppExecFwk::IsTypeForNapiValue(env_, method, napi_null)) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null method");
        return;
    }

    napi_value argv[] = { abilityResult };
    napi_call_function(env_, obj, method, ArraySize(argv), argv, nullptr);
    TAG_LOGI(AAFwkTag::VERTICAL_PANEL, "end");
}

void JsPanelStartCallback::CallJsError(int32_t number)
{
    TAG_LOGD(AAFwkTag::VERTICAL_PANEL, "CallJsError call");
    if (env_ == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null env_ ");
        return;
    }
    std::string name;
    std::string message;
#ifdef SUPPORT_SCREEN
    if (number != static_cast<int32_t>(Rosen::WSError::WS_OK)) {
        number = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
        name = ERROR_MSG_INNER;
        message = "StartVerticalPanel failed.";
    }
#endif // SUPPORT_SCREEN
    napi_value nativeNumber = CreateJsValue(env_, number);
    napi_value nativeName = CreateJsValue(env_, name);
    napi_value nativeMessage = CreateJsValue(env_, message);
    if (jsCallbackObject_ == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null jsCallbackObject_");
        return;
    }
    napi_value obj = jsCallbackObject_->GetNapiValue();
    if (obj == nullptr) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null obj");
        return;
    }
    napi_value method = nullptr;
    napi_get_named_property(env_, obj, "onError", &method);
    if (method == nullptr || AppExecFwk::IsTypeForNapiValue(env_, method, napi_undefined)
        || AppExecFwk::IsTypeForNapiValue(env_, method, napi_null)) {
        TAG_LOGE(AAFwkTag::VERTICAL_PANEL, "null method");
        return;
    }

    napi_value argv[] = { nativeNumber, nativeName, nativeMessage };
    napi_call_function(env_, obj, method, ArraySize(argv), argv, nullptr);
    TAG_LOGI(AAFwkTag::VERTICAL_PANEL, "end");
}
}  // namespace AbilityRuntime
}  // namespace OHOS