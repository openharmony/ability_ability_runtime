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

#include "js_startup_config.h"

#include "hilog_tag_wrapper.h"
#include "hap_module_info.h"
#include "js_runtime_utils.h"
#include "napi_common_util.h"
#include "napi_common_want.h"

namespace OHOS {
namespace AbilityRuntime {

JsStartupConfig::JsStartupConfig(napi_env env) : StartupConfig(), env_(env)
{}

JsStartupConfig::~JsStartupConfig() = default;

int32_t JsStartupConfig::Init(Runtime &runtime, std::shared_ptr<Context> context,
    const std::string &srcEntry, std::shared_ptr<AAFwk::Want> want)
{
    auto &jsRuntime = static_cast<JsRuntime&>(runtime);
    auto configEntryJsRef = LoadSrcEntry(jsRuntime, context, srcEntry);
    if (configEntryJsRef == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null configEntry");
        return ERR_STARTUP_INTERNAL_ERROR;
    }
    HandleScope handleScope(env_);

    napi_value configEntry = configEntryJsRef->GetNapiValue();
    if (!CheckTypeForNapiValue(env_, configEntry, napi_object)) {
        TAG_LOGE(AAFwkTag::STARTUP, "not napi object");
        return ERR_STARTUP_INTERNAL_ERROR;
    }
    napi_value onConfig = nullptr;
    napi_get_named_property(env_, configEntry, "onConfig", &onConfig);
    if (onConfig == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null onConfig");
        return ERR_STARTUP_INTERNAL_ERROR;
    }
    bool isCallable = false;
    napi_is_callable(env_, onConfig, &isCallable);
    if (!isCallable) {
        TAG_LOGE(AAFwkTag::STARTUP, "onConfig not callable");
        return ERR_STARTUP_INTERNAL_ERROR;
    }
    napi_value config = nullptr;
    napi_call_function(env_, configEntry, onConfig, 0, nullptr, &config);
    if (config == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null config");
        return ERR_STARTUP_INTERNAL_ERROR;
    }

    InitAwaitTimeout(env_, config);
    InitListener(env_, config);
    InitCustomization(env_, configEntry, want);
    return ERR_OK;
}

int32_t JsStartupConfig::Init(napi_value config)
{
    if (config == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null config");
        return ERR_STARTUP_INTERNAL_ERROR;
    }

    InitAwaitTimeout(env_, config);
    InitListener(env_, config);
    return ERR_OK;
}

std::unique_ptr<NativeReference> JsStartupConfig::LoadSrcEntry(JsRuntime &jsRuntime,
    std::shared_ptr<Context> context, const std::string &srcEntry)
{
    TAG_LOGD(AAFwkTag::APPKIT, "call");
    if (srcEntry.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "srcEntry invalid");
        return nullptr;
    }
    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        return nullptr;
    }
    auto hapModuleInfo = context->GetHapModuleInfo();
    if (!hapModuleInfo) {
        TAG_LOGE(AAFwkTag::APPKIT, "null hapModuleInfo");
        return nullptr;
    }

    bool esmodule = hapModuleInfo->compileMode == AppExecFwk::CompileMode::ES_MODULE;
    std::string moduleNameWithStartupConfig(hapModuleInfo->moduleName + "::startupConfig");
    std::string srcPath(hapModuleInfo->moduleName + "/" + srcEntry);

    auto pos = srcPath.rfind('.');
    if (pos == std::string::npos) {
        return nullptr;
    }
    srcPath.erase(pos);
    srcPath.append(".abc");

    jsRuntime.UpdateModuleNameAndAssetPath(hapModuleInfo->moduleName);
    return jsRuntime.LoadModule(moduleNameWithStartupConfig, srcPath, hapModuleInfo->hapPath, esmodule);
}

void JsStartupConfig::InitAwaitTimeout(napi_env env, napi_value config)
{
    napi_value awaitTimeout = nullptr;
    napi_get_named_property(env, config, "timeoutMs", &awaitTimeout);
    if (awaitTimeout == nullptr) {
        TAG_LOGD(AAFwkTag::STARTUP, "timeoutMs invalid");
        return;
    }
    int32_t awaitTimeoutNum = DEFAULT_AWAIT_TIMEOUT_MS;
    if (!ConvertFromJsValue(env, awaitTimeout, awaitTimeoutNum)) {
        TAG_LOGD(AAFwkTag::STARTUP, "covert failed");
        return;
    }
    if (awaitTimeoutNum <= 0) {
        TAG_LOGE(AAFwkTag::STARTUP, "invalid argc");
        awaitTimeoutNum = DEFAULT_AWAIT_TIMEOUT_MS;
    }
    TAG_LOGD(AAFwkTag::STARTUP, "set awaitTimeoutMs to %{public}d", awaitTimeoutNum);
    awaitTimeoutMs_ = awaitTimeoutNum;
}

void JsStartupConfig::InitListener(napi_env env, napi_value config)
{
    napi_value listener = nullptr;
    napi_get_named_property(env, config, "startupListener", &listener);
    if (listener == nullptr) {
        TAG_LOGD(AAFwkTag::STARTUP, "null startupListener");
        return;
    }
    if (!CheckTypeForNapiValue(env, listener, napi_object)) {
        TAG_LOGD(AAFwkTag::STARTUP, "not napi object");
        return;
    }

    napi_value onCompleted = nullptr;
    napi_get_named_property(env, listener, "onCompleted", &onCompleted);
    if (onCompleted == nullptr) {
        TAG_LOGD(AAFwkTag::STARTUP, "null onCompleted");
        return;
    }
    napi_ref listenerRef = nullptr;
    napi_create_reference(env, listener, 1, &listenerRef);
    std::shared_ptr<NativeReference> listenerRefSp(reinterpret_cast<NativeReference *>(listenerRef));
    OnCompletedCallbackFunc onCompletedCallback =
        [env, listenerRefSp](const std::shared_ptr<StartupTaskResult> &result) {
            if (env == nullptr || listenerRefSp == nullptr) {
                TAG_LOGE(AAFwkTag::STARTUP, "null env or listenerRefSp");
                return;
            }
            HandleScope handleScope(env);
            napi_value listener = listenerRefSp->GetNapiValue();

            napi_value onCompleted = nullptr;
            napi_get_named_property(env, listener, "onCompleted", &onCompleted);
            if (onCompleted == nullptr) {
                TAG_LOGE(AAFwkTag::STARTUP, "null onCompleted");
                return;
            }
            bool isCallable = false;
            napi_is_callable(env, onCompleted, &isCallable);
            if (!isCallable) {
                TAG_LOGE(AAFwkTag::STARTUP, "onCompleted not callable");
                return;
            }
            napi_value argv[1] = { JsStartupConfig::BuildResult(env, result) };
            napi_call_function(env, listener, onCompleted, 1, argv, nullptr);
        };
    listener_ = std::make_shared<StartupListener>(onCompletedCallback);
}

void JsStartupConfig::InitCustomization(napi_env env, napi_value configEntry, std::shared_ptr<AAFwk::Want> want)
{
    TAG_LOGD(AAFwkTag::STARTUP, "InitCustomization");
    if (!want) {
        TAG_LOGD(AAFwkTag::STARTUP, "want is null");
        return;
    }

    napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, *want);
    napi_value method = nullptr;
    napi_get_named_property(env, configEntry, "onRequestCustomMatchRule", &method);
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null method onRequestCustomMatchRule");
        return;
    }

    bool isCallable = false;
    napi_is_callable(env, method, &isCallable);
    if (!isCallable) {
        TAG_LOGI(AAFwkTag::STARTUP, "onRequestCustomMatchRule not callable");
        return;
    }

    constexpr size_t argc = 1;
    napi_value argv[] = { napiWant };
    napi_value callResult = nullptr;
    napi_status status = napi_call_function(env, configEntry, method, argc, argv, &callResult);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "call js func onRequestCustomMatchRule failed: %{public}d", status);
    }
    customization_ = AppExecFwk::UnwrapStringFromJS(env, callResult);
}

napi_value JsStartupConfig::BuildResult(napi_env env, const std::shared_ptr<StartupTaskResult> &result)
{
    if (result == nullptr) {
        return CreateJsError(env, ERR_STARTUP_INTERNAL_ERROR,
            StartupUtils::GetErrorMessage(ERR_STARTUP_INTERNAL_ERROR));
    }
    if (result->GetResultCode() != ERR_OK) {
        return CreateJsError(env, result->GetResultCode(), result->GetResultMessage());
    }
    return CreateJsNull(env);
}
} // namespace AbilityRuntime
} // namespace OHOS
