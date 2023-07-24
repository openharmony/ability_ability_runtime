/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "js_action_extension.h"

#include <type_traits>
#include <vector>

#include "ability_info.h"
#include "ability_manager_client.h"
#include "hilog_wrapper.h"
#include "hitrace_meter.h"
#include "js_extension_common.h"
#include "js_extension_context.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "js_ui_extension_content_session.h"
#include "js_ui_extension_context.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "napi_common_configuration.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "napi_remote_object.h"
#include "ui_extension_window_command.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr size_t ARGC_ONE = 1;
constexpr size_t ARGC_TWO = 2;
}
NativeValue *AttachActionExtensionContext(NativeEngine *engine, void *value, void*)
{
    HILOG_DEBUG("called.");
    if (value == nullptr) {
        HILOG_ERROR("invalid parameter.");
        return nullptr;
    }

    auto ptr = reinterpret_cast<std::weak_ptr<UIExtensionContext>*>(value)->lock();
    if (ptr == nullptr) {
        HILOG_ERROR("invalid context.");
        return nullptr;
    }
    NativeValue *object = JsUIExtensionContext::CreateJsUIExtensionContext(*engine, ptr);
    if (object == nullptr) {
        HILOG_ERROR("create context error.");
        return nullptr;
    }
    auto contextObj = JsRuntime::LoadSystemModuleByEngine(engine, "application.UIExtensionContext", &object, 1)->Get();
    if (contextObj == nullptr) {
        HILOG_ERROR("load context error.");
        return nullptr;
    }
    NativeObject *nObject = ConvertNativeValueTo<NativeObject>(contextObj);
    if (nObject == nullptr) {
        HILOG_ERROR("convert context error.");
        return nullptr;
    }
    nObject->ConvertToNativeBindingObject(engine, DetachCallbackFunc, AttachActionExtensionContext, value, nullptr);

    auto workContext = new (std::nothrow) std::weak_ptr<UIExtensionContext>(ptr);
    nObject->SetNativePointer(
        workContext,
        [](NativeEngine*, void *data, void*) {
            HILOG_DEBUG("Finalizer for weak_ptr ui extension context is called");
            delete static_cast<std::weak_ptr<UIExtensionContext>*>(data);
        },
        nullptr);
    return contextObj;
}

JsActionExtension *JsActionExtension::Create(const std::unique_ptr<Runtime> &runtime)
{
    HILOG_DEBUG("call");
    return new JsActionExtension(static_cast<JsRuntime&>(*runtime));
}

JsActionExtension::JsActionExtension(JsRuntime &jsRuntime) : jsRuntime_(jsRuntime) {}

JsActionExtension::~JsActionExtension()
{
    HILOG_DEBUG("destructor.");
    auto context = GetContext();
    if (context) {
        context->Unbind();
    }

    jsRuntime_.FreeNativeReference(std::move(jsObj_));
    jsRuntime_.FreeNativeReference(std::move(shellContextRef_));
}

void JsActionExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application, std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    HILOG_DEBUG("called.");
    ActionExtension::Init(record, application, handler, token);
    std::string srcPath(Extension::abilityInfo_->moduleName + "/");
    srcPath.append(Extension::abilityInfo_->srcEntrance);
    srcPath.erase(srcPath.rfind('.'));
    srcPath.append(".abc");

    std::string moduleName(Extension::abilityInfo_->moduleName);
    moduleName.append("::").append(abilityInfo_->name);
    HILOG_DEBUG("JsActionExtension::Init moduleName:%{public}s,srcPath:%{public}s, compileMode :%{public}d.",
        moduleName.c_str(), srcPath.c_str(), abilityInfo_->compileMode);
    HandleScope handleScope(jsRuntime_);
    auto &engine = jsRuntime_.GetNativeEngine();

    jsObj_ = jsRuntime_.LoadModule(
        moduleName, srcPath, abilityInfo_->hapPath, abilityInfo_->compileMode == CompileMode::ES_MODULE);
    if (jsObj_ == nullptr) {
        HILOG_ERROR("Failed to get jsObj_");
        return;
    }

    NativeObject *obj = ConvertNativeValueTo<NativeObject>(jsObj_->Get());
    if (obj == nullptr) {
        HILOG_ERROR("Failed to get JsActionExtension object");
        return;
    }

    BindContext(engine, obj);
}

void JsActionExtension::BindContext(NativeEngine &engine, NativeObject *obj)
{
    auto context = GetContext();
    if (context == nullptr) {
        HILOG_ERROR("Failed to get context");
        return;
    }
    if (obj == nullptr) {
        HILOG_ERROR("Failed to get JsActionExtension object");
        return;
    }
    HILOG_DEBUG("BindContext CreateJsUIExtensionContext.");
    NativeValue *contextObj = JsUIExtensionContext::CreateJsUIExtensionContext(engine, context);
    if (contextObj == nullptr) {
        HILOG_ERROR("Create js ui extension context error.");
        return;
    }

    shellContextRef_ =
        JsRuntime::LoadSystemModuleByEngine(&engine, "application.UIExtensionContext", &contextObj, ARGC_ONE);
    contextObj = shellContextRef_->Get();
    NativeObject *nativeObj = ConvertNativeValueTo<NativeObject>(contextObj);
    if (nativeObj == nullptr) {
        HILOG_ERROR("Failed to get context native object");
        return;
    }
    auto workContext = new (std::nothrow) std::weak_ptr<UIExtensionContext>(context);
    nativeObj->ConvertToNativeBindingObject(&engine, DetachCallbackFunc, AttachActionExtensionContext,
        workContext, nullptr);
    context->Bind(jsRuntime_, shellContextRef_.get());
    obj->SetProperty("context", contextObj);

    nativeObj->SetNativePointer(workContext,
        [](NativeEngine*, void *data, void*) {
            HILOG_DEBUG("Finalizer for weak_ptr ui extension context is called");
            delete static_cast<std::weak_ptr<UIExtensionContext>*>(data);
        }, nullptr);
}

void JsActionExtension::OnStart(const AAFwk::Want &want)
{
    HILOG_DEBUG("called.");
    Extension::OnStart(want);
    HandleScope handleScope(jsRuntime_);
    NativeEngine *nativeEngine = &jsRuntime_.GetNativeEngine();
    if (nativeEngine == nullptr) {
        HILOG_ERROR("NativeEngine is nullptr.");
        return;
    }
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(reinterpret_cast<napi_env>(nativeEngine), want);
    NativeValue *nativeWant = reinterpret_cast<NativeValue*>(napiWant);
    if (nativeWant == nullptr) {
        HILOG_ERROR("Failed to get want");
        return;
    }
    NativeValue *argv[] = { nativeWant };
    CallObjectMethod("onCreate", argv, ARGC_ONE);
}

void JsActionExtension::OnStop()
{
    HILOG_DEBUG("called.");
    ActionExtension::OnStop();
    HandleScope handleScope(jsRuntime_);
    CallObjectMethod("onDestroy");
}

sptr<IRemoteObject> JsActionExtension::OnConnect(const AAFwk::Want &want)
{
    HandleScope handleScope(jsRuntime_);
    NativeValue *result = CallOnConnect(want);
    if (result == nullptr) {
        HILOG_ERROR("CallOnConnect failed.");
        return nullptr;
    }
    NativeEngine *nativeEngine = &jsRuntime_.GetNativeEngine();
    if (nativeEngine == nullptr) {
        HILOG_ERROR("NativeEngine is nullptr.");
        return nullptr;
    }
    auto remoteObj = NAPI_ohos_rpc_getNativeRemoteObject(
        reinterpret_cast<napi_env>(nativeEngine), reinterpret_cast<napi_value>(result));
    if (remoteObj == nullptr) {
        HILOG_ERROR("remoteObj is nullptr.");
    }
    return remoteObj;
}

void JsActionExtension::OnDisconnect(const AAFwk::Want &want)
{
    HILOG_DEBUG("called.");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    Extension::OnDisconnect(want);
    CallOnDisconnect(want, false);
}

void JsActionExtension::OnCommandWindow(
    const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo, AAFwk::WindowCommand winCmd)
{
    HILOG_DEBUG("begin. persistentId: %{private}d, winCmd: %{public}d", sessionInfo->persistentId, winCmd);
    if (sessionInfo == nullptr) {
        HILOG_ERROR("sessionInfo is nullptr.");
        return;
    }
    Extension::OnCommandWindow(want, sessionInfo, winCmd);
    switch (winCmd) {
        case AAFwk::WIN_CMD_FOREGROUND:
            ForegroundWindow(want, sessionInfo);
            break;
        case AAFwk::WIN_CMD_BACKGROUND:
            BackgroundWindow(sessionInfo);
            break;
        case AAFwk::WIN_CMD_DESTROY:
            DestroyWindow(sessionInfo);
            break;
        default:
            HILOG_DEBUG("unsupported cmd.");
            break;
    }
    auto context = GetContext();
    if (context == nullptr) {
        HILOG_ERROR("Failed to get context");
        return;
    }
    AAFwk::AbilityCommand abilityCmd;
    if (uiWindowMap_.empty()) {
        abilityCmd = AAFwk::ABILITY_CMD_DESTROY;
    } else if (foregroundWindows_.empty()) {
        abilityCmd = AAFwk::ABILITY_CMD_BACKGROUND;
    } else {
        abilityCmd = AAFwk::ABILITY_CMD_FOREGROUND;
    }
    AAFwk::AbilityManagerClient::GetInstance()->ScheduleCommandAbilityWindowDone(
        context->GetToken(), sessionInfo, winCmd, abilityCmd);
}

void JsActionExtension::OnCommand(const AAFwk::Want &want, bool restart, int32_t startId)
{
    Extension::OnCommand(want, restart, startId);
    HILOG_DEBUG("begin restart = %{public}s, startId = %{public}d.", restart ? "true" : "false", startId);
    HandleScope handleScope(jsRuntime_);
    NativeEngine *nativeEngine = &jsRuntime_.GetNativeEngine();
    if (nativeEngine == nullptr) {
        HILOG_ERROR("NativeEngine is nullptr.");
        return;
    }
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(reinterpret_cast<napi_env>(nativeEngine), want);
    NativeValue *nativeWant = reinterpret_cast<NativeValue*>(napiWant);
    if (nativeWant == nullptr) {
        HILOG_ERROR("Failed to get want");
        return;
    }
    napi_value napiStartId = nullptr;
    napi_create_int32(reinterpret_cast<napi_env>(nativeEngine), startId, &napiStartId);
    NativeValue *nativeStartId = reinterpret_cast<NativeValue*>(napiStartId);
    if (nativeStartId == nullptr) {
        HILOG_ERROR("Failed to get startId");
        return;
    }
    NativeValue *argv[] = { nativeWant, nativeStartId };
    CallObjectMethod("onRequest", argv, ARGC_TWO);
}

void JsActionExtension::OnForeground(const Want &want)
{
    HILOG_DEBUG("called.");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    Extension::OnForeground(want);
    HandleScope handleScope(jsRuntime_);
    CallObjectMethod("onForeground");
}

void JsActionExtension::OnBackground()
{
    HILOG_DEBUG("called.");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    HandleScope handleScope(jsRuntime_);
    CallObjectMethod("onBackground");
    Extension::OnBackground();
}

void JsActionExtension::ForegroundWindow(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo)
{
    HILOG_DEBUG("called.");
    if (sessionInfo == nullptr || sessionInfo->sessionToken == nullptr) {
        HILOG_ERROR("Invalid sessionInfo.");
        return;
    }
    auto obj = sessionInfo->sessionToken;
    if (uiWindowMap_.find(obj) == uiWindowMap_.end()) {
        sptr<Rosen::WindowOption> option = new Rosen::WindowOption();
        auto context = GetContext();
        if (context == nullptr || context->GetAbilityInfo() == nullptr) {
            HILOG_ERROR("Failed to get context");
            return;
        }
        option->SetWindowName(context->GetBundleName() + context->GetAbilityInfo()->name);
        option->SetWindowType(Rosen::WindowType::WINDOW_TYPE_UI_EXTENSION);
        option->SetWindowSessionType(Rosen::WindowSessionType::EXTENSION_SESSION);
        auto uiWindow = Rosen::Window::Create(option, GetContext(), sessionInfo->sessionToken);
        if (uiWindow == nullptr) {
            HILOG_ERROR("create ui window error.");
            return;
        }
        HandleScope handleScope(jsRuntime_);
        NativeEngine *nativeEngine = &jsRuntime_.GetNativeEngine();
        if (nativeEngine == nullptr) {
            HILOG_ERROR("NativeEngine is nullptr.");
            return;
        }
        napi_value napiWant = OHOS::AppExecFwk::WrapWant(reinterpret_cast<napi_env>(nativeEngine), want);
        NativeValue *nativeWant = reinterpret_cast<NativeValue*>(napiWant);
        if (nativeWant == nullptr) {
            HILOG_ERROR("Failed to get want");
            return;
        }
        NativeValue *nativeContentSession =
            JsUIExtensionContentSession::CreateJsUIExtensionContentSession(*nativeEngine, sessionInfo, uiWindow);
        if (nativeContentSession == nullptr) {
            HILOG_ERROR("Failed to get contentSession");
            return;
        }
        contentSessions_.emplace(
            obj, std::shared_ptr<NativeReference>(nativeEngine->CreateReference(nativeContentSession, 1)));
        NativeValue *argv[] = { nativeWant, nativeContentSession };
        CallObjectMethod("onSessionCreate", argv, ARGC_TWO);
        uiWindowMap_[obj] = uiWindow;
    }
    auto &uiWindow = uiWindowMap_[obj];
    if (uiWindow) {
        uiWindow->Show();
        foregroundWindows_.emplace(obj);
    }
}

void JsActionExtension::BackgroundWindow(const sptr<AAFwk::SessionInfo> &sessionInfo)
{
    HILOG_DEBUG("called.");
    if (sessionInfo == nullptr || sessionInfo->sessionToken == nullptr) {
        HILOG_ERROR("Invalid sessionInfo.");
        return;
    }
    auto obj = sessionInfo->sessionToken;
    if (uiWindowMap_.find(obj) == uiWindowMap_.end()) {
        HILOG_ERROR("Fail to find uiWindow");
        return;
    }
    auto &uiWindow = uiWindowMap_[obj];
    if (uiWindow) {
        uiWindow->Hide();
        foregroundWindows_.erase(obj);
    }
}

void JsActionExtension::DestroyWindow(const sptr<AAFwk::SessionInfo> &sessionInfo)
{
    HILOG_DEBUG("called.");
    if (sessionInfo == nullptr || sessionInfo->sessionToken == nullptr) {
        HILOG_ERROR("Invalid sessionInfo.");
        return;
    }
    auto obj = sessionInfo->sessionToken;
    if (uiWindowMap_.find(obj) == uiWindowMap_.end()) {
        HILOG_ERROR("Fail to find uiWindow");
        return;
    }
    if (contentSessions_.find(obj) != contentSessions_.end() && contentSessions_[obj] != nullptr) {
        HandleScope handleScope(jsRuntime_);
        NativeValue *argv[] = {contentSessions_[obj]->Get()};
        CallObjectMethod("onSessionDestroy", argv, ARGC_ONE);
    }
    auto &uiWindow = uiWindowMap_[obj];
    if (uiWindow) {
        uiWindow->Destroy();
    }
    uiWindowMap_.erase(obj);
    foregroundWindows_.erase(obj);
    contentSessions_.erase(obj);
}

NativeValue *JsActionExtension::CallObjectMethod(const char *name, NativeValue *const *argv, size_t argc)
{
    HILOG_DEBUG("CallObjectMethod(%{public}s), begin", name);
    auto &nativeEngine = jsRuntime_.GetNativeEngine();
    NativeValue *value = jsObj_->Get();
    NativeObject *obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        HILOG_ERROR("Failed to get UIExtension object");
        return nullptr;
    }

    NativeValue *method = obj->GetProperty(name);
    if (method == nullptr || method->TypeOf() != NATIVE_FUNCTION) {
        HILOG_ERROR("Failed to get '%{public}s' from UIExtension object", name);
        return nullptr;
    }
    HILOG_DEBUG("JsActionExtension CallFunction(%{public}s), success", name);
    return nativeEngine.CallFunction(value, method, argv, argc);
}

NativeValue *JsActionExtension::CallOnConnect(const AAFwk::Want &want)
{
    HILOG_DEBUG("called.");
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    Extension::OnConnect(want);
    HandleScope handleScope(jsRuntime_);
    NativeEngine *nativeEngine = &jsRuntime_.GetNativeEngine();
    if (nativeEngine == nullptr) {
        HILOG_ERROR("NativeEngine is nullptr.");
        return nullptr;
    }
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(reinterpret_cast<napi_env>(nativeEngine), want);
    auto *nativeWant = reinterpret_cast<NativeValue*>(napiWant);
    if (nativeWant == nullptr) {
        HILOG_ERROR("Failed to get want");
        return nullptr;
    }
    NativeValue *argv[] = { nativeWant };
    if (!jsObj_) {
        HILOG_ERROR("Not found UIExtension.js");
        return nullptr;
    }

    NativeValue *value = jsObj_->Get();
    auto *obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        HILOG_ERROR("Failed to get UIExtension object");
        return nullptr;
    }

    NativeValue *method = obj->GetProperty("onConnect");
    if (method == nullptr) {
        HILOG_ERROR("Failed to get onConnect from UIExtension object");
        return nullptr;
    }
    NativeValue *remoteNative = nativeEngine->CallFunction(value, method, argv, ARGC_ONE);
    if (remoteNative == nullptr) {
        HILOG_ERROR("remoteNative is nullptr.");
    }
    return remoteNative;
}

NativeValue *JsActionExtension::CallOnDisconnect(const AAFwk::Want &want, bool withResult)
{
    HandleEscape handleEscape(jsRuntime_);
    NativeEngine *nativeEngine = &jsRuntime_.GetNativeEngine();
    if (nativeEngine == nullptr) {
        HILOG_ERROR("NativeEngine is nullptr.");
        return nullptr;
    }
    napi_value napiWant = OHOS::AppExecFwk::WrapWant(reinterpret_cast<napi_env>(nativeEngine), want);
    NativeValue *nativeWant = reinterpret_cast<NativeValue*>(napiWant);
    if (nativeWant == nullptr) {
        HILOG_ERROR("Failed to get want");
        return nullptr;
    }
    NativeValue *argv[] = { nativeWant };
    if (!jsObj_) {
        HILOG_ERROR("Not found UIExtension.js");
        return nullptr;
    }

    NativeValue *value = jsObj_->Get();
    NativeObject *obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        HILOG_ERROR("Failed to get UIExtension object");
        return nullptr;
    }

    NativeValue *method = obj->GetProperty("onDisconnect");
    if (method == nullptr) {
        HILOG_ERROR("Failed to get onDisconnect from UIExtension object");
        return nullptr;
    }

    if (withResult) {
        return handleEscape.Escape(nativeEngine->CallFunction(value, method, argv, ARGC_ONE));
    } else {
        nativeEngine->CallFunction(value, method, argv, ARGC_ONE);
        return nullptr;
    }
}

void JsActionExtension::OnConfigurationUpdated(const AppExecFwk::Configuration &configuration)
{
    HILOG_DEBUG("called.");
    Extension::OnConfigurationUpdated(configuration);

    HandleScope handleScope(jsRuntime_);
    auto &nativeEngine = jsRuntime_.GetNativeEngine();

    auto fullConfig = GetContext()->GetConfiguration();
    if (!fullConfig) {
        HILOG_ERROR("configuration is nullptr.");
        return;
    }
    JsExtensionContext::ConfigurationUpdated(&nativeEngine, shellContextRef_, fullConfig);

    napi_value napiConfiguration = OHOS::AppExecFwk::WrapConfiguration(
        reinterpret_cast<napi_env>(&nativeEngine), *fullConfig);
    NativeValue *jsConfiguration = reinterpret_cast<NativeValue*>(napiConfiguration);
    if (jsConfiguration == nullptr) {
        HILOG_ERROR("Failed to get configuration.");
        return;
    }
    CallObjectMethod("onConfigurationUpdate", &jsConfiguration, ARGC_ONE);
}

void JsActionExtension::Dump(const std::vector<std::string> &params, std::vector<std::string> &info)
{
    HILOG_DEBUG("called.");
    Extension::Dump(params, info);
    HandleScope handleScope(jsRuntime_);
    auto &nativeEngine = jsRuntime_.GetNativeEngine();
    NativeValue *arrayValue = nativeEngine.CreateArray(params.size());
    if (arrayValue == nullptr) {
        HILOG_ERROR("create array failed");
        return;
    }
    NativeArray *array = ConvertNativeValueTo<NativeArray>(arrayValue);
    if (array == nullptr) {
        HILOG_ERROR("convert array failed");
        return;
    }
    uint32_t index = 0;
    for (const auto &param : params) {
        array->SetElement(index++, CreateJsValue(nativeEngine, param));
    }
    NativeValue *argv[] = { arrayValue };

    if (!jsObj_) {
        HILOG_ERROR("Not found UIExtension.js");
        return;
    }

    NativeValue *value = jsObj_->Get();
    NativeObject *obj = ConvertNativeValueTo<NativeObject>(value);
    if (obj == nullptr) {
        HILOG_ERROR("Failed to get UIExtension object");
        return;
    }

    NativeValue *method = obj->GetProperty("onDump");
    if (method == nullptr || method->TypeOf() != NATIVE_FUNCTION) {
        method = obj->GetProperty("dump");
        if (method == nullptr || method->TypeOf() != NATIVE_FUNCTION) {
            HILOG_ERROR("Failed to get onDump from UIExtension object");
            return;
        }
    }
    NativeValue *dumpInfo = nativeEngine.CallFunction(value, method, argv, ARGC_ONE);
    if (dumpInfo == nullptr) {
        HILOG_ERROR("dumpInfo is nullptr.");
        return;
    }
    NativeArray *dumpInfoNative = ConvertNativeValueTo<NativeArray>(dumpInfo);
    if (dumpInfoNative == nullptr) {
        HILOG_ERROR("dumpInfoNative is nullptr.");
        return;
    }
    for (uint32_t i = 0; i < dumpInfoNative->GetLength(); i++) {
        std::string dumpInfoStr;
        if (!ConvertFromJsValue(nativeEngine, dumpInfoNative->GetElement(i), dumpInfoStr)) {
            HILOG_ERROR("Parse dumpInfoStr failed");
            return;
        }
        info.push_back(dumpInfoStr);
    }
    HILOG_DEBUG("Dump info size: %{public}zu", info.size());
}

void JsActionExtension::OnAbilityResult(int32_t requestCode, int32_t resultCode, const Want &resultData)
{
    HILOG_DEBUG("called.");
    Extension::OnAbilityResult(requestCode, resultCode, resultData);
    auto context = GetContext();
    if (context == nullptr) {
        HILOG_WARN("not attached to any runtime context!");
        return;
    }
    context->OnAbilityResult(requestCode, resultCode, resultData);
}
} // namespace AbilityRuntime
} // namespace OHOS
