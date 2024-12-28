/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "js_ability_stage.h"

#include "ability_delegator_registry.h"
#include "freeze_util.h"
#include "hilog_tag_wrapper.h"
#include "js_ability_stage_context.h"
#include "js_context_utils.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "js_startup_config.h"
#include "napi_common_configuration.h"
#include "napi_common_util.h"
#include "napi_common_want.h"
#include "ohos_application.h"
#include "startup_manager.h"
#include "hitrace_meter.h"
#include <algorithm>
#include <cstring>
#include <exception>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

namespace OHOS {
namespace AbilityRuntime {
constexpr const char* PROFILE_FILE_PREFIX = "$profile:";
constexpr const char* STARTUP_TASKS = "startupTasks";
constexpr const char* NAME = "name";
constexpr const char* SRC_ENTRY = "srcEntry";
constexpr const char* DEPENDENCIES = "dependencies";
constexpr const char* EXCLUDE_FROM_AUTO_START = "excludeFromAutoStart";
constexpr const char* RUN_ON_THREAD = "runOnThread";
constexpr const char* WAIT_ON_MAIN_THREAD = "waitOnMainThread";
constexpr const char* CONFIG_ENTRY = "configEntry";
constexpr const char *TASKPOOL = "taskPool";
constexpr const char *TASKPOOL_LOWER = "taskpool";
namespace {
void RegisterStopPreloadSoCallback(JsRuntime& jsRuntime)
{
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    if (startupManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startupManager");
        return;
    }
    if (!startupManager->HasAppStartupConfig()) {
        // no app startup config, no need to register stop preload so callback.
        return;
    }
    jsRuntime.SetStopPreloadSoCallback([]()-> void {
        std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
        if (startupManager == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null startupManager");
            return;
        }
        startupManager->StopAutoPreloadSoTask();
    });
}
} // namespace

bool JsAbilityStage::UseCommonChunk(const AppExecFwk::HapModuleInfo& hapModuleInfo)
{
    for (auto &md: hapModuleInfo.metadata) {
        if (md.name == "USE_COMMON_CHUNK") {
            if (md.value != "true") {
                TAG_LOGW(AAFwkTag::APPKIT, "USE_COMMON_CHUNK = %s{public}s", md.value.c_str());
                return false;
            }
            return true;
        }
    }
    return false;
}

std::shared_ptr<AbilityStage> JsAbilityStage::Create(
    const std::unique_ptr<Runtime>& runtime, const AppExecFwk::HapModuleInfo& hapModuleInfo)
{
    if (runtime == nullptr) {
        TAG_LOGW(AAFwkTag::APPKIT, "null runtime");
        return nullptr;
    }
    FreezeUtil::GetInstance().AddAppLifecycleEvent(0, "JsAbilityStage::Create");
    auto& jsRuntime = static_cast<JsRuntime&>(*runtime);
    std::string srcPath(hapModuleInfo.name);
    std::string moduleName(hapModuleInfo.moduleName);
    moduleName.append("::").append("AbilityStage");
    bool commonChunkFlag = UseCommonChunk(hapModuleInfo);
    RegisterStopPreloadSoCallback(jsRuntime);
    /* temporary compatibility api8 + config.json */
    if (!hapModuleInfo.isModuleJson) {
        srcPath.append("/assets/js/");
        if (hapModuleInfo.srcPath.empty()) {
            srcPath.append("AbilityStage.abc");
        } else {
            srcPath.append(hapModuleInfo.srcPath);
            srcPath.append("/AbilityStage.abc");
        }
        std::string key(moduleName);
        key.append("::");
        key.append(srcPath);
        std::unique_ptr<NativeReference> moduleObj = nullptr;
        if (jsRuntime.PopPreloadObj(key, moduleObj)) {
            return std::make_shared<JsAbilityStage>(jsRuntime, std::move(moduleObj));
        } else {
            auto moduleObj = jsRuntime.LoadModule(moduleName, srcPath, hapModuleInfo.hapPath,
                hapModuleInfo.compileMode == AppExecFwk::CompileMode::ES_MODULE, commonChunkFlag);
            return std::make_shared<JsAbilityStage>(jsRuntime, std::move(moduleObj));
        }
    }

    std::unique_ptr<NativeReference> moduleObj;
    srcPath.append("/");
    if (!hapModuleInfo.srcEntrance.empty()) {
        srcPath.append(hapModuleInfo.srcEntrance);
        srcPath.erase(srcPath.rfind("."));
        srcPath.append(".abc");
        moduleObj = jsRuntime.LoadModule(moduleName, srcPath, hapModuleInfo.hapPath,
            hapModuleInfo.compileMode == AppExecFwk::CompileMode::ES_MODULE, commonChunkFlag);
        TAG_LOGD(AAFwkTag::APPKIT, "srcPath is %{public}s", srcPath.c_str());
    }
    return std::make_shared<JsAbilityStage>(jsRuntime, std::move(moduleObj));
}

JsAbilityStage::JsAbilityStage(JsRuntime& jsRuntime, std::unique_ptr<NativeReference>&& jsAbilityStageObj)
    : jsRuntime_(jsRuntime), jsAbilityStageObj_(std::move(jsAbilityStageObj))
{}

JsAbilityStage::~JsAbilityStage()
{
    auto context = GetContext();
    if (context) {
        context->Unbind();
    }

    jsRuntime_.FreeNativeReference(std::move(jsAbilityStageObj_));
    jsRuntime_.FreeNativeReference(std::move(shellContextRef_));
}

void JsAbilityStage::Init(const std::shared_ptr<Context> &context,
    const std::weak_ptr<AppExecFwk::OHOSApplication> application)
{
    AbilityStage::Init(context, application);

    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        return;
    }

    if (!jsAbilityStageObj_) {
        TAG_LOGE(AAFwkTag::APPKIT, "null stage");
        return;
    }

    SetJsAbilityStage(context);
}

void JsAbilityStage::OnCreate(const AAFwk::Want &want) const
{
    AbilityStage::OnCreate(want);

    if (!jsAbilityStageObj_) {
        TAG_LOGW(AAFwkTag::APPKIT, "Not found AbilityStage.js");
        return;
    }

    HandleScope handleScope(jsRuntime_);
    auto env = jsRuntime_.GetNapiEnv();

    napi_value obj = jsAbilityStageObj_->GetNapiValue();
    if (!CheckTypeForNapiValue(env, obj, napi_object)) {
        TAG_LOGE(AAFwkTag::APPKIT, "get object failed");
        return;
    }

    napi_value methodOnCreate = nullptr;
    napi_get_named_property(env, obj, "onCreate", &methodOnCreate);
    if (methodOnCreate == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null methodOnCreate");
        return;
    }
    FreezeUtil::GetInstance().AddAppLifecycleEvent(0, "JsAbilityStage::OnCreate begin");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    napi_call_function(env, obj, methodOnCreate, 0, nullptr, nullptr);
    FreezeUtil::GetInstance().AddAppLifecycleEvent(0, "JsAbilityStage::OnCreate end");

    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator();
    if (delegator) {
        delegator->PostPerformStageStart(CreateStageProperty());
    }
}

void JsAbilityStage::OnDestroy() const
{
    TAG_LOGD(AAFwkTag::APPKIT, "Called");
    AbilityStage::OnDestroy();

    if (!jsAbilityStageObj_) {
        TAG_LOGW(AAFwkTag::APPKIT, "Not found AbilityStage.js");
        return;
    }

    HandleScope handleScope(jsRuntime_);
    auto env = jsRuntime_.GetNapiEnv();

    napi_value obj = jsAbilityStageObj_->GetNapiValue();
    if (!CheckTypeForNapiValue(env, obj, napi_object)) {
        TAG_LOGE(AAFwkTag::APPKIT, "get object failed");
        return;
    }

    napi_value methodOnDestroy = nullptr;
    napi_get_named_property(env, obj, "onDestroy", &methodOnDestroy);
    if (methodOnDestroy == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null methodOnDestroy");
        return;
    }
    napi_call_function(env, obj, methodOnDestroy, 0, nullptr, nullptr);
}

bool JsAbilityStage::OnPrepareTerminate(int32_t &prepareTermination) const
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    AbilityStage::OnPrepareTerminate(prepareTermination);

    if (!jsAbilityStageObj_) {
        TAG_LOGW(AAFwkTag::APPKIT, "Not found AbilityStage.js");
        return false;
    }

    HandleScope handleScope(jsRuntime_);
    auto env = jsRuntime_.GetNapiEnv();

    napi_value obj = jsAbilityStageObj_->GetNapiValue();
    if (!CheckTypeForNapiValue(env, obj, napi_object)) {
        TAG_LOGE(AAFwkTag::APPKIT, "Fail to get AbilityStage object");
        return false;
    }

    napi_value methodOnPrepareTerminate = nullptr;
    napi_get_named_property(env, obj, "onPrepareTermination", &methodOnPrepareTerminate);
    if (methodOnPrepareTerminate == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "onPrepareTermination is unimplemented");
        return false;
    }
    TAG_LOGI(AAFwkTag::APPKIT, "onPrepareTermination is implemented");
    napi_value result = nullptr;
    napi_call_function(env, obj, methodOnPrepareTerminate, 0, nullptr, &result);
    if (!ConvertFromJsValue(env, result, prepareTermination)) {
        TAG_LOGE(AAFwkTag::APPKIT, "Fail to unwrap prepareTermination result");
        return false;
    }
    return true;
}

std::string JsAbilityStage::OnAcceptWant(const AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    AbilityStage::OnAcceptWant(want);

    if (!jsAbilityStageObj_) {
        TAG_LOGW(AAFwkTag::APPKIT, "Not found AbilityStage.js");
        return "";
    }

    HandleScope handleScope(jsRuntime_);
    auto env = jsRuntime_.GetNapiEnv();

    napi_value obj = jsAbilityStageObj_->GetNapiValue();
    if (!CheckTypeForNapiValue(env, obj, napi_object)) {
        TAG_LOGE(AAFwkTag::APPKIT, "get object failed");
        return "";
    }

    napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
    napi_value methodOnAcceptWant = nullptr;
    napi_get_named_property(env, obj, "onAcceptWant", &methodOnAcceptWant);
    if (methodOnAcceptWant == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null methodOnAcceptWant");
        return "";
    }

    napi_value argv[] = { napiWant };
    napi_value flagNative = nullptr;
    napi_call_function(env, obj, methodOnAcceptWant, 1, argv, &flagNative);
    return AppExecFwk::UnwrapStringFromJS(env, flagNative);
}

std::string JsAbilityStage::OnNewProcessRequest(const AAFwk::Want &want)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    AbilityStage::OnNewProcessRequest(want);

    if (!jsAbilityStageObj_) {
        TAG_LOGW(AAFwkTag::APPKIT, "Not found AbilityStage.js");
        return "";
    }

    HandleScope handleScope(jsRuntime_);
    auto env = jsRuntime_.GetNapiEnv();

    napi_value obj = jsAbilityStageObj_->GetNapiValue();
    if (!CheckTypeForNapiValue(env, obj, napi_object)) {
        TAG_LOGE(AAFwkTag::APPKIT, "get object failed");
        return "";
    }

    napi_value napiWant = OHOS::AppExecFwk::WrapWant(env, want);
    napi_value methodOnNewProcessRequest = nullptr;
    napi_get_named_property(env, obj, "onNewProcessRequest", &methodOnNewProcessRequest);
    if (methodOnNewProcessRequest == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null methodOnNewProcessRequest");
        return "";
    }

    napi_value argv[] = { napiWant };
    napi_value flagNative = nullptr;
    napi_call_function(env, obj, methodOnNewProcessRequest, 1, argv, &flagNative);
    return AppExecFwk::UnwrapStringFromJS(env, flagNative);
}

void JsAbilityStage::OnConfigurationUpdated(const AppExecFwk::Configuration& configuration)
{
    AbilityStage::OnConfigurationUpdated(configuration);

    HandleScope handleScope(jsRuntime_);
    auto env = jsRuntime_.GetNapiEnv();
    auto application = application_.lock();
    if (application == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null application");
        return;
    }
    // Notify Ability stage context
    auto fullConfig = application->GetConfiguration();
    if (!fullConfig) {
        TAG_LOGE(AAFwkTag::APPKIT, "null fullConfig");
        return;
    }
    JsAbilityStageContext::ConfigurationUpdated(env, shellContextRef_, fullConfig);

    napi_value napiConfiguration = OHOS::AppExecFwk::WrapConfiguration(env, *fullConfig);
    CallObjectMethod("onConfigurationUpdated", &napiConfiguration, 1);
    CallObjectMethod("onConfigurationUpdate", &napiConfiguration, 1);
}

void JsAbilityStage::OnMemoryLevel(int32_t level)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    AbilityStage::OnMemoryLevel(level);

    if (!jsAbilityStageObj_) {
        TAG_LOGW(AAFwkTag::APPKIT, "Not found stage");
        return;
    }

    HandleScope handleScope(jsRuntime_);
    auto env = jsRuntime_.GetNapiEnv();

    napi_value obj = jsAbilityStageObj_->GetNapiValue();
    if (!CheckTypeForNapiValue(env, obj, napi_object)) {
        TAG_LOGE(AAFwkTag::APPKIT, "get object failed");
        return;
    }

    napi_value jsLevel = CreateJsValue(env, level);
    napi_value argv[] = { jsLevel };
    CallObjectMethod("onMemoryLevel", argv, ArraySize(argv));
    TAG_LOGD(AAFwkTag::APPKIT, "end");
}

int32_t JsAbilityStage::RunAutoStartupTask(const std::function<void()> &callback, bool &isAsyncCallback,
    const std::shared_ptr<Context> &stageContext)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    isAsyncCallback = false;
    auto context = GetContext();
    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        return ERR_INVALID_VALUE;
    }
    auto hapModuleInfo = context->GetHapModuleInfo();
    if (!hapModuleInfo) {
        TAG_LOGE(AAFwkTag::APPKIT, "null hapModuleInfo");
        return ERR_INVALID_VALUE;
    }
    if (hapModuleInfo->moduleType != AppExecFwk::ModuleType::ENTRY) {
        TAG_LOGD(AAFwkTag::APPKIT, "not entry module");
        return ERR_INVALID_VALUE;
    }
    if (hapModuleInfo->appStartup.empty()) {
        TAG_LOGD(AAFwkTag::APPKIT, "entry module no app startup config");
        return ERR_INVALID_VALUE;
    }
    if (!shellContextRef_) {
        SetJsAbilityStage(stageContext);
    }
    int32_t result = RegisterAppStartupTask(hapModuleInfo);
    if (result != ERR_OK) {
        return result;
    }
    return RunAutoStartupTaskInner(callback, isAsyncCallback);
}

int32_t JsAbilityStage::RegisterAppStartupTask(const std::shared_ptr<AppExecFwk::HapModuleInfo>& hapModuleInfo)
{
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    if (startupManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startupManager");
        return ERR_INVALID_VALUE;
    }
    bool needRunAutoStartupTask = false;
    int32_t result = startupManager->LoadAppStartupTaskConfig(needRunAutoStartupTask);
    if (result != ERR_OK) {
        return result;
    }
    if (!needRunAutoStartupTask) {
        return ERR_OK;
    }
    jsRuntime_.UpdateModuleNameAndAssetPath(hapModuleInfo->moduleName);

    const std::string &configEntry = startupManager->GetPendingConfigEntry();
    if (!LoadJsStartupConfig(configEntry)) {
        TAG_LOGE(AAFwkTag::APPKIT, "load js appStartup config failed.");
        return ERR_INVALID_VALUE;
    }

    const std::vector<StartupTaskInfo> &startupTaskInfos = startupManager->GetStartupTaskInfos();
    for (const auto& item : startupTaskInfos) {
        std::unique_ptr<NativeReference> startupJsRef = LoadJsOhmUrl(
            item.srcEntry, item.ohmUrl, item.moduleName, item.hapPath, item.esModule);
        if (startupJsRef == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "load js appStartup tasks failed.");
            continue;
        }
        auto jsStartupTask = std::make_shared<JsStartupTask>(item.name, jsRuntime_, startupJsRef, shellContextRef_);
        jsStartupTask->SetDependencies(item.dependencies);
        jsStartupTask->SetIsExcludeFromAutoStart(item.excludeFromAutoStart);
        jsStartupTask->SetCallCreateOnMainThread(item.callCreateOnMainThread);
        jsStartupTask->SetWaitOnMainThread(item.waitOnMainThread);
        startupManager->RegisterAppStartupTask(item.name, jsStartupTask);
    }
    return ERR_OK;
}

int32_t JsAbilityStage::RunAutoStartupTaskInner(const std::function<void()> &callback, bool &isAsyncCallback)
{
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    if (startupManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startupManager");
        return ERR_INVALID_VALUE;
    }
    std::shared_ptr<StartupTaskManager> startupTaskManager = nullptr;
    int32_t result = startupManager->BuildAutoAppStartupTaskManager(startupTaskManager);
    if (result != ERR_OK) {
        return result;
    }
    result = startupTaskManager->Prepare();
    if (result != ERR_OK) {
        return result;
    }
    auto runAutoStartupCallback = std::make_shared<OnCompletedCallback>(
        [callback](const std::shared_ptr<StartupTaskResult> &) {
            TAG_LOGI(AAFwkTag::APPKIT, "RunAutoStartupCallback");
            callback();
        });
    result = startupTaskManager->Run(runAutoStartupCallback);
    if (result != ERR_OK) {
        isAsyncCallback = runAutoStartupCallback->IsCalled();
        return result;
    }
    isAsyncCallback = true;
    return ERR_OK;
}

std::unique_ptr<NativeReference> JsAbilityStage::LoadJsOhmUrl(const std::string &srcEntry, const std::string &ohmUrl,
    const std::string &moduleName, const std::string &hapPath, bool esmodule)
{
    TAG_LOGD(AAFwkTag::APPKIT, "call");
    if (srcEntry.empty() && ohmUrl.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "srcEntry and ohmUrl empty");
        return nullptr;
    }

    std::string moduleNameWithStartupTask = moduleName + "::startupTask";
    std::string srcPath(moduleName + "/" + srcEntry);
    auto pos = srcPath.rfind('.');
    if (pos == std::string::npos) {
        return nullptr;
    }
    srcPath.erase(pos);
    srcPath.append(".abc");
    std::unique_ptr<NativeReference> jsCode(
        jsRuntime_.LoadModule(moduleNameWithStartupTask, srcPath, hapPath, esmodule, false, ohmUrl));
    return jsCode;
}

std::unique_ptr<NativeReference> JsAbilityStage::LoadJsSrcEntry(const std::string &srcEntry)
{
    TAG_LOGD(AAFwkTag::APPKIT, "call");
    if (srcEntry.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "srcEntry invalid");
        return nullptr;
    }
    auto context = GetContext();
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
    std::string moduleName(hapModuleInfo->moduleName);
    std::string srcPath(moduleName + "/" + srcEntry);

    auto pos = srcPath.rfind('.');
    if (pos == std::string::npos) {
        return nullptr;
    }
    srcPath.erase(pos);
    srcPath.append(".abc");

    std::unique_ptr<NativeReference> jsCode(
        jsRuntime_.LoadModule(moduleName, srcPath, hapModuleInfo->hapPath, esmodule));
    return jsCode;
}

bool JsAbilityStage::LoadJsStartupConfig(const std::string &srcEntry)
{
    std::unique_ptr<NativeReference> startupConfigEntry = LoadJsSrcEntry(srcEntry);
    if (startupConfigEntry == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startupConfigEntry");
        return false;
    }
    auto env = jsRuntime_.GetNapiEnv();
    std::shared_ptr<JsStartupConfig> startupConfig = std::make_shared<JsStartupConfig>(env);
    if (startupConfig == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startupConfig");
        return false;
    }
    if (startupConfig->Init(startupConfigEntry) != ERR_OK) {
        return false;
    }
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    if (startupManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startupManager");
        return false;
    }
    startupManager->SetDefaultConfig(startupConfig);
    return true;
}

napi_value JsAbilityStage::CallObjectMethod(const char* name, napi_value const * argv, size_t argc)
{
    TAG_LOGD(AAFwkTag::APPKIT, "call %{public}s", name);
    if (!jsAbilityStageObj_) {
        TAG_LOGW(AAFwkTag::APPKIT, "Not found AbilityStage.js");
        return nullptr;
    }

    HandleScope handleScope(jsRuntime_);
    auto env = jsRuntime_.GetNapiEnv();

    napi_value obj = jsAbilityStageObj_->GetNapiValue();
    if (!CheckTypeForNapiValue(env, obj, napi_object)) {
        TAG_LOGE(AAFwkTag::APPKIT, "get object failed");
        return nullptr;
    }

    napi_value method = nullptr;
    napi_get_named_property(env, obj, name, &method);
    if (!CheckTypeForNapiValue(env, method, napi_function)) {
        TAG_LOGE(AAFwkTag::APPKIT, "get '%{public}s' object failed", name);
        return nullptr;
    }

    napi_value result = nullptr;
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    napi_call_function(env, obj, method, argc, argv, &result);
    return result;
}

std::shared_ptr<AppExecFwk::DelegatorAbilityStageProperty> JsAbilityStage::CreateStageProperty() const
{
    auto property = std::make_shared<AppExecFwk::DelegatorAbilityStageProperty>();
    property->moduleName_ = GetHapModuleProp("name");
    property->srcEntrance_ = GetHapModuleProp("srcEntrance");
    property->object_ = jsAbilityStageObj_;
    return property;
}

std::string JsAbilityStage::GetHapModuleProp(const std::string &propName) const
{
    auto context = GetContext();
    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        return std::string();
    }
    auto hapModuleInfo = context->GetHapModuleInfo();
    if (!hapModuleInfo) {
        TAG_LOGE(AAFwkTag::APPKIT, "null hapModuleInfo");
        return std::string();
    }
    if (propName.compare("name") == 0) {
        return hapModuleInfo->name;
    }
    if (propName.compare("srcEntrance") == 0) {
        return hapModuleInfo->srcEntrance;
    }
    TAG_LOGE(AAFwkTag::APPKIT, "name = %{public}s", propName.c_str());
    return std::string();
}

void JsAbilityStage::SetJsAbilityStage(const std::shared_ptr<Context> &context)
{
    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        return;
    }

    HandleScope handleScope(jsRuntime_);
    auto env = jsRuntime_.GetNapiEnv();

    napi_value obj = nullptr;
    if (jsAbilityStageObj_) {
        obj = jsAbilityStageObj_->GetNapiValue();
        if (!CheckTypeForNapiValue(env, obj, napi_object)) {
            TAG_LOGE(AAFwkTag::APPKIT, "get object failed");
            return;
        }
    }

    napi_value contextObj = CreateJsAbilityStageContext(env, context);
    shellContextRef_ = JsRuntime::LoadSystemModuleByEngine(env, "application.AbilityStageContext", &contextObj, 1);
    if (shellContextRef_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null shellContextRef_");
        return;
    }
    contextObj = shellContextRef_->GetNapiValue();
    if (!CheckTypeForNapiValue(env, contextObj, napi_object)) {
        TAG_LOGE(AAFwkTag::APPKIT, "get object failed");
        return;
    }
    auto workContext = new (std::nothrow) std::weak_ptr<AbilityRuntime::Context>(context);
    napi_coerce_to_native_binding_object(
        env, contextObj, DetachCallbackFunc, AttachAbilityStageContext, workContext, nullptr);
    context->Bind(jsRuntime_, shellContextRef_.get());

    if (obj != nullptr) {
        napi_set_named_property(env, obj, "context", contextObj);
    }
    TAG_LOGD(AAFwkTag::APPKIT, "Set ability stage context");
    napi_status status = napi_wrap(env, contextObj, workContext,
        [](napi_env, void* data, void*) {
            TAG_LOGD(AAFwkTag::APPKIT, "Finalizer for weak_ptr ability stage context is called");
            delete static_cast<std::weak_ptr<AbilityRuntime::Context>*>(data);
        },
        nullptr, nullptr);
    if (status != napi_ok && workContext != nullptr) {
        TAG_LOGD(AAFwkTag::APPKIT, "napi_wrap Failed: %{public}d", status);
        delete workContext;
        return;
    }
}
}  // namespace AbilityRuntime
}  // namespace OHOS
