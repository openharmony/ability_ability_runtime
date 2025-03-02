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

#include <cstdio>
#include <cstring>
#include <fcntl.h>

#include <sys/stat.h>

#include "ohos_application.h"

#include "ability.h"
#include "ability_record_mgr.h"
#include "ability_thread.h"
#include "app_loader.h"
#include "application_context.h"
#include "application_cleaner.h"
#include "application_impl.h"
#include "bundle_mgr_helper.h"
#include "configuration_utils.h"
#include "context_impl.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "iservice_registry.h"
#include "runtime.h"
#include "system_ability_definition.h"
#include "syspara/parameter.h"
#include "ui_ability.h"
#include "application_configuration_manager.h"
#ifdef SUPPORT_GRAPHICS
#include "window.h"
#endif
#include "runtime/include/mock/ani/ani.h"
#include "sts_runtime.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    constexpr const char* PERSIST_DARKMODE_KEY = "persist.ace.darkmode";
    constexpr const char* STS_APPLICATION_CONTEXT_CLASS_NAME = "LApplicationContext/ApplicationContext;";
}
REGISTER_APPLICATION(OHOSApplication, OHOSApplication)
constexpr int32_t APP_ENVIRONMENT_OVERWRITE = 1;
using ApplicationConfigurationManager = AbilityRuntime::ApplicationConfigurationManager;
OHOSApplication::OHOSApplication()
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
}

OHOSApplication::~OHOSApplication()
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
}

/**
 *
 * @brief Will be called the application foregrounds
 *
 */
void OHOSApplication::OnForeground()
{
    TAG_LOGD(AAFwkTag::APPKIT, "begin");
    if (abilityRuntimeContext_) {
        abilityRuntimeContext_->NotifyApplicationForeground();
    }

    for (const auto& runtime : runtimes_) {
        if (runtime == nullptr) {
            TAG_LOGD(AAFwkTag::APPKIT, "NotifyApplicationState, runtime is nullptr");
            continue;
        }
        runtime->NotifyApplicationState(false);
    }

    TAG_LOGD(AAFwkTag::APPKIT, "NotifyApplicationState::OnForeground end");
}

/**
 *
 * @brief Will be called the application backgrounds
 *
 */
void OHOSApplication::OnBackground()
{
    TAG_LOGD(AAFwkTag::APPKIT, "begin");
    if (abilityRuntimeContext_) {
        abilityRuntimeContext_->NotifyApplicationBackground();
    }

    for (const auto& runtime : runtimes_) {
        if (runtime == nullptr) {
            TAG_LOGD(AAFwkTag::APPKIT, "runtime is nullptr");
            continue;
        }
        runtime->NotifyApplicationState(true);
    }
}

void OHOSApplication::DumpApplication()
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    // create and initialize abilityInfos
    std::shared_ptr<AbilityInfo> abilityInfo = nullptr;
    std::shared_ptr<AbilityLocalRecord> record = nullptr;

    if (abilityRecordMgr_) {
        record = abilityRecordMgr_->GetAbilityItem(abilityRecordMgr_->GetToken());
    }

    if (record) {
        abilityInfo = record->GetAbilityInfo();
    }

    if (abilityInfo) {
        TAG_LOGD(AAFwkTag::APPKIT, "==============AbilityInfo==============");
        TAG_LOGD(AAFwkTag::APPKIT, "abilityInfo: package: %{public}s", abilityInfo->package.c_str());
        TAG_LOGD(AAFwkTag::APPKIT, "abilityInfo: name: %{public}s", abilityInfo->name.c_str());
        TAG_LOGD(AAFwkTag::APPKIT, "abilityInfo: label: %{public}s", abilityInfo->label.c_str());
        TAG_LOGD(AAFwkTag::APPKIT, "abilityInfo: description: %{public}s", abilityInfo->description.c_str());
        TAG_LOGD(AAFwkTag::APPKIT, "abilityInfo: iconPath: %{public}s", abilityInfo->iconPath.c_str());
        TAG_LOGD(AAFwkTag::APPKIT, "abilityInfo: visible: %{public}d", abilityInfo->visible);
        TAG_LOGD(AAFwkTag::APPKIT, "abilityInfo: kind: %{public}s", abilityInfo->kind.c_str());
        TAG_LOGD(AAFwkTag::APPKIT, "abilityInfo: type: %{public}d", abilityInfo->type);
        TAG_LOGD(AAFwkTag::APPKIT, "abilityInfo: orientation: %{public}d", abilityInfo->orientation);
        TAG_LOGD(AAFwkTag::APPKIT, "abilityInfo: launchMode: %{public}d", abilityInfo->launchMode);
        for (auto permission : abilityInfo->permissions) {
            TAG_LOGD(AAFwkTag::APPKIT, "abilityInfo: permission: %{public}s", permission.c_str());
        }
        TAG_LOGD(AAFwkTag::APPKIT, "abilityInfo: bundleName: %{public}s", abilityInfo->bundleName.c_str());
        TAG_LOGD(AAFwkTag::APPKIT, "abilityInfo: applicationName: %{public}s", abilityInfo->applicationName.c_str());
    }

    // create and initialize applicationInfo
    std::shared_ptr<ApplicationInfo> applicationInfoPtr = GetApplicationInfo();
    if (applicationInfoPtr != nullptr) {
        TAG_LOGD(AAFwkTag::APPKIT, "applicationInfo: name: %{public}s", applicationInfoPtr->name.c_str());
        TAG_LOGD(AAFwkTag::APPKIT, "applicationInfo: bundleName: %{public}s", applicationInfoPtr->bundleName.c_str());
        TAG_LOGD(
            AAFwkTag::APPKIT, "applicationInfo: signatureKey: %{public}s", applicationInfoPtr->signatureKey.c_str());
    }
}

/**
 * @brief Add Runtime
 *
 * @param runtime Runtime instance.
 */
void OHOSApplication::AddRuntime(std::unique_ptr<AbilityRuntime::Runtime>&& runtime)
{
    TAG_LOGD(AAFwkTag::APPKIT, "begin");
    if (runtime == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "runtime is empty");
        return;
    }
    runtimes_.push_back(std::move(runtime));
}

/**
 * @brief Set ApplicationContext
 *
 * @param abilityRuntimeContext ApplicationContext instance.
 */
void OHOSApplication::SetApplicationContext(
    const std::shared_ptr<AbilityRuntime::ApplicationContext> &abilityRuntimeContext)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (abilityRuntimeContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "context is empty");
        return;
    }
    abilityRuntimeContext_ = abilityRuntimeContext;
    auto application = std::static_pointer_cast<OHOSApplication>(shared_from_this());
    std::weak_ptr<OHOSApplication> applicationWptr = application;
    abilityRuntimeContext_->RegisterAppConfigUpdateObserver([applicationWptr](const Configuration &config) {
        std::shared_ptr<OHOSApplication> applicationSptr = applicationWptr.lock();
        if (applicationSptr == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "application is nullptr.");
            return;
        }
        applicationSptr->OnConfigurationUpdated(config, AbilityRuntime::SetLevel::Application);
    });
    abilityRuntimeContext_->RegisterAppFontObserver([applicationWptr](const Configuration &config) {
        std::shared_ptr<OHOSApplication> applicationSptr = applicationWptr.lock();
        if (applicationSptr == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "application is nullptr.");
            return;
        }
        applicationSptr->OnUpdateConfigurationForAll(config);
    });
}

static void SetSupportedProcessCacheSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_boolean value) {
    TAG_LOGI(AAFwkTag::APPKIT, "SetSupportedProcessCacheSync called");
    ani_class applicationContextCls = nullptr;
    if (env->FindClass(STS_APPLICATION_CONTEXT_CLASS_NAME, &applicationContextCls) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass ApplicationContext failed");
        return;
    }
    ani_field contextField;
    if (env->Class_FindField(applicationContextCls, "nativeApplicationContext", &contextField) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindField failed");
        return;
    }
    ani_long nativeContextLong;
    if (env->Object_GetField_Long(aniObj, contextField, &nativeContextLong) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_GetField_Long failed");
        return;
    }
    ((AbilityRuntime::ApplicationContext*)nativeContextLong)->SetSupportedProcessCacheSelf(value);
    TAG_LOGI(AAFwkTag::APPKIT, "SetSupportedProcessCacheSync end");
}

void OHOSApplication::InitAniApplicationContext()
{
    TAG_LOGI(AAFwkTag::APPKIT, "init application context");
    auto& runtime = GetRuntime(AbilityRuntime::APPLICAITON_CODE_LANGUAGE_ARKTS_1_2);
    auto aniEnv = static_cast<AbilityRuntime::STSRuntime &>(*runtime).GetAniEnv();
    ani_class applicationContextCls = nullptr;
    if (aniEnv->FindClass(STS_APPLICATION_CONTEXT_CLASS_NAME, &applicationContextCls) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass ApplicationContext failed");
        return;
    }
    std::array applicationContextFunctions = {
        ani_native_function {"setSupportedProcessCacheSync", "Z:V",
            reinterpret_cast<void *>(SetSupportedProcessCacheSync)},
    };
    aniEnv->Class_BindNativeMethods(applicationContextCls, applicationContextFunctions.data(),
        applicationContextFunctions.size());

    ani_method contextCtorMethod = nullptr;
    if (aniEnv->Class_FindMethod(applicationContextCls, "<ctor>", ":V", &contextCtorMethod) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod ctor failed");
        return;
    }
    ani_object applicationContextObject = nullptr;
    if (aniEnv->Object_New(applicationContextCls, contextCtorMethod, &applicationContextObject) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_New failed");
        return;
    }
    ani_field contextField;
    if (aniEnv->Class_FindField(applicationContextCls, "nativeApplicationContext", &contextField) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindField failed");
        return;
    }
    if (aniEnv->Object_SetField_Long(applicationContextObject, contextField,
        (ani_long)abilityRuntimeContext_.get()) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Long failed");
        return;
    }
    ani_ref applicationContextObjectRef = nullptr;
    if (aniEnv->GlobalReference_Create(applicationContextObject, &applicationContextObjectRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Create failed");
        return;
    }
    applicationContextObjRef_ = reinterpret_cast<void*>(applicationContextObjectRef);
    abilityRuntimeContext_->SetApplicationCtxObjRef(applicationContextObjRef_);
    TAG_LOGI(AAFwkTag::APPKIT, "init application context success");
}

/**
 *
 * @brief Set the abilityRecordMgr to the OHOSApplication.
 *
 * @param abilityRecordMgr
 */
void OHOSApplication::SetAbilityRecordMgr(const std::shared_ptr<AbilityRecordMgr> &abilityRecordMgr)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (abilityRecordMgr == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "abilityRecordMgr is nullptr");
        return;
    }
    abilityRecordMgr_ = abilityRecordMgr;
}

/**
 *
 * @brief Will be Called when the system configuration of the device changes.
 *
 * @param config Indicates the new Configuration object.
 */
void OHOSApplication::OnConfigurationUpdated(Configuration config, AbilityRuntime::SetLevel level)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (!abilityRecordMgr_ || !configuration_ || !abilityRuntimeContext_) {
        TAG_LOGD(AAFwkTag::APPKIT, "abilityRecordMgr_ or configuration_ or abilityRuntimeContext_ is null");
        return;
    }
    // Whether the color changes with the system
    bool isUpdateAppColor = IsUpdateColorNeeded(config, level);
    // Whether the font changes with the system
    bool isUpdateAppFontSize = isUpdateFontSize(config, level);
    // Whether the language changes with the system
    bool isUpdateAppLanguage = IsUpdateLanguageNeeded(config, level);
    if (!isUpdateAppColor && !isUpdateAppFontSize && !isUpdateAppLanguage && config.GetItemSize() == 0) {
        TAG_LOGD(AAFwkTag::APPKIT, "configuration need not updated");
        return;
    }
    std::vector<std::string> changeKeyV;
    {
        HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, "configuration_->CompareDifferent");
        configuration_->CompareDifferent(changeKeyV, config);
        configuration_->Merge(changeKeyV, config);
    }
    TAG_LOGI(AAFwkTag::APPKIT, "configuration_: %{public}s, config: %{public}s",
        configuration_->GetName().c_str(), config.GetName().c_str());
    // Update resConfig of resource manager, which belongs to application context.
    UpdateAppContextResMgr(config);
    // Notify all abilities
    for (const auto &abilityToken : abilityRecordMgr_->GetAllTokens()) {
        auto abilityRecord = abilityRecordMgr_->GetAbilityItem(abilityToken);
        if (abilityRecord && abilityRecord->GetAbilityThread()) {
            abilityRecord->GetAbilityThread()->ScheduleUpdateConfiguration(config);
        }
    }

    for (auto it = abilityStages_.begin(); it != abilityStages_.end(); it++) {
        auto abilityStage = it->second;
        if (abilityStage) {
            abilityStage->OnConfigurationUpdated(config);
        }
    }

#ifdef SUPPORT_GRAPHICS
    TAG_LOGD(AAFwkTag::APPKIT, "Update configuration for all window.");
    auto diffConfiguration = std::make_shared<AppExecFwk::Configuration>(config);
    Rosen::Window::UpdateConfigurationForAll(diffConfiguration);
#endif

    abilityRuntimeContext_->DispatchConfigurationUpdated(*configuration_);
    abilityRuntimeContext_->SetConfiguration(configuration_);
}

/**
 *
 * @brief Will be Called when the application font of the device changes.
 *
 * @param config Indicates the new Configuration object.
 */
void OHOSApplication::OnUpdateConfigurationForAll(Configuration config)
{
#ifdef SUPPORT_GRAPHICS
    // Notify Window
    auto diffConfiguration = std::make_shared<AppExecFwk::Configuration>(config);
    Rosen::Window::UpdateConfigurationForAll(diffConfiguration);
#endif
}

/**
 *
 * @brief Called when the system has determined to trim the memory, for example,
 * when the ability is running in the background and there is no enough memory for
 * running as many background processes as possible.
 *
 * @param level Indicates the memory trim level, which shows the current memory usage status.
 */
void OHOSApplication::OnMemoryLevel(int32_t level)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (abilityRuntimeContext_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "abilityRuntimeContext_ is nullptr");
        return;
    }
    if (abilityRecordMgr_) {
        TAG_LOGD(
            AAFwkTag::APPKIT, "Number of ability to be notified : [%{public}d]", abilityRecordMgr_->GetRecordCount());
        for (const auto &abilityToken : abilityRecordMgr_->GetAllTokens()) {
            auto abilityRecord = abilityRecordMgr_->GetAbilityItem(abilityToken);
            if (abilityRecord && abilityRecord->GetAbilityThread()) {
                abilityRecord->GetAbilityThread()->NotifyMemoryLevel(level);
            }
        }
    }

    TAG_LOGD(AAFwkTag::APPKIT, "Number of abilityStage to be notified : [%{public}zu]", abilityStages_.size());
    for (auto it = abilityStages_.begin(); it != abilityStages_.end(); it++) {
        auto abilityStage = it->second;
        if (abilityStage) {
            abilityStage->OnMemoryLevel(level);
        }
    }

    TAG_LOGD(AAFwkTag::APPKIT, "called");
    abilityRuntimeContext_->DispatchMemoryLevel(level);
}

/**
 *
 * @brief Will be called the application starts
 *
 */
void OHOSApplication::OnStart()
{}

/**
 *
 * @brief Will be called the application ends
 */
void OHOSApplication::OnTerminate()
{}

void OHOSApplication::SetAppEnv(const std::vector<AppEnvironment>& appEnvironments)
{
    if (appEnvironments.empty()) {
        return;
    }

    for (const auto &appEnvironment : appEnvironments) {
        if (setenv(appEnvironment.name.c_str(), appEnvironment.value.c_str(), APP_ENVIRONMENT_OVERWRITE)) {
            TAG_LOGE(AAFwkTag::APPKIT, "appEnvironment: %{public}s set failed", appEnvironment.name.c_str());
            return;
        }
        TAG_LOGI(AAFwkTag::APPKIT, "appEnvironment set successfully: %{public}s = %{public}s",
            appEnvironment.name.c_str(), appEnvironment.value.c_str());
    }
    return;
}

std::shared_ptr<AbilityRuntime::Context> OHOSApplication::AddAbilityStage(
    const std::shared_ptr<AbilityLocalRecord> &abilityRecord,
    const std::function<void(const std::shared_ptr<AbilityRuntime::Context> &)> &callback, bool &isAsyncCallback)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    if (abilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "abilityRecord is nullptr");
        return nullptr;
    }
    const std::shared_ptr<AbilityInfo> &abilityInfo = abilityRecord->GetAbilityInfo();
    if (abilityInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "abilityInfo is nullptr");
        return nullptr;
    }
    std::string moduleName = abilityInfo->moduleName;
    std::shared_ptr<AbilityRuntime::AbilityStage> abilityStage;
    auto iterator = abilityStages_.find(moduleName);
    if (iterator == abilityStages_.end()) {
        auto stageContext = std::make_shared<AbilityRuntime::AbilityStageContext>();
        stageContext->SetParentContext(abilityRuntimeContext_);
        stageContext->InitHapModuleInfo(abilityInfo);
        stageContext->SetConfiguration(GetConfiguration());
        std::shared_ptr<AppExecFwk::HapModuleInfo> hapModuleInfo = stageContext->GetHapModuleInfo();
        if (hapModuleInfo == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "hapModuleInfo is nullptr");
            return nullptr;
        }
        auto& runtime = GetRuntime(abilityInfo->language);
        if (runtime) {
            runtime->UpdatePkgContextInfoJson(
                hapModuleInfo->moduleName, hapModuleInfo->hapPath, hapModuleInfo->packageName);
        }
        SetAppEnv(hapModuleInfo->appEnvironments);

        if (abilityInfo->applicationInfo.multiProjects) {
            auto moduleContext = stageContext->CreateModuleContext(hapModuleInfo->moduleName);
            auto rm = moduleContext != nullptr ? moduleContext->GetResourceManager() : nullptr;
            stageContext->SetResourceManager(rm);
        }

        auto& runtimeStage = GetRuntime(hapModuleInfo->language);
        abilityStage = AbilityRuntime::AbilityStage::Create(runtimeStage, *hapModuleInfo);
        if (abilityStage == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "ability stage invalid");
            return nullptr;
        }
        auto application = std::static_pointer_cast<OHOSApplication>(shared_from_this());
        std::weak_ptr<OHOSApplication> weak = application;
        abilityStage->Init(stageContext, weak);
        auto autoStartupCallback = CreateAutoStartupCallback(abilityStage, abilityRecord, callback);
        if (autoStartupCallback != nullptr) {
            abilityStage->RunAutoStartupTask(autoStartupCallback, isAsyncCallback, stageContext);
            if (isAsyncCallback) {
                TAG_LOGI(AAFwkTag::APPKIT, "waiting for startup");
                return nullptr;
            }
        }
        Want want;
        if (abilityRecord->GetWant()) {
            TAG_LOGD(AAFwkTag::APPKIT, "want is ok, transport to abilityStage");
            want = *(abilityRecord->GetWant());
        }
        abilityStage->OnCreate(want);
        abilityStages_[moduleName] = abilityStage;
    } else {
        abilityStage = iterator->second;
    }
    const sptr<IRemoteObject> &token = abilityRecord->GetToken();
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "token is null");
        return nullptr;
    }
    abilityStage->AddAbility(token, abilityRecord);
    return abilityStage->GetContext();
}

const std::function<void()> OHOSApplication::CreateAutoStartupCallback(
    const std::shared_ptr<AbilityRuntime::AbilityStage> abilityStage,
    const std::shared_ptr<AbilityLocalRecord> abilityRecord,
    const std::function<void(const std::shared_ptr<AbilityRuntime::Context>&)>& callback)
{
    const std::shared_ptr<AbilityInfo> &abilityInfo = abilityRecord->GetAbilityInfo();
    if (abilityInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null abilityInfo");
        return nullptr;
    }
    if (!IsMainProcess(abilityInfo->bundleName, abilityInfo->applicationInfo.process)) {
        return nullptr;
    }
    auto application = std::static_pointer_cast<OHOSApplication>(shared_from_this());
    std::weak_ptr<OHOSApplication> weak = application;

    auto autoStartupCallback = [weak, abilityStage, abilityRecord, callback]() {
        auto ohosApplication = weak.lock();
        if (ohosApplication == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null ohosApplication");
            return;
        }
        if (abilityRecord == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null abilityRecord");
            return;
        }

        auto abilityInfo = abilityRecord->GetAbilityInfo();
        if (abilityInfo == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null abilityInfo");
            return;
        }

        std::string moduleName = abilityInfo->moduleName;
        ohosApplication->AutoStartupDone(abilityRecord, abilityStage, moduleName);
        if (callback == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null callback");
            return;
        }
        callback(abilityStage->GetContext());
    };

    return autoStartupCallback;
}

const std::function<void()> OHOSApplication::CreateAutoStartupCallback(
    const std::shared_ptr<AbilityRuntime::AbilityStage> &abilityStage,
    const AppExecFwk::HapModuleInfo &hapModuleInfo,
    const std::function<void()>& callback)
{
    auto applicationInfo = abilityRuntimeContext_->GetApplicationInfo();
    if (applicationInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null applicationInfo");
        return nullptr;
    }
    if (!IsMainProcess(hapModuleInfo.bundleName, applicationInfo->process)) {
        return nullptr;
    }
    auto application = std::static_pointer_cast<OHOSApplication>(shared_from_this());
    std::weak_ptr<OHOSApplication> weak = application;

    auto autoStartupCallback = [weak, abilityStage, hapModuleInfo, callback]() {
        auto ohosApplication = weak.lock();
        if (ohosApplication == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null ohosApplication");
            return;
        }
        ohosApplication->AutoStartupDone(abilityStage, hapModuleInfo);
        if (callback == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null callback");
            return;
        }
        callback();
    };

    return autoStartupCallback;
}

void OHOSApplication::AutoStartupDone(const std::shared_ptr<AbilityLocalRecord> &abilityRecord,
    const std::shared_ptr<AbilityRuntime::AbilityStage> &abilityStage, const std::string &moduleName)
{
    if (abilityStage == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "abilityStage is nullptr");
        return;
    }

    Want want;
    if (abilityRecord->GetWant()) {
        TAG_LOGD(AAFwkTag::APPKIT, "want is ok, transport to abilityStage");
        want = *(abilityRecord->GetWant());
    }

    abilityStage->OnCreate(want);
    abilityStages_[moduleName] = abilityStage;
    const sptr<IRemoteObject> &token = abilityRecord->GetToken();
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "token is null");
        return;
    }
    abilityStage->AddAbility(token, abilityRecord);
}

void OHOSApplication::AutoStartupDone(
    const std::shared_ptr<AbilityRuntime::AbilityStage> &abilityStage,
    const AppExecFwk::HapModuleInfo &hapModuleInfo)
{
    if (abilityStage == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "abilityStage is nullptr");
        return;
    }

    Want want;
    abilityStage->OnCreate(want);
    abilityStages_[hapModuleInfo.moduleName] = abilityStage;
    TAG_LOGI(AAFwkTag::APPKIT, "abilityStage insert and initialization");
    return;
}

/**
 *
 * @brief update the application info after new module installed.
 *
 * @param appInfo The latest application info obtained from bms for update abilityRuntimeContext.
 *
 */
void OHOSApplication::UpdateApplicationInfoInstalled(const AppExecFwk::ApplicationInfo &appInfo)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");

    if (abilityRuntimeContext_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "abilityRuntimeContext_ is nullptr");
        return;
    }

    abilityRuntimeContext_->SetApplicationInfo(std::make_shared<AppExecFwk::ApplicationInfo>(appInfo));
}

bool OHOSApplication::AddAbilityStage(
    const AppExecFwk::HapModuleInfo &hapModuleInfo,
    const std::function<void()> &callback, bool &isAsyncCallback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    if (abilityRuntimeContext_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "abilityRuntimeContext_ is nullptr");
        return false;
    }

    if (runtimes_.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "runtimes empty");
        return false;
    }

    if (abilityStages_.find(hapModuleInfo.moduleName) != abilityStages_.end()) {
        TAG_LOGE(AAFwkTag::APPKIT, "object exist");
        return false;
    }

    auto stageContext = std::make_shared<AbilityRuntime::AbilityStageContext>();
    stageContext->SetParentContext(abilityRuntimeContext_);
    stageContext->InitHapModuleInfo(hapModuleInfo);
    stageContext->SetConfiguration(GetConfiguration());
    auto moduleInfo = stageContext->GetHapModuleInfo();
    if (moduleInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "moduleInfo is nullptr");
        return false;
    }

    if (abilityRuntimeContext_->GetApplicationInfo() && abilityRuntimeContext_->GetApplicationInfo()->multiProjects) {
        auto rm = stageContext->CreateModuleContext(hapModuleInfo.moduleName)->GetResourceManager();
        stageContext->SetResourceManager(rm);
    }

    auto& runtime = GetRuntime(moduleInfo->language);
    auto abilityStage = AbilityRuntime::AbilityStage::Create(runtime, *moduleInfo);
    if (abilityStage == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "ability stage invalid");
        return false;
    }
    auto application = std::static_pointer_cast<OHOSApplication>(shared_from_this());
    std::weak_ptr<OHOSApplication> weak = application;
    abilityStage->Init(stageContext, weak);
    auto autoStartupCallback = CreateAutoStartupCallback(abilityStage, hapModuleInfo, callback);
    if (autoStartupCallback != nullptr) {
        abilityStage->RunAutoStartupTask(autoStartupCallback, isAsyncCallback, stageContext);
        if (isAsyncCallback) {
            TAG_LOGI(AAFwkTag::APPKIT, "waiting for startup");
            return false;
        }
    }
    Want want;
    abilityStage->OnCreate(want);
    abilityStages_[hapModuleInfo.moduleName] = abilityStage;
    TAG_LOGI(AAFwkTag::APPKIT, "abilityStage insert and initialization");

    return true;
}

void OHOSApplication::CleanAbilityStage(const sptr<IRemoteObject> &token,
    const std::shared_ptr<AbilityInfo> &abilityInfo, bool isCacheProcess)
{
    if (abilityInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "abilityInfo is nullptr");
        return;
    }
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "token is nullptr");
        return;
    }
    std::string moduleName = abilityInfo->moduleName;
    auto iterator = abilityStages_.find(moduleName);
    if (iterator != abilityStages_.end()) {
        auto abilityStage = iterator->second;
        if (abilityStage == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "abilityStage is nullptr");
            return;
        }
        abilityStage->RemoveAbility(token);
        if (!abilityStage->ContainsAbility() && !isCacheProcess) {
            abilityStage->OnDestroy();
            abilityStages_.erase(moduleName);
        }
    }
}

std::shared_ptr<AbilityRuntime::Context> OHOSApplication::GetAppContext() const
{
    return abilityRuntimeContext_;
}

const std::vector<std::unique_ptr<AbilityRuntime::Runtime>>& OHOSApplication::GetRuntime() const
{
    return runtimes_;
}

void OHOSApplication::SetConfiguration(const Configuration &config)
{
    if (!configuration_) {
        configuration_ = std::make_shared<Configuration>(config);
    }
    auto colorMode = config.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE);
    AbilityRuntime::ApplicationConfigurationManager::GetInstance().
        SetColorModeSetLevel(AbilityRuntime::SetLevel::System, colorMode);

    if (abilityRuntimeContext_ && configuration_) {
        abilityRuntimeContext_->SetConfiguration(configuration_);
    }
}

void OHOSApplication::ScheduleAcceptWant(const AAFwk::Want &want, const std::string &moduleName, std::string &flag)
{
    TAG_LOGD(AAFwkTag::APPKIT, "called");
    auto iter = abilityStages_.find(moduleName);
    if (iter != abilityStages_.end()) {
        auto abilityStage = iter->second;
        if (abilityStage) {
            flag = abilityStage->OnAcceptWant(want);
        }
    }
}

void OHOSApplication::ScheduleNewProcessRequest(const AAFwk::Want &want, const std::string &moduleName,
    std::string &flag)
{
    TAG_LOGD(AAFwkTag::APPKIT, "call");
    if (abilityStages_.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "abilityStages_ is empty");
        return;
    }
    auto iter = abilityStages_.find(moduleName);
    if (iter == abilityStages_.end()) {
        TAG_LOGE(AAFwkTag::APPKIT, "%{public}s is not in abilityStage", moduleName.c_str());
        return;
    }
    auto abilityStage = iter->second;
    if (abilityStage) {
        flag = abilityStage->OnNewProcessRequest(want);
    }
}

std::shared_ptr<Configuration> OHOSApplication::GetConfiguration() const
{
    return configuration_;
}

void OHOSApplication::SetExtensionTypeMap(std::map<int32_t, std::string> map)
{
    extensionTypeMap_ = map;
}

bool OHOSApplication::NotifyLoadRepairPatch(const std::string &hqfFile, const std::string &hapPath)
{
    // TODO sts 确认hqf类型，当前只js\cj使用
    if (runtimes_.empty()) {
        TAG_LOGD(AAFwkTag::APPKIT, "runtimes empty");
        return true;
    }

    for (const auto& runtime : runtimes_) {
        if (runtime == nullptr) {
            TAG_LOGD(AAFwkTag::APPKIT, "null runtime");
            continue;
        }
        if (!runtime->LoadRepairPatch(hqfFile, hapPath)) {
            return false;
        }
    }
    return true;
}

bool OHOSApplication::NotifyHotReloadPage()
{
    if (runtimes_.empty()) {
        TAG_LOGD(AAFwkTag::APPKIT, "runtimes empty");
        return true;
    }

    for (const auto& runtime : runtimes_) {
        if (runtime == nullptr) {
            TAG_LOGD(AAFwkTag::APPKIT, "null runtime");
            continue;
        }
        if (!runtime->NotifyHotReloadPage()) {
            return false;
        }
    }
    return true;
}

bool OHOSApplication::NotifyUnLoadRepairPatch(const std::string &hqfFile)
{
    // TODO sts 确认hqf类型，当前只js\cj使用
    if (runtimes_.empty()) {
        TAG_LOGD(AAFwkTag::APPKIT, "runtimes empty");
        return true;
    }

    for (const auto& runtime : runtimes_) {
        if (runtime == nullptr) {
            TAG_LOGD(AAFwkTag::APPKIT, "null runtime");
            continue;
        }
        if (!runtime->UnLoadRepairPatch(hqfFile)) {
            return false;
        }
    }

    return true;
}

void OHOSApplication::CleanAppTempData(bool isLastProcess)
{
    if (!isLastProcess) {
        TAG_LOGE(AAFwkTag::APPKIT, "failed");
        return;
    }
    if (abilityRuntimeContext_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "Context is nullptr");
        return;
    }

    auto cleaner = ApplicationCleaner::GetInstance();
    if (cleaner) {
        cleaner->SetRuntimeContext(abilityRuntimeContext_);
        cleaner->RenameTempData();
    }
}

void OHOSApplication::CleanUselessTempData()
{
    if (abilityRuntimeContext_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "Context is nullptr");
        return;
    }

    auto cleaner = ApplicationCleaner::GetInstance();
    if (cleaner) {
        cleaner->SetRuntimeContext(abilityRuntimeContext_);
        cleaner->ClearTempData();
    }
}

void OHOSApplication::UpdateAppContextResMgr(const Configuration &config)
{
    auto context = GetAppContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "Application context is nullptr");
        return;
    }

    auto configUtils = std::make_shared<AbilityRuntime::ConfigurationUtils>();
    configUtils->UpdateGlobalConfig(config, context->GetResourceManager());
}

void OHOSApplication::CleanEmptyAbilityStage()
{
    bool containsNonEmpty = false;
    for (auto it = abilityStages_.begin(); it != abilityStages_.end();) {
        auto abilityStage = it->second;
        if (abilityStage == nullptr) {
            it++;
            continue;
        }
        if (!abilityStage->ContainsAbility()) {
            abilityStage->OnDestroy();
            it = abilityStages_.erase(it);
        } else {
            containsNonEmpty = true;
            it++;
        }
    }
    if (containsNonEmpty) {
        TAG_LOGI(AAFwkTag::APPKIT, "Application contains none empty abilityStage");
    }
}

bool OHOSApplication::IsUpdateColorNeeded(Configuration &config, AbilityRuntime::SetLevel level)
{
    std::string colorMode = config.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE);
    std::string colorModeIsSetBySa =
        config.GetItem(AAFwk::GlobalConfigurationKey::COLORMODE_IS_SET_BY_SA);
    if (level < AbilityRuntime::SetLevel::SA && !colorModeIsSetBySa.empty()) {
        level = AbilityRuntime::SetLevel::SA;
    }

    TAG_LOGI(AAFwkTag::APPKIT, "current %{public}d, pre %{public}d",
        static_cast<uint8_t>(level),
        static_cast<uint8_t>(AbilityRuntime::ApplicationConfigurationManager::GetInstance().GetColorModeSetLevel()));

    bool needUpdate = true;

    if (level < AbilityRuntime::ApplicationConfigurationManager::GetInstance().GetColorModeSetLevel() ||
        colorMode.empty()) {
        config.RemoveItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE);
        config.RemoveItem(AAFwk::GlobalConfigurationKey::COLORMODE_IS_SET_BY_SA);
        TAG_LOGI(AAFwkTag::APPKIT, "color remove");
        needUpdate = false;
    }

    if (!colorMode.empty()) {
        config.AddItem(AAFwk::GlobalConfigurationKey::SYSTEM_COLORMODE,
            AbilityRuntime::ApplicationConfigurationManager::GetInstance().SetColorModeSetLevel(level, colorMode));

        if (level > AbilityRuntime::SetLevel::System) {
            config.AddItem(AAFwk::GlobalConfigurationKey::COLORMODE_IS_SET_BY_APP,
                AppExecFwk::ConfigurationInner::IS_SET_BY_APP);
        }
    }

    return needUpdate;
}

bool OHOSApplication::isUpdateFontSize(Configuration &config, AbilityRuntime::SetLevel level)
{
    std::string fontSize = config.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_SIZE_SCALE);
    if (fontSize.empty()) {
        TAG_LOGW(AAFwkTag::APPKIT, "fontSize is empty");
        return false;
    }

    auto preLevle = ApplicationConfigurationManager::GetInstance().GetFontSetLevel();
    if (level < preLevle) {
        config.RemoveItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_SIZE_SCALE);
        return false;
    }

    std::string globalFontFollowSysteme = configuration_->GetItem(AAFwk::GlobalConfigurationKey::APP_FONT_SIZE_SCALE);
    if (level == preLevle && !globalFontFollowSysteme.empty()) {
        if (globalFontFollowSysteme.compare(ConfigurationInner::IS_APP_FONT_FOLLOW_SYSTEM) == 0) {
            return true;
        }
        config.RemoveItem(AAFwk::GlobalConfigurationKey::SYSTEM_FONT_SIZE_SCALE);
        return false;
    }

    // level > preLevle
    configuration_->RemoveItem(AAFwk::GlobalConfigurationKey::APP_FONT_SIZE_SCALE);
    ApplicationConfigurationManager::GetInstance().SetfontSetLevel(level);
    return true;
}

bool OHOSApplication::IsUpdateLanguageNeeded(Configuration &config, AbilityRuntime::SetLevel level)
{
    TAG_LOGI(AAFwkTag::APPKIT, "current %{public}d, pre %{public}d",
        static_cast<uint8_t>(level),
        static_cast<uint8_t>(AbilityRuntime::ApplicationConfigurationManager::GetInstance().GetLanguageSetLevel()));

    std::string language = config.GetItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
    if (language.empty()) {
        TAG_LOGW(AAFwkTag::APPKIT, "language is empty");
        return false;
    }
    if (level < AbilityRuntime::ApplicationConfigurationManager::GetInstance().GetLanguageSetLevel()) {
        config.RemoveItem(AAFwk::GlobalConfigurationKey::SYSTEM_LANGUAGE);
        TAG_LOGI(AAFwkTag::APPKIT, "language remove");
        return false;
    }
    AbilityRuntime::ApplicationConfigurationManager::GetInstance().SetLanguageSetLevel(level);
    config.AddItem(AAFwk::GlobalConfigurationKey::IS_PREFERRED_LANGUAGE,
        level == AbilityRuntime::SetLevel::Application ? "1" : "0");
    return true;
}

bool OHOSApplication::IsMainProcess(const std::string &bundleName, const std::string &process)
{
    auto processInfo = GetProcessInfo();
    if (processInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null processInfo");
        return false;
    }
    ProcessType processType = processInfo->GetProcessType();
    if (processType == ProcessType::NORMAL) {
        return true;
    }

    std::string processName = processInfo->GetProcessName();
    if (processName == bundleName || processName == process) {
        return true;
    }
    TAG_LOGD(AAFwkTag::APPKIT, "not main process");
    return false;
}

const std::unique_ptr<AbilityRuntime::Runtime>& OHOSApplication::GetRuntime(const std::string& language) const
{
    for (auto& runtime : runtimes_) {
        if (runtime->GetLanguage() == AbilityRuntime::Runtime::ConvertLangToCode(language)) {
            return runtime;
        }
    }
    return runtimeNullptr_;
}
}  // namespace AppExecFwk
}  // namespace OHOS
