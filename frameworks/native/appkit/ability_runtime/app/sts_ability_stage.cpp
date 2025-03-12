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

#include "sts_ability_stage.h"
#include "ability_delegator_registry.h"
#include "freeze_util.h"
#include "hilog_tag_wrapper.h"
#include "configuration_convertor.h"
#include "sts_ability_stage_context.h"
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
void RegisterStopPreloadSoCallback(STSRuntime& stsRuntime)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    if (startupManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null startupManager");
        return;
    }
}
} // namespace


bool STSAbilityStage::UseCommonChunk(const AppExecFwk::HapModuleInfo& hapModuleInfo)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
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

std::shared_ptr<AbilityStage> STSAbilityStage::Create(
    const std::unique_ptr<Runtime>& runtime, const AppExecFwk::HapModuleInfo& hapModuleInfo)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    if (runtime == nullptr) {
        TAG_LOGW(AAFwkTag::APPKIT, "null runtime");
        return nullptr;
    }
    FreezeUtil::GetInstance().AddAppLifecycleEvent(0, "STSAbilityStage::Create");

    auto& stsRuntime = static_cast<STSRuntime&>(*runtime);

    std::string srcPath(hapModuleInfo.name);
    std::string moduleName(hapModuleInfo.moduleName);
    moduleName.append("::").append("AbilityStage");
    bool commonChunkFlag = UseCommonChunk(hapModuleInfo);

    RegisterStopPreloadSoCallback(stsRuntime);
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
    } else {
        srcPath.append("/");
        if (!hapModuleInfo.srcEntrance.empty()) {
            srcPath.append(hapModuleInfo.srcEntrance);
            srcPath.erase(srcPath.rfind("."));
            srcPath.append(".abc");
            TAG_LOGI(AAFwkTag::APPKIT, "srcPath is %{public}s", srcPath.c_str());
        }
    }
    auto moduleObj = stsRuntime.LoadModule(moduleName, srcPath, hapModuleInfo.hapPath,
        hapModuleInfo.compileMode == AppExecFwk::CompileMode::ES_MODULE, commonChunkFlag, hapModuleInfo.srcEntrance);
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s finished", __func__);
    return std::make_shared<STSAbilityStage>(stsRuntime, std::move(moduleObj));
}

STSAbilityStage::STSAbilityStage(STSRuntime & stsRuntime, std::unique_ptr<STSNativeReference>&& stsAbilityStageObj)
    : stsRuntime_(stsRuntime), stsAbilityStageObj_(std::move(stsAbilityStageObj))
{}

STSAbilityStage::~STSAbilityStage()
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
}

void STSAbilityStage::Init(const std::shared_ptr<Context> &context,
    const std::weak_ptr<AppExecFwk::OHOSApplication> application)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    AbilityStage::Init(context, application);

    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        return;
    }

    if (!stsAbilityStageObj_) {
        TAG_LOGE(AAFwkTag::APPKIT, "null stage");
        return;
    }

    SetJsAbilityStage(context);
}

void STSAbilityStage::OnCreate(const AAFwk::Want &want) const
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    AbilityStage::OnCreate(want);

    if (!stsAbilityStageObj_) {
        TAG_LOGW(AAFwkTag::APPKIT, "Not found AbilityStage.js");
        return;
    }

    ani_status status = ANI_OK;
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env nullptr");
        return;
    }
    STSAbilityStageContext::ResetEnv(env);

    ani_method method = nullptr;
    status = env->Class_FindMethod(stsAbilityStageObj_->aniCls, "onCreate", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "Class_FindMethod FAILED");
        STSAbilityStageContext::ResetEnv(env);
        return;
    }

    status = env->Object_CallMethod_Void(stsAbilityStageObj_->aniObj, method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "CALL Object_CallMethod FAILED: %{public}d", status);
        STSAbilityStageContext::ResetEnv(env);
        return;
    } else {
        TAG_LOGI(AAFwkTag::ABILITY, "CALL Object_CallMethod SUCCEED");
    }

    FreezeUtil::GetInstance().AddAppLifecycleEvent(0, "STSAbilityStage::OnCreate end");
    auto delegator = AppExecFwk::AbilityDelegatorRegistry::GetAbilityDelegator(AbilityRuntime::Runtime::Language::STS);
    if (delegator) {
        delegator->PostPerformStageStart(CreateStageProperty());
    }
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s finished", __func__);
}

void STSAbilityStage::OnDestroy() const
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    AbilityStage::OnDestroy();
    if (!stsAbilityStageObj_) {
        TAG_LOGW(AAFwkTag::APPKIT, "Not found AbilityStage.js");
        return;
    }
    ani_status status = ANI_OK;
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGW(AAFwkTag::ABILITY, "env nullptr");
        return;
    }

    STSAbilityStageContext::ResetEnv(env);

    ani_method method = nullptr;
    status = env->Class_FindMethod(stsAbilityStageObj_->aniCls, "onDestroy", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "Class_FindMethod FAILED");
        STSAbilityStageContext::ResetEnv(env);
        return;
    }

    status = env->Object_CallMethod_Void(stsAbilityStageObj_->aniObj, method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "CALL Object_CallMethod FAILED: %{public}d", status);
        STSAbilityStageContext::ResetEnv(env);
        return;
    } else {
        TAG_LOGI(AAFwkTag::ABILITY, "CALL Object_CallMethod SUCCEED");
    }
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s finished", __func__);
}

std::string STSAbilityStage::OnAcceptWant(const AAFwk::Want &want)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    return std::string();
}

std::string STSAbilityStage::OnNewProcessRequest(const AAFwk::Want &want)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    return std::string();
}

void STSAbilityStage::OnConfigurationUpdated(const AppExecFwk::Configuration& configuration)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    AbilityStage::OnConfigurationUpdated(configuration);
    auto env = stsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGI(AAFwkTag::ABILITY, "env nullptr");
        return;
    }

    auto configurationPtr = std::make_shared<AppExecFwk::Configuration>(configuration);
    ani_object configObj = STSAbilityStageContext::Createfiguration(env, configurationPtr);


    ani_method method = nullptr;
    ani_status status = env->Class_FindMethod(stsAbilityStageObj_->aniCls, "onConfigurationUpdate", "L@ohos/app/ability/Configuration/Configuration;:V", &method);
    if (status != ANI_OK) {
        TAG_LOGI(AAFwkTag::ABILITY, "Class_FindMethod FAILED");
        STSAbilityStageContext::ResetEnv(env);
        return;
    }

    status = env->Object_CallMethod_Void(stsAbilityStageObj_->aniObj, method, configObj);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "CALL Object_CallMethod FAILED: %{public}d", status);
        STSAbilityStageContext::ResetEnv(env);
        return;
    } else {
        TAG_LOGI(AAFwkTag::ABILITY, "CALL Object_CallMethod SUCCEED");
    }
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s finished", __func__);
}

void STSAbilityStage::OnMemoryLevel(int32_t level)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
}

int32_t STSAbilityStage::RunAutoStartupTask(const std::function<void()> &callback, bool &isAsyncCallback,
    const std::shared_ptr<Context> &stageContext)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    // TAG_LOGD(AAFwkTag::APPKIT, "called");
    isAsyncCallback = false;
    return RunAutoStartupTaskInner(callback, isAsyncCallback);
}

int32_t STSAbilityStage::RegisterAppStartupTask(const std::shared_ptr<AppExecFwk::HapModuleInfo>& hapModuleInfo)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    return ERR_OK;
}

int32_t STSAbilityStage::RunAutoStartupTaskInner(const std::function<void()> &callback, bool &isAsyncCallback)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    return ERR_OK;
}

std::unique_ptr<STSNativeReference> STSAbilityStage::LoadJsOhmUrl(const std::string &srcEntry, const std::string &ohmUrl,
    const std::string &moduleName, const std::string &hapPath, bool esmodule)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    return nullptr;
}

std::unique_ptr<STSNativeReference> STSAbilityStage::LoadJsSrcEntry(const std::string &srcEntry)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    return nullptr;
}

bool STSAbilityStage::LoadJsStartupConfig(const std::string &srcEntry)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    return true;
}

napi_value STSAbilityStage::CallObjectMethod(const char* name, napi_value const * argv, size_t argc)
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    napi_value result = nullptr;
    return result;
}

std::shared_ptr<AppExecFwk::DelegatorAbilityStageProperty> STSAbilityStage::CreateStageProperty() const
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    auto property = std::make_shared<AppExecFwk::DelegatorAbilityStageProperty>();
    return property;
}

std::string STSAbilityStage::GetHapModuleProp(const std::string &propName) const
{
    TAG_LOGI(AAFwkTag::ABILITY, "STS %{public}s called", __func__);
    return std::string();
}


void STSAbilityStage::SetJsAbilityStage(const std::shared_ptr<Context> &context)
{
    // if (context == nullptr) {
    //     TAG_LOGE(AAFwkTag::ABILITY, "context nullptr");
    //     return;
    // }
    // auto env = stsRuntime_.GetAniEnv();
    // if (env == nullptr) {
    //     TAG_LOGE(AAFwkTag::ABILITY, "env nullptr");
    //     return;
    // }

    // TAG_LOGE(AAFwkTag::ABILITY, "SetJsAbilityStage env:%{public}p", env);
    // STSAbilityStageContext::ResetEnv(env);

	// ani_object stageCtxObj = STSAbilityStageContext::CreateStsAbilityStageContext(env, context, application_);
    // if (stageCtxObj == nullptr) {
    //     STSAbilityStageContext::ResetEnv(env);
    //     TAG_LOGE(AAFwkTag::ABILITY, "CreateStsAbilityStageContext failed");
    //     return;
    // }

    // ani_status status = ANI_OK;
    // ani_field contextField;
    // status = env->Class_FindField(stsAbilityStageObj_->aniCls, "context", &contextField);
    // if (status != ANI_OK) {
    //     TAG_LOGI(AAFwkTag::ABILITY, "Class_GetField context failed");
    //     STSAbilityStageContext::ResetEnv(env);
    //     return;
    // }
    // ani_ref stageCtxObjRef = nullptr;
    // if (env->GlobalReference_Create(stageCtxObj, &stageCtxObjRef) != ANI_OK) {
    //     TAG_LOGE(AAFwkTag::ABILITY, "GlobalReference_Create stageCtxObj failed");
    //     return;
    // }
    // if (env->Object_SetField_Ref(stsAbilityStageObj_->aniObj, contextField, stageCtxObjRef) != ANI_OK) {
    //     TAG_LOGI(AAFwkTag::ABILITY, "zg Object_SetField_Ref stageCtxObj failed");
    //     STSAbilityStageContext::ResetEnv(env);
    // }
}

}  // namespace AbilityRuntime
}  // namespace OHOS
