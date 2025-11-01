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

#include "ets_startup_task.h"

#include "ani_common_util.h"
#include "hitrace_meter.h"
#include "ets_startup_task_executor.h"
#include "hilog_tag_wrapper.h"
#include "stage_context_transfer.h"

#ifdef WINDOWS_PLATFORM
#define ETS_EXPORT __declspec(dllexport)
#else
#define ETS_EXPORT __attribute__((visibility("default")))
#endif

namespace OHOS {
namespace AbilityRuntime {
EtsStartupTask::EtsStartupTask(ETSRuntime &etsRuntime, const StartupTaskInfo &info, bool lazyLoad)
    : AppStartupTask(info.name), etsRuntime_(etsRuntime), srcEntry_(info.srcEntry), ohmUrl_(info.ohmUrl),
    hapPath_(info.hapPath), esModule_(info.esModule)
{
    SetModuleName(info.moduleName);
    if (!lazyLoad) {
        LoadEtsOhmUrl();
    }
}

EtsStartupTask::~EtsStartupTask() = default;

const std::string &EtsStartupTask::GetType() const
{
    return AppStartupTask::TASK_TYPE_ETS;
}

int32_t EtsStartupTask::RunTaskInit(std::unique_ptr<StartupTaskResultCallback> callback)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::STARTUP, "RunTaskInit: %{public}s init", GetName().c_str());
    if (startupRef_ == nullptr) {
        int32_t result = LoadEtsOhmUrl();
        if (result != ERR_OK) {
            return result;
        }
    }

    resultCallback_ = std::move(callback);
    if (callCreateOnMainThread_) {
        return ETSStartupTaskExecutor::RunOnMainThread(etsRuntime_.GetAniEnv(), startupRef_, contextRef_,
            resultCallback_);
    }
    return ETSStartupTaskExecutor::RunOnTaskPool(etsRuntime_.GetAniEnv(), startupRef_, contextRef_, resultCallback_);
}

int32_t EtsStartupTask::LoadEtsOhmUrl()
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::STARTUP, "LoadEtsOhmUrl call, srcEntry: %{private}s", srcEntry_.c_str());
    if (srcEntry_.empty()) {
        TAG_LOGE(AAFwkTag::STARTUP, "srcEntry and ohmUrl empty");
        return ERR_STARTUP_INTERNAL_ERROR;
    }

    std::string moduleNameWithStartupTask = GetModuleName() + "::startupTask";
    std::string srcPath(srcEntry_);
    auto pos = srcPath.rfind('.');
    if (pos != std::string::npos) {
        srcPath.erase(pos);
        srcPath.append(".abc");
    }
    
    auto startupEtsRef = etsRuntime_.LoadModule(moduleNameWithStartupTask, srcPath, hapPath_, esModule_, false,
        srcEntry_);
    if (startupEtsRef == nullptr || startupEtsRef->aniRef == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "startup task null");
        return ERR_STARTUP_INTERNAL_ERROR;
    }
    startupRef_ = startupEtsRef->aniRef;
    return ERR_OK;
}

void EtsStartupTask::UpdateContextRef(std::shared_ptr<NativeReference> contextRef)
{
    contextRef_ = StageContextTransfer::GetStaticRef(etsRuntime_, contextRef);
}

void EtsStartupTask::UpdateContextRef(ani_ref contextRef)
{
    contextRef_ = contextRef;
}

int32_t EtsStartupTask::RunTaskOnDependencyCompleted(const std::string &dependencyName,
    const std::shared_ptr<StartupTaskResult> &result)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    TAG_LOGD(AAFwkTag::STARTUP, "RunTaskOnDependencyCompleted");
    if (startupRef_ == nullptr) {
        int32_t result = LoadEtsOhmUrl();
        if (result != ERR_OK) {
            return result;
        }
    }
    auto env = etsRuntime_.GetAniEnv();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null env");
        return ERR_STARTUP_INTERNAL_ERROR;
    }
    ani_object startupObj = reinterpret_cast<ani_object>(startupRef_);
    if (startupObj == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "%{public}s, null object", name_.c_str());
        return ERR_STARTUP_INTERNAL_ERROR;
    }

    ani_string dependency = AppExecFwk::GetAniString(env, dependencyName);
    ani_ref etsResult = GetDependencyResult(env, dependencyName, result);
    ani_status status = env->Object_CallMethodByName_Void(startupObj, "onDependencyCompleted", nullptr, dependency,
        etsResult);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::STARTUP, "%{public}s, call onDependencyCompleted fail:%{public}d", name_.c_str(), status);
        return ERR_STARTUP_FAILED_TO_EXECUTE_STARTUP;
    }
    return ERR_OK;
}

ani_ref EtsStartupTask::GetDependencyResult(ani_env *env, const std::string &dependencyName,
    std::shared_ptr<StartupTaskResult> result)
{
    if (result == nullptr) {
        return nullptr;
    }
    if (result->GetResultType() == StartupTaskResult::ResultType::ETS) {
        std::shared_ptr<EtsStartupTaskResult> etsResultPtr = std::static_pointer_cast<EtsStartupTaskResult>(result);
        return etsResultPtr->GetEtsStartupResultRef();
    }
    if (result->GetResultType() == StartupTaskResult::ResultType::JS) {
        std::shared_ptr<JsStartupTaskResult> jsResultPtr = std::static_pointer_cast<JsStartupTaskResult>(result);
        auto resultObj = EtsStartupTaskResult::JsToEtsResult(env, jsResultPtr->GetJsStartupResultRef());
        return reinterpret_cast<ani_ref>(resultObj);
    }
    TAG_LOGE(AAFwkTag::STARTUP, "invalid result type:%{public}d", static_cast<int32_t>(result->GetResultType()));
    return nullptr;
}

extern "C" ETS_EXPORT AppStartupTask* OHOS_CreateEtsStartupTask(
    const std::unique_ptr<Runtime> &runtime, const StartupTaskInfo &info,
    bool lazyLoad)
{
    if (runtime == nullptr) {
        return nullptr;
    }
    auto &etsRuntime = static_cast<ETSRuntime &>(*runtime);
    return new (std::nothrow) EtsStartupTask(etsRuntime, info, lazyLoad);
}
} // namespace AbilityRuntime
} // namespace OHOS