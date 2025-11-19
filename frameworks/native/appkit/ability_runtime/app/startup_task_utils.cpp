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

#include "startup_task_utils.h"

#include "ets_startup_task.h"
#include "hilog_tag_wrapper.h"
#include "stage_context_transfer.h"
#include "startup_task_utils.h"

namespace OHOS {
namespace AbilityRuntime {

void StartupTaskUtils::UpdateStartupTaskContextRef(napi_env env, std::shared_ptr<AppStartupTask> startupTask,
    std::shared_ptr<Context> context, ani_ref contextAniRef)
{
    if (startupTask == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null startupTask");
        return;
    }
    if (startupTask->GetType() == AppStartupTask::TASK_TYPE_ETS) {
        auto etsStartupTask = std::static_pointer_cast<EtsStartupTask>(startupTask);
        if (contextAniRef == nullptr) {
            TAG_LOGE(AAFwkTag::STARTUP, "contextAniRef null");
            return;
        }
        etsStartupTask->UpdateContextRef(contextAniRef);
    } else if (startupTask->GetType() == AppStartupTask::TASK_TYPE_JS) {
        if (context == nullptr) {
            TAG_LOGE(AAFwkTag::STARTUP, "context null");
            return;
        }
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::STARTUP, "env is null");
            return;
        }
        auto hapModuleInfo = context->GetHapModuleInfo();
        if (hapModuleInfo == nullptr) {
            TAG_LOGE(AAFwkTag::STARTUP, "null hapModuleInfo");
            return;
        }
        std::string moduleName = hapModuleInfo->name;
        std::shared_ptr<NativeReference> contextRef = StageContextTransfer::GetInstance().GetContextRef(moduleName);
        if (contextRef == nullptr) {
            TAG_LOGI(AAFwkTag::STARTUP, "transfer module context: %{public}s", moduleName.c_str());
            auto nativeRefPtr = StageContextTransfer::GetDynamicRef(env, context);
            contextRef = std::shared_ptr<NativeReference>(nativeRefPtr);
            StageContextTransfer::GetInstance().SaveContextRef(moduleName, contextRef);
        }
        startupTask->UpdateContextRef(contextRef);
    } else {
        TAG_LOGW(AAFwkTag::STARTUP, "Unknown startup task type: %{public}s", startupTask->GetType().c_str());
    }
}

ani_ref StartupTaskUtils::GetDependencyResult(ani_env *env, std::shared_ptr<StartupTaskResult> result)
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
} // namespace AbilityRuntime
} // namespace OHOS