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

#include "ext_native_startup_manager.h"

#include <memory>

#include "ffrt.h"
#include "hilog_tag_wrapper.h"
#include "startup_task_manager.h"
#include "startup_manager.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
class ExtNativeStartupTaskWrapper : public StartupTask {
public:
    explicit ExtNativeStartupTaskWrapper(const std::string& name,
        const std::shared_ptr<ExtNativeStartupTask> &extNativeStartupTask_)
        : StartupTask(name), extNativeStartupTask_(extNativeStartupTask_)
    {}

    ~ExtNativeStartupTaskWrapper() override = default;

    const std::string &GetType() const override
    {
        return name_;
    }

    int32_t RunTaskInit(std::unique_ptr<StartupTaskResultCallback> callback) override
    {
        callback_ = std::move(callback);
        auto self = std::static_pointer_cast<ExtNativeStartupTaskWrapper>(shared_from_this());
        auto runTaskInitCallback = [weak = std::weak_ptr(self)]() {
            auto self = weak.lock();
            if (self == nullptr) {
                TAG_LOGE(AAFwkTag::STARTUP, "null self");
                return;
            }
            self->RunTaskInitInner();
        };
        ffrt::submit(runTaskInitCallback);
        return ERR_OK;
    }

    int32_t RunTaskOnDependencyCompleted(const std::string& dependencyName,
        const std::shared_ptr<StartupTaskResult>& result) override
    {
        // no onDependencyCompleted callback, do nothing
        return ERR_OK;
    }

private:
    std::shared_ptr<ExtNativeStartupTask> extNativeStartupTask_;
    std::unique_ptr<StartupTaskResultCallback> callback_;

    void RunTaskInitInner()
    {
        TAG_LOGD(AAFwkTag::STARTUP, "run ext native task: %{public}s", name_.c_str());
        if (extNativeStartupTask_ == nullptr) {
            TAG_LOGE(AAFwkTag::STARTUP, "null extNativeStartupTask");
            OnCompletedCallback::OnCallback(std::move(callback_), ERR_STARTUP_INTERNAL_ERROR);
            return;
        }
        int32_t code = extNativeStartupTask_->RunTask();
        if (code != ERR_OK) {
            // the failure of the ext startup task does not affect other tasks
            TAG_LOGE(AAFwkTag::STARTUP, "ext startup task %{public}s return %{public}d", name_.c_str(), code);
        }
        OnCompletedCallback::OnCallback(std::move(callback_), ERR_OK);
    }
};
} // namespace
void ExtNativeStartupManager::LoadExtStartupTask()
{
    TAG_LOGD(AAFwkTag::STARTUP, "call");
}

int32_t ExtNativeStartupManager::BuildExtStartupTask(const std::shared_ptr<ExtNativeStartupTask> &extNativeStartupTask,
    std::shared_ptr<StartupTask> &startupTask)
{
    if (extNativeStartupTask == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null extNativeStartupTask");
        return ERR_STARTUP_INVALID_VALUE;
    }
    startupTask = std::make_shared<ExtNativeStartupTaskWrapper>(extNativeStartupTask->GetName(), extNativeStartupTask);
    startupTask->SetCallCreateOnMainThread(false);
    startupTask->SetWaitOnMainThread(false);
    return ERR_OK;
}

int32_t ExtNativeStartupManager::RunNativeStartupTask(
    const std::map<std::string, std::shared_ptr<StartupTask>> &nativeStartupTask)
{
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    if (startupManager == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "failed to get startupManager");
        return ERR_STARTUP_INTERNAL_ERROR;
    }
    std::shared_ptr<StartupTaskManager> startupTaskManager;
    int32_t result = startupManager->BuildStartupTaskManager(nativeStartupTask, startupTaskManager);
    if (result != ERR_OK || startupTaskManager == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "build preload startup task manager failed, result: %{public}d", result);
        return result;
    }
    result = startupTaskManager->Prepare();
    if (result != ERR_OK) {
        TAG_LOGE(AAFwkTag::STARTUP, "native startup task manager prepare failed, result: %{public}d", result);
        return result;
    }
    TAG_LOGD(AAFwkTag::STARTUP, "native startup task manager run");
    startupTaskManager->Run(nullptr);
    return ERR_OK;
}
} // namespace AbilityRuntime
} // namespace OHOS