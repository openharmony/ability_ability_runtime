/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_BACKGROUND_TASK_OBSERVER_H
#define OHOS_ABILITY_RUNTIME_BACKGROUND_TASK_OBSERVER_H

#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
#include "background_task_mgr_helper.h"
#include "background_task_subscriber.h"
#include "iremote_object.h"
#include "app_mgr_interface.h"

namespace OHOS {
namespace AAFwk {
class BackgroundTaskObserver : public BackgroundTaskMgr::BackgroundTaskSubscriber,
                               public std::enable_shared_from_this<BackgroundTaskObserver> {
public:
    BackgroundTaskObserver();
    virtual ~BackgroundTaskObserver();
    bool IsBackgroundTaskUid(const int uid);
    bool IsEfficiencyResourcesTaskUid(const int uid);

    void GetContinuousTaskApps();
    void GetEfficiencyResourcesTaskApps();

private:
    void OnContinuousTaskStart(const std::shared_ptr<BackgroundTaskMgr::ContinuousTaskCallbackInfo>
        &continuousTaskCallbackInfo) override;

    void OnContinuousTaskStop(const std::shared_ptr<BackgroundTaskMgr::ContinuousTaskCallbackInfo>
        &continuousTaskCallbackInfo) override;

    void OnAppEfficiencyResourcesApply(
        const std::shared_ptr<BackgroundTaskMgr::ResourceCallbackInfo> &resourceInfo) override;

    void OnAppEfficiencyResourcesReset(
        const std::shared_ptr<BackgroundTaskMgr::ResourceCallbackInfo> &resourceInfo) override;

    void OnProcEfficiencyResourcesApply(
        const std::shared_ptr<BackgroundTaskMgr::ResourceCallbackInfo> &resourceInfo) override;

    void OnProcEfficiencyResourcesReset(
        const std::shared_ptr<BackgroundTaskMgr::ResourceCallbackInfo> &resourceInfo) override;

    sptr<AppExecFwk::IAppMgr> GetAppManager();

private:
    sptr<OHOS::AppExecFwk::IAppMgr> appManager_ = nullptr;
    std::list<int> bgTaskUids_;
    std::list<int> efficiencyUids_;
    std::mutex efficiencyMutex_;
    std::mutex bgTaskMutex_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif
#endif  // OHOS_ABILITY_RUNTIME_BACKGROUND_TASK_OBSERVER_H
