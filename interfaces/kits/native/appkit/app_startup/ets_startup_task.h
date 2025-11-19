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

#ifndef OHOS_ABILITY_RUNTIME_ETS_STARTUP_TASK_H
#define OHOS_ABILITY_RUNTIME_ETS_STARTUP_TASK_H

#include "app_startup_task.h"
#include "ets_native_reference.h"
#include "ets_runtime.h"
#include "ets_startup_task_result.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsStartupTask : public AppStartupTask {
public:

    EtsStartupTask(ETSRuntime &etsRuntime, const StartupTaskInfo &info, bool lazyLoad);

    ~EtsStartupTask() override;

    const std::string &GetType() const override;

    int32_t RunTaskInit(std::unique_ptr<StartupTaskResultCallback> callback) override;

    int32_t RunTaskOnDependencyCompleted(const std::string &dependencyName,
        const std::shared_ptr<StartupTaskResult> &result) override;

    void OnAsyncTaskCompleted(const std::shared_ptr<StartupTaskResult> &result);

    void UpdateContextRef(std::shared_ptr<NativeReference> contextJsRef) override;

    void UpdateContextRef(ani_ref contextRef);

private:
    ETSRuntime &etsRuntime_;
    ani_ref contextRef_ = nullptr;
    ani_ref startupRef_ = nullptr;
    std::string srcEntry_;
    std::string ohmUrl_;
    std::string hapPath_;
    bool esModule_ = true;
    std::shared_ptr<StartupTaskResultCallback> resultCallback_;

    int32_t LoadEtsOhmUrl();
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_STARTUP_TASK_H