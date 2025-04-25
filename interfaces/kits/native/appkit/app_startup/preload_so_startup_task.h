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

#ifndef OHOS_ABILITY_RUNTIME_PRELOAD_SO_STARTUP_TASK_H
#define OHOS_ABILITY_RUNTIME_PRELOAD_SO_STARTUP_TASK_H

#include "app_startup_task.h"

namespace OHOS {
namespace AbilityRuntime {
class PreloadSoStartupTask : public AppStartupTask {
public:
    static const std::string TASK_TYPE;

    PreloadSoStartupTask(const std::string& name, const std::string& ohmUrl, const std::string& path = "");

    ~PreloadSoStartupTask() override;

    const std::string &GetType() const override;

    int32_t RunTaskInit(std::unique_ptr<StartupTaskResultCallback> callback) override;

    int32_t RunTaskOnDependencyCompleted(const std::string& dependencyName,
        const std::shared_ptr<StartupTaskResult>& result) override;

private:
    std::string ohmUrl_;
    std::string path_;
    bool isExcludeFromAutoStart_ = false;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_PRELOAD_SO_STARTUP_TASK_H
