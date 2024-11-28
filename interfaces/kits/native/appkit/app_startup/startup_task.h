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

#ifndef OHOS_ABILITY_RUNTIME_STARTUP_TASK_H
#define OHOS_ABILITY_RUNTIME_STARTUP_TASK_H

#include <string>
#include <vector>
#include <memory>

#include "startup_task_result.h"

namespace OHOS {
namespace AbilityRuntime {
class StartupTask : public std::enable_shared_from_this<StartupTask> {
public:
    enum class State {
        INVALID,
        CREATED,
        INITIALIZING,
        INITIALIZED,
    };

    explicit StartupTask(const std::string &name);

    virtual ~StartupTask();

    const std::string& GetName() const;

    std::vector<std::string> GetDependencies() const;

    void SetDependencies(const std::vector<std::string> &dependencies);

    uint32_t GetDependenciesCount() const;

    bool GetWaitOnMainThread() const;

    void SetWaitOnMainThread(bool waitOnMainThread);

    bool GetCallCreateOnMainThread() const;

    void SetCallCreateOnMainThread(bool callCreateOnMainThread);

    void SaveResult(const std::shared_ptr<StartupTaskResult> &result);

    int32_t RemoveResult();

    const std::shared_ptr<StartupTaskResult>& GetResult() const;

    int32_t RunTaskPreInit(std::unique_ptr<StartupTaskResultCallback>& callback);

    virtual const std::string &GetType() const = 0;

    virtual int32_t RunTaskInit(std::unique_ptr<StartupTaskResultCallback> callback) = 0;

    virtual int32_t RunTaskOnDependencyCompleted(const std::string &name,
        const std::shared_ptr<StartupTaskResult> &result) = 0;

    State GetState() const;

    int32_t AddExtraCallback(std::unique_ptr<StartupTaskResultCallback> callback);

    void CallExtraCallback(const std::shared_ptr<StartupTaskResult> &result);

protected:
    std::string name_;
    std::vector<std::string> dependencies_;
    bool waitOnMainThread_ = true;
    bool callCreateOnMainThread_ = true;
    std::shared_ptr<StartupTaskResult> result_;
    State state_ = State::INVALID;
    std::vector<std::unique_ptr<StartupTaskResultCallback>> extraCallbacks_;

    std::string DumpDependencies() const;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_STARTUP_TASK_H
