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

#ifndef OHOS_ABILITY_RUNTIME_STARTUP_TASK_H
#define OHOS_ABILITY_RUNTIME_STARTUP_TASK_H

#include <memory>
#include <gmock/gmock.h>

#include "startup_task_result.h"

namespace OHOS {
namespace AbilityRuntime {
class StartupTask;
class StartupTaskInstanceMgr {
public:
    static StartupTaskInstanceMgr &GetInstance()
    {
        static StartupTaskInstanceMgr instance;
        return instance;
    }

    MOCK_METHOD(void, Constructor, (StartupTask&));

private:
    StartupTaskInstanceMgr() = default;
    ~StartupTaskInstanceMgr() = default;
};

class StartupTask : public std::enable_shared_from_this<StartupTask> {
public:
    explicit StartupTask(const std::string &name) : name_(name)
    {
        StartupTaskInstanceMgr::GetInstance().Constructor(*this);
    }

    virtual ~StartupTask() = default;

    virtual const std::string &GetType() const = 0;
    virtual int32_t RunTaskInit(std::unique_ptr<StartupTaskResultCallback> callback) = 0;
    virtual int32_t RunTaskOnDependencyCompleted(const std::string &dependencyName,
        const std::shared_ptr<StartupTaskResult> &result) = 0;

    MOCK_METHOD(bool, GetWaitOnMainThread, ());
    MOCK_METHOD(void, SetWaitOnMainThread, (bool));
    MOCK_METHOD(bool, GetCallCreateOnMainThread, ());
    MOCK_METHOD(void, SetCallCreateOnMainThread, (bool));
    MOCK_METHOD((const std::string&), GetName, (), (const));
    std::string name_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_STARTUP_TASK_H
