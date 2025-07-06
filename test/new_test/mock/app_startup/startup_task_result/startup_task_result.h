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

#ifndef OHOS_ABILITY_RUNTIME_STARTUP_TASK_RESULT_H
#define OHOS_ABILITY_RUNTIME_STARTUP_TASK_RESULT_H

#include <string>

#include "startup_utils.h"

namespace OHOS {
namespace AppExecFwk {
template<typename T = void>
class AbilityTransactionCallbackInfo {
public:
    using CallbackFunc = std::function<void(T&)>;

    AbilityTransactionCallbackInfo() = default;
    ~AbilityTransactionCallbackInfo() = default;
};

template<>
class AbilityTransactionCallbackInfo<void> {
public:
    using CallbackFunc = std::function<void()>;

    AbilityTransactionCallbackInfo() = default;
    ~AbilityTransactionCallbackInfo() = default;
};
} // namespace AppExecFwk

namespace AbilityRuntime {
class StartupTaskResult {
public:
    StartupTaskResult() = default;
    ~StartupTaskResult() = default;
};

using StartupTaskResultCallback = AppExecFwk::AbilityTransactionCallbackInfo<const std::shared_ptr<StartupTaskResult>>;
using OnCompletedCallbackFunc = std::function<void(const std::shared_ptr<StartupTaskResult> &)>;
class OnCompletedCallback {
public:
    static OnCompletedCallback &GetStaticInstance()
    {
        static OnCompletedCallback instance;
        return instance;
    }

    OnCompletedCallback() = default;
    ~OnCompletedCallback() = default;

    MOCK_METHOD(void, MockOnCallback, (std::unique_ptr<StartupTaskResultCallback>, int32_t, const std::string&));
    MOCK_METHOD(void, MockOnCallback, (std::unique_ptr<StartupTaskResultCallback>,
        const std::shared_ptr<StartupTaskResult> &));

    static void OnCallback(std::unique_ptr<StartupTaskResultCallback> callback, int32_t resultCode,
        const std::string& resultMessage = "")
    {
        GetStaticInstance().MockOnCallback(std::move(callback), resultCode, resultMessage);
    }

    static void OnCallback(std::unique_ptr<StartupTaskResultCallback> callback,
        const std::shared_ptr<StartupTaskResult> &result)
    {
        GetStaticInstance().MockOnCallback(std::move(callback), result);
    }
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_STARTUP_TASK_RESULT_H

