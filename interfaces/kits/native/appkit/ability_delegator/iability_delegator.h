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

#ifndef OHOS_ABILITY_RUNTIME_IABILITY_DELEGATOR_H
#define OHOS_ABILITY_RUNTIME_IABILITY_DELEGATOR_H

#include "context.h"
#include "runtime.h"
#include "test_runner.h"

namespace OHOS {
namespace AppExecFwk {

class IAbilityDelegator {
public:
    static std::shared_ptr<IAbilityDelegator> Create(const std::unique_ptr<AbilityRuntime::Runtime>& runtime,
        const std::shared_ptr<AbilityRuntime::Context>& context, std::unique_ptr<TestRunner> runner,
        const sptr<IRemoteObject>& observer);

    IAbilityDelegator() = default;

    virtual ~IAbilityDelegator() = default;

    /**
     * Clears all monitors.
     */
    virtual void ClearAllMonitors();

    /**
     * Obtains the number of monitors.
     *
     * @return the number of monitors.
     */
    virtual size_t GetMonitorsNum();

    /**
     * Obtains the number of stage monitors.
     *
     * @return the number of stage monitors.
     */
    virtual size_t GetStageMonitorsNum();

    /**
     * Obtains the name of the thread.
     *
     * @return the name of the thread.
     */
    virtual std::string GetThreadName() const;

    /**
     * Notifies TestRunner to prepare.
     */
    virtual void Prepare();

    /**
     * Notifies TestRunner to run.
     */
    virtual void OnRun();
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_IABILITY_DELEGATOR_H