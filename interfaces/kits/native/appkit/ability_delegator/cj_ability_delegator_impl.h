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

#ifndef OHOS_ABILITY_RUNTIME_CJ_ABILITY_DELEGATOR_IMPL_H
#define OHOS_ABILITY_RUNTIME_CJ_ABILITY_DELEGATOR_IMPL_H

#include <functional>
#include <list>
#include <map>
#include <vector>

#ifndef SUPPORT_GRAPHICS
#include "inttypes.h"
#endif

#include "ability_lifecycle_executor.h"
#include "cj_ability_delegator_infos.h"
#include "cj_iability_monitor.h"
#include "cj_iability_stage_monitor.h"
#include "delegator_thread.h"
#include "iability_delegator.h"
#include "shell_cmd_result.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
class CJAbilityDelegatorImpl : public std::enable_shared_from_this<CJAbilityDelegatorImpl>, public IAbilityDelegator {
public:
    enum class AbilityState : uint8_t {
        /**
         * Indicates that the ability has not been initialized.
         */
        UNINITIALIZED = 0,
        /**
         * Indicates that the ability is in the started state.
         */
        STARTED,
        /**
         * Indicates that the ability is in the foreground state.
         */
        FOREGROUND,
        /**
         * Indicates that the ability is in the background state.
         */
        BACKGROUND,
        /**
         * Indicates that the ability is in the stopped state.
         */
        STOPPED
    };
    /**
     * Definition of cleanup function.
     */
    using ClearFunc = std::function<void(const std::shared_ptr<ACJDelegatorAbilityProperty>&)>;

public:
    static std::shared_ptr<CJAbilityDelegatorImpl> Create(const std::shared_ptr<AbilityRuntime::Context>& context,
        std::unique_ptr<TestRunner> runner, const sptr<IRemoteObject>& observer);

    /**
     * A constructor used to create a CJAbilityDelegatorImpl instance with the input
     * parameter passed.
     *
     * @param context Indicates the ability runtime context.
     * @param runner Indicates the TestRunner object.
     * @param observer Indicates the TestObserver object.
     */
    CJAbilityDelegatorImpl(const std::shared_ptr<AbilityRuntime::Context>& context, std::unique_ptr<TestRunner> runner,
        const sptr<IRemoteObject>& observer);

    /**
     * Default deconstructor used to deconstruct.
     */
    ~CJAbilityDelegatorImpl();

    /**
     * Adds monitor for monitoring the lifecycle state changes of the ability.
     *
     * @param monitor, Indicates the monitor object.
     */
    void AddAbilityMonitor(const std::shared_ptr<CJIAbilityMonitor>& monitor);

    /**
     * Adds monitor for monitoring the lifecycle state changes of the
     * abilityStage.
     *
     * @param monitor, Indicates the stage monitor object.
     */
    void AddAbilityStageMonitor(const std::shared_ptr<CJIAbilityStageMonitor>& monitor);

    /**
     * Removes ability monitor.
     *
     * @param monitor, Indicates the specified monitor object.
     */
    void RemoveAbilityMonitor(const std::shared_ptr<CJIAbilityMonitor>& monitor);

    /**
     * Removes abilityStage monitor.
     *
     * @param monitor, Indicates the specified stage monitor object.
     */
    void RemoveAbilityStageMonitor(const std::shared_ptr<CJIAbilityStageMonitor>& monitor);

    /**
     * Clears all monitors.
     */
    void ClearAllMonitors() override;

    /**
     * Obtains the number of monitors.
     *
     * @return the number of monitors.
     */
    size_t GetMonitorsNum() override;

    /**
     * Obtains the number of stage monitors.
     *
     * @return the number of stage monitors.
     */
    size_t GetStageMonitorsNum() override;

    /**
     * Waits for the specified monitor and return the obtained ability.
     *
     * @param monitor, Indicates the specified monitor object.
     * @return the obtained ability.
     */
    std::shared_ptr<ACJDelegatorAbilityProperty> WaitAbilityMonitor(const std::shared_ptr<CJIAbilityMonitor>& monitor);

    /**
     * Waits for the specified monitor and return the obtained abilityStage.
     *
     * @param monitor, Indicates the specified stage monitor object.
     * @return the obtained abilityStage.
     */
    std::shared_ptr<CJDelegatorAbilityStageProperty> WaitAbilityStageMonitor(
        const std::shared_ptr<CJIAbilityStageMonitor>& monitor);

    /**
     * Waits for the specified monitor within the timeout time and return the
     * obtained ability.
     *
     * @param monitor, Indicates the specified monitor object.
     * @param timeoutMs, Indicates the specified time out time, in milliseconds.
     * @return the obtained ability.
     */
    std::shared_ptr<ACJDelegatorAbilityProperty> WaitAbilityMonitor(
        const std::shared_ptr<CJIAbilityMonitor>& monitor, const int64_t timeoutMs);

    /**
     * Waits for the specified monitor within the timeout time and return the
     * obtained abilityStage.
     *
     * @param monitor, Indicates the specified stage monitor object.
     * @param timeoutMs, Indicates the specified time out time, in milliseconds.
     * @return the obtained abilityStage.
     */
    std::shared_ptr<CJDelegatorAbilityStageProperty> WaitAbilityStageMonitor(
        const std::shared_ptr<CJIAbilityStageMonitor>& monitor, const int64_t timeoutMs);

    /**
     * Obtains the application context.
     *
     * @return the application context.
     */
    std::shared_ptr<AbilityRuntime::Context> GetAppContext() const;

    /**
     * Obtains the lifecycle state of the specified ability.
     *
     * @param token, Indicates the specified ability.
     * @return the lifecycle state of the specified ability.
     */
    CJAbilityDelegatorImpl::AbilityState GetAbilityState(const sptr<IRemoteObject>& token);

    /**
     * Obtains the ability that is currently being displayed.
     *
     * @return the ability that is currently being displayed.
     */
    std::shared_ptr<ACJDelegatorAbilityProperty> GetCurrentTopAbility();

    /**
     * Obtains the name of the thread.
     *
     * @return the name of the thread.
     */
    std::string GetThreadName() const override;

    /**
     * Notifies TestRunner to prepare.
     */
    void Prepare() override;

    /**
     * Notifies TestRunner to run.
     */
    void OnRun() override;

    /**
     * Starts an ability based on the given Want.
     *
     * @param want, Indicates the Want for starting the ability.
     * @return the result code.
     */
    ErrCode StartAbility(const AAFwk::Want& want);

    /**
     * Transits the specified ability to foreground.
     *
     * @param token, Indicates the specified ability.
     * @return true if succeed; returns false otherwise.
     */
    bool DoAbilityForeground(const sptr<IRemoteObject>& token);

    /**
     * Transits the specified ability to background.
     *
     * @param token, Indicates the specified ability.
     * @return true if succeed; returns false otherwise.
     */
    bool DoAbilityBackground(const sptr<IRemoteObject>& token);

    /**
     * Executes the specified shell command.
     *
     * @param cmd, Indicates the specified shell command.
     * @param timeoutSec, Indicates the specified time out time, in seconds.
     * @return the result of the specified shell command.
     */
    std::unique_ptr<ShellCmdResult> ExecuteShellCommand(const std::string& cmd, const int64_t timeoutSec);

    /**
     * Prints log information to the console.
     * The total length of the log information to be printed cannot exceed 1000
     * characters.
     *
     * @param msg, Indicates the log information to print.
     */
    void Print(const std::string& msg);

    /**
     * Saves ability properties when ability is started and notify monitors of
     * state changes.
     *
     * @param ability, Indicates the ability properties.
     */
    void PostPerformStart(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability);

    /**
     * Saves abilityStage properties when abilityStage is started and notify
     * monitors.
     *
     * @param abilityStage , Indicates the abilityStage properties.
     */
    void PostPerformStageStart(const std::shared_ptr<CJDelegatorAbilityStageProperty>& abilityStage);

    /**
     * Saves ability properties when scence is created and notify monitors of
     * state changes.
     *
     * @param ability, Indicates the ability properties.
     */
    void PostPerformScenceCreated(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability);

    /**
     * Saves ability properties when scence is restored and notify monitors of
     * state changes.
     *
     * @param ability, Indicates the ability properties.
     */
    void PostPerformScenceRestored(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability);

    /**
     * Saves ability properties when scence is destroyed and notify monitors of
     * state changes.
     *
     * @param ability, Indicates the ability properties.
     */
    void PostPerformScenceDestroyed(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability);

    /**
     * Saves ability properties when ability is in the foreground and notify
     * monitors of state changes.
     *
     * @param ability, Indicates the ability properties.
     */
    void PostPerformForeground(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability);

    /**
     * Saves ability properties when ability is in the background and notify
     * monitors of state changes.
     *
     * @param ability, Indicates the ability properties.
     */
    void PostPerformBackground(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability);

    /**
     * Saves ability properties when ability is stopped and notify monitors of
     * state changes.
     *
     * @param ability, Indicates the ability properties.
     */
    void PostPerformStop(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability);

    /**
     * Finishes user test.
     *
     * @param msg, Indicates the status information.The total length of the status
     * information cannot exceed 1000 characters.
     * @param resultCode, Indicates the result code.
     */
    void FinishUserTest(const std::string& msg, const int64_t resultCode);

    /**
     * Registers a function for cleanup.
     *
     * @param func, Indicates the cleanup function, called when the ability is
     * stopped.
     */
    void RegisterClearFunc(ClearFunc func);

private:
    CJAbilityDelegatorImpl::AbilityState ConvertAbilityState(
        const AbilityLifecycleExecutor::LifecycleState lifecycleState);
    void ProcessAbilityProperties(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability);
    void RemoveAbilityProperty(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability);
    std::shared_ptr<ACJDelegatorAbilityProperty> FindPropertyByToken(const sptr<IRemoteObject>& token);
    std::shared_ptr<ACJDelegatorAbilityProperty> FindPropertyByName(const std::string& name);
    inline void CallClearFunc(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability);

private:
    static constexpr size_t INFORMATION_MAX_LENGTH { 1000 };
    static constexpr size_t DELEGATOR_PRINT_MAX_LENGTH { 10000 };
    const std::string IS_DELEGATOR_CALL = "isDelegatorCall";

private:
    std::shared_ptr<AbilityRuntime::Context> appContext_;
    std::unique_ptr<TestRunner> testRunner_;
    sptr<IRemoteObject> observer_;

    std::unique_ptr<DelegatorThread> delegatorThread_;
    std::list<std::shared_ptr<ACJDelegatorAbilityProperty>> abilityProperties_;
    std::vector<std::shared_ptr<CJIAbilityMonitor>> abilityMonitors_;
    std::vector<std::shared_ptr<CJIAbilityStageMonitor>> abilityStageMonitors_;

    ClearFunc clearFunc_;

    std::mutex mutexMonitor_;
    std::mutex mutexAbilityProperties_;
    std::mutex mutexStageMonitor_;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_ABILITY_DELEGATOR_H