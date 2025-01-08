/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "cj_ability_delegator_impl.h"

#include "ability_delegator_registry.h"
#include "ability_manager_client.h"
#include "hilog_tag_wrapper.h"
#include "itest_observer.h"
#include "ohos_application.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<CJAbilityDelegatorImpl> CJAbilityDelegatorImpl::Create(
    const std::shared_ptr<AbilityRuntime::Context>& context, std::unique_ptr<TestRunner> runner,
    const sptr<IRemoteObject>& observer)
{
    return std::make_shared<CJAbilityDelegatorImpl>(context, std::move(runner), observer);
}

CJAbilityDelegatorImpl::CJAbilityDelegatorImpl(const std::shared_ptr<AbilityRuntime::Context>& context,
    std::unique_ptr<TestRunner> runner, const sptr<IRemoteObject>& observer)
    : appContext_(context), testRunner_(std::move(runner)), observer_(observer)
{}

CJAbilityDelegatorImpl::~CJAbilityDelegatorImpl() {}

void CJAbilityDelegatorImpl::AddAbilityMonitor(const std::shared_ptr<CJIAbilityMonitor>& monitor)
{
    if (!monitor) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return;
    }

    std::unique_lock<std::mutex> lck(mutexMonitor_);
    auto pos = std::find(abilityMonitors_.begin(), abilityMonitors_.end(), monitor);
    if (pos != abilityMonitors_.end()) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "monitor has been added");
        return;
    }

    abilityMonitors_.emplace_back(monitor);
}

void CJAbilityDelegatorImpl::AddAbilityStageMonitor(const std::shared_ptr<CJIAbilityStageMonitor>& monitor)
{
    if (!monitor) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return;
    }
    std::unique_lock<std::mutex> lck(mutexStageMonitor_);
    auto pos = std::find(abilityStageMonitors_.begin(), abilityStageMonitors_.end(), monitor);
    if (pos != abilityStageMonitors_.end()) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "stage monitor added");
        return;
    }
    abilityStageMonitors_.emplace_back(monitor);
}

void CJAbilityDelegatorImpl::RemoveAbilityMonitor(const std::shared_ptr<CJIAbilityMonitor>& monitor)
{
    if (!monitor) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return;
    }

    std::unique_lock<std::mutex> lck(mutexMonitor_);
    auto pos = std::find(abilityMonitors_.begin(), abilityMonitors_.end(), monitor);
    if (pos != abilityMonitors_.end()) {
        abilityMonitors_.erase(pos);
    }
}

void CJAbilityDelegatorImpl::RemoveAbilityStageMonitor(const std::shared_ptr<CJIAbilityStageMonitor>& monitor)
{
    if (!monitor) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return;
    }
    std::unique_lock<std::mutex> lck(mutexStageMonitor_);
    auto pos = std::find(abilityStageMonitors_.begin(), abilityStageMonitors_.end(), monitor);
    if (pos != abilityStageMonitors_.end()) {
        abilityStageMonitors_.erase(pos);
    }
}

void CJAbilityDelegatorImpl::ClearAllMonitors()
{
    std::unique_lock<std::mutex> lck(mutexMonitor_);
    abilityMonitors_.clear();
}

size_t CJAbilityDelegatorImpl::GetMonitorsNum()
{
    std::unique_lock<std::mutex> lck(mutexMonitor_);
    return abilityMonitors_.size();
}

size_t CJAbilityDelegatorImpl::GetStageMonitorsNum()
{
    std::unique_lock<std::mutex> lck(mutexStageMonitor_);
    return abilityStageMonitors_.size();
}

std::shared_ptr<ACJDelegatorAbilityProperty> CJAbilityDelegatorImpl::WaitAbilityMonitor(
    const std::shared_ptr<CJIAbilityMonitor>& monitor)
{
    if (!monitor) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return {};
    }

    AddAbilityMonitor(monitor);

    auto obtainedAbility = monitor->WaitForAbility();
    if (!obtainedAbility) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid obtained ability");
        return {};
    }

    return obtainedAbility;
}

std::shared_ptr<CJDelegatorAbilityStageProperty> CJAbilityDelegatorImpl::WaitAbilityStageMonitor(
    const std::shared_ptr<CJIAbilityStageMonitor>& monitor)
{
    if (!monitor) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid monitor");
        return nullptr;
    }

    AddAbilityStageMonitor(monitor);
    auto stage = monitor->WaitForAbilityStage();
    if (!stage) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid abilityStage");
        return nullptr;
    }
    return stage;
}

std::shared_ptr<ACJDelegatorAbilityProperty> CJAbilityDelegatorImpl::WaitAbilityMonitor(
    const std::shared_ptr<CJIAbilityMonitor>& monitor, const int64_t timeoutMs)
{
    if (!monitor) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return {};
    }

    AddAbilityMonitor(monitor);

    auto obtainedAbility = monitor->WaitForAbility(timeoutMs);
    if (!obtainedAbility) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid obtained ability");
        return {};
    }

    return obtainedAbility;
}

std::shared_ptr<CJDelegatorAbilityStageProperty> CJAbilityDelegatorImpl::WaitAbilityStageMonitor(
    const std::shared_ptr<CJIAbilityStageMonitor>& monitor, const int64_t timeoutMs)
{
    if (!monitor) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid monitor");
        return nullptr;
    }
    AddAbilityStageMonitor(monitor);
    auto stage = monitor->WaitForAbilityStage(timeoutMs);
    if (!stage) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid obtained abilityStage");
        return nullptr;
    }
    return stage;
}

std::shared_ptr<AbilityRuntime::Context> CJAbilityDelegatorImpl::GetAppContext() const
{
    return appContext_;
}

CJAbilityDelegatorImpl::AbilityState CJAbilityDelegatorImpl::GetAbilityState(const sptr<IRemoteObject>& token)
{
    if (!token) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return CJAbilityDelegatorImpl::AbilityState::UNINITIALIZED;
    }

    std::unique_lock<std::mutex> lck(mutexAbilityProperties_);
    auto existedProperty = FindPropertyByToken(token);
    if (!existedProperty) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "unknown ability token");
        return CJAbilityDelegatorImpl::AbilityState::UNINITIALIZED;
    }

    return ConvertAbilityState(existedProperty->lifecycleState_);
}

std::shared_ptr<ACJDelegatorAbilityProperty> CJAbilityDelegatorImpl::GetCurrentTopAbility()
{
    AppExecFwk::ElementName elementName = AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility();
    std::string bundleName = elementName.GetBundleName();
    std::string abilityName = elementName.GetAbilityName();
    if (abilityName.empty()) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "get topAbility failed");
        return {};
    }

    if (!bundleName.empty()) {
        std::string::size_type pos = abilityName.find(bundleName);
        if (pos == std::string::npos || pos != 0) {
            abilityName = bundleName + "." + abilityName;
        }
    }

    std::unique_lock<std::mutex> lck(mutexAbilityProperties_);
    auto existedProperty = FindPropertyByName(abilityName);
    if (!existedProperty) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "unknown ability name");
        return {};
    }

    return existedProperty;
}

std::string CJAbilityDelegatorImpl::GetThreadName() const
{
    return {};
}

void CJAbilityDelegatorImpl::Prepare()
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "Enter");
    if (!testRunner_) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid TestRunner");
        return;
    }

    TAG_LOGD(AAFwkTag::DELEGATOR, "call js onPrepare()");
    testRunner_->Prepare();

    if (!delegatorThread_) {
        delegatorThread_ = std::make_unique<DelegatorThread>(true);
        if (!delegatorThread_) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "create delegatorThread failed");
            return;
        }
    }

    auto runTask = [this]() { this->OnRun(); };
    if (!delegatorThread_->Run(runTask)) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "run task on delegatorThread failed");
    }
}

void CJAbilityDelegatorImpl::OnRun()
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "Enter");
    if (!testRunner_) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid TestRunner");
        return;
    }

    TAG_LOGD(AAFwkTag::DELEGATOR, "call js onRun()");
    testRunner_->Run();
}

ErrCode CJAbilityDelegatorImpl::StartAbility(const AAFwk::Want& want)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "Enter");

    auto realWant(want);
    auto delegatorArgs = AbilityDelegatorRegistry::GetArguments();
    if (delegatorArgs && delegatorArgs->FindDebugFlag()) {
        TAG_LOGI(AAFwkTag::DELEGATOR, "start with debug");
        realWant.SetParam("debugApp", true);
    }
    realWant.SetParam(IS_DELEGATOR_CALL, true);

    return AbilityManagerClient::GetInstance()->StartAbility(realWant);
}

bool CJAbilityDelegatorImpl::DoAbilityForeground(const sptr<IRemoteObject>& token)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called");

    if (!token) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return false;
    }

    auto ret = AAFwk::AbilityManagerClient::GetInstance()->DelegatorDoAbilityForeground(token);
    if (ret) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "call DelegatorDoAbilityForeground failed, reson: %{public}d", ret);
        return false;
    }

    return true;
}

bool CJAbilityDelegatorImpl::DoAbilityBackground(const sptr<IRemoteObject>& token)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "Enter");

    if (!token) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return false;
    }

    auto ret = AAFwk::AbilityManagerClient::GetInstance()->DelegatorDoAbilityBackground(token);
    if (ret) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "call doAbilityBackground failed, reson: %{public}d", ret);
        return false;
    }

    return true;
}

std::unique_ptr<ShellCmdResult> CJAbilityDelegatorImpl::ExecuteShellCommand(
    const std::string& cmd, const int64_t timeoutSec)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "command : %{public}s, timeout : %{public}" PRId64, cmd.data(), timeoutSec);

    if (cmd.empty()) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid cmd");
        return {};
    }

    auto testObserver = iface_cast<ITestObserver>(observer_);
    if (!testObserver) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid testObserver");
        return {};
    }

    auto result = testObserver->ExecuteShellCommand(cmd, timeoutSec);
    return std::make_unique<ShellCmdResult>(result);
}

void CJAbilityDelegatorImpl::Print(const std::string& msg)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "Enter");

    auto testObserver = iface_cast<ITestObserver>(observer_);
    if (!testObserver) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid testObserver");
        return;
    }

    auto realMsg(msg);
    if (realMsg.length() > DELEGATOR_PRINT_MAX_LENGTH) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "too long message");
        realMsg.resize(DELEGATOR_PRINT_MAX_LENGTH);
    }
    TAG_LOGI(AAFwkTag::DELEGATOR, "message to print : %{public}s", realMsg.data());

    testObserver->TestStatus(realMsg, 0);
}

void CJAbilityDelegatorImpl::PostPerformStart(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called");

    if (!ability) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return;
    }

    ProcessAbilityProperties(ability);

    std::unique_lock<std::mutex> lck(mutexMonitor_);
    if (abilityMonitors_.empty()) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "empty abilityMonitors");
        return;
    }

    for (auto& monitor : abilityMonitors_) {
        if (!monitor) {
            continue;
        }

        if (monitor->Match(ability, true)) {
            monitor->OnAbilityStart(ability->cjObject_);
        }
    }
}

void CJAbilityDelegatorImpl::PostPerformStageStart(const std::shared_ptr<CJDelegatorAbilityStageProperty>& abilityStage)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called");
    if (!abilityStage) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return;
    }

    std::unique_lock<std::mutex> lck(mutexStageMonitor_);
    if (abilityStageMonitors_.empty()) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "null abilityStageMonitors");
        return;
    }

    for (auto& monitor : abilityStageMonitors_) {
        if (!monitor) {
            continue;
        }
        monitor->Match(abilityStage, true);
    }
}

void CJAbilityDelegatorImpl::PostPerformScenceCreated(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called");

    if (!ability) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return;
    }

    ProcessAbilityProperties(ability);

    std::unique_lock<std::mutex> lck(mutexMonitor_);
    if (abilityMonitors_.empty()) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid abilityMonitors");
        return;
    }

    for (auto& monitor : abilityMonitors_) {
        if (!monitor) {
            continue;
        }

        if (monitor->Match(ability)) {
            monitor->OnWindowStageCreate(ability->cjObject_);
        }
    }
}

void CJAbilityDelegatorImpl::PostPerformScenceRestored(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called");

    if (!ability) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return;
    }

    ProcessAbilityProperties(ability);

    std::unique_lock<std::mutex> lck(mutexMonitor_);
    if (abilityMonitors_.empty()) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "null abilityMonitors");
        return;
    }

    for (auto& monitor : abilityMonitors_) {
        if (!monitor) {
            continue;
        }

        if (monitor->Match(ability)) {
            monitor->OnWindowStageRestore(ability->cjObject_);
        }
    }
}

void CJAbilityDelegatorImpl::PostPerformScenceDestroyed(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called");

    if (!ability) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return;
    }

    ProcessAbilityProperties(ability);

    std::unique_lock<std::mutex> lck(mutexMonitor_);
    if (abilityMonitors_.empty()) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "null abilityMonitors");
        return;
    }

    for (auto& monitor : abilityMonitors_) {
        if (!monitor) {
            continue;
        }

        if (monitor->Match(ability)) {
            monitor->OnWindowStageDestroy(ability->cjObject_);
        }
    }
}

void CJAbilityDelegatorImpl::PostPerformForeground(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called");

    if (!ability) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return;
    }

    ProcessAbilityProperties(ability);

    std::unique_lock<std::mutex> lck(mutexMonitor_);
    if (abilityMonitors_.empty()) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid abilityMonitors");
        return;
    }

    for (auto& monitor : abilityMonitors_) {
        if (!monitor) {
            continue;
        }

        if (monitor->Match(ability)) {
            monitor->OnAbilityForeground(ability->cjObject_);
        }
    }
}

void CJAbilityDelegatorImpl::PostPerformBackground(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "called");

    if (!ability) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return;
    }

    ProcessAbilityProperties(ability);

    std::unique_lock<std::mutex> lck(mutexMonitor_);
    if (abilityMonitors_.empty()) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid abilityMonitors");
        return;
    }

    for (auto& monitor : abilityMonitors_) {
        if (!monitor) {
            continue;
        }

        if (monitor->Match(ability)) {
            monitor->OnAbilityBackground(ability->cjObject_);
        }
    }
}

void CJAbilityDelegatorImpl::PostPerformStop(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "Enter");

    if (!ability) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return;
    }

    ProcessAbilityProperties(ability);

    std::unique_lock<std::mutex> lck(mutexMonitor_);
    if (abilityMonitors_.empty()) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid abilityMonitors");
        return;
    }

    for (auto& monitor : abilityMonitors_) {
        if (!monitor) {
            continue;
        }

        if (monitor->Match(ability)) {
            monitor->OnAbilityStop(ability->cjObject_);
        }
    }

    RemoveAbilityProperty(ability);
    CallClearFunc(ability);
}

CJAbilityDelegatorImpl::AbilityState CJAbilityDelegatorImpl::ConvertAbilityState(
    const AbilityLifecycleExecutor::LifecycleState lifecycleState)
{
    CJAbilityDelegatorImpl::AbilityState abilityState { CJAbilityDelegatorImpl::AbilityState::UNINITIALIZED };
    switch (lifecycleState) {
        case AbilityLifecycleExecutor::LifecycleState::STARTED_NEW:
            abilityState = CJAbilityDelegatorImpl::AbilityState::STARTED;
            break;
        case AbilityLifecycleExecutor::LifecycleState::FOREGROUND_NEW:
            abilityState = CJAbilityDelegatorImpl::AbilityState::FOREGROUND;
            break;
        case AbilityLifecycleExecutor::LifecycleState::BACKGROUND_NEW:
            abilityState = CJAbilityDelegatorImpl::AbilityState::BACKGROUND;
            break;
        case AbilityLifecycleExecutor::LifecycleState::STOPED_NEW:
            abilityState = CJAbilityDelegatorImpl::AbilityState::STOPPED;
            break;
        default:
            TAG_LOGE(AAFwkTag::DELEGATOR, "Unknown lifecycleState");
            break;
    }

    return abilityState;
}

void CJAbilityDelegatorImpl::ProcessAbilityProperties(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "Enter");

    if (!ability) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid ability property");
        return;
    }

    TAG_LOGW(AAFwkTag::DELEGATOR, "ability property : name : %{public}s, state : %{public}d", ability->name_.data(),
        ability->lifecycleState_);

    std::unique_lock<std::mutex> lck(mutexAbilityProperties_);
    auto existedProperty = FindPropertyByToken(ability->token_);
    if (existedProperty) {
        // update
        existedProperty->lifecycleState_ = ability->lifecycleState_;
        return;
    }

    abilityProperties_.emplace_back(ability);
}

void CJAbilityDelegatorImpl::RemoveAbilityProperty(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability)
{
    TAG_LOGD(AAFwkTag::DELEGATOR, "called");

    if (!ability) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid ability property");
        return;
    }

    TAG_LOGI(AAFwkTag::DELEGATOR, "ability property { name : %{public}s, state : %{public}d }", ability->name_.data(),
        ability->lifecycleState_);

    std::unique_lock<std::mutex> lck(mutexAbilityProperties_);
    abilityProperties_.remove_if(
        [ability](const auto& properties) { return ability->fullName_ == properties->fullName_; });
}

std::shared_ptr<ACJDelegatorAbilityProperty> CJAbilityDelegatorImpl::FindPropertyByToken(
    const sptr<IRemoteObject>& token)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "Enter");

    if (!token) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return {};
    }

    for (const auto& it : abilityProperties_) {
        if (!it) {
            TAG_LOGW(AAFwkTag::DELEGATOR, "invalid ability property");
            continue;
        }

        if (token == it->token_) {
            TAG_LOGD(AAFwkTag::DELEGATOR, "property exist");
            return it;
        }
    }

    return {};
}

std::shared_ptr<ACJDelegatorAbilityProperty> CJAbilityDelegatorImpl::FindPropertyByName(const std::string& name)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "find property by %{public}s", name.c_str());

    if (name.empty()) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "invalid params");
        return {};
    }

    for (const auto& it : abilityProperties_) {
        if (!it) {
            TAG_LOGW(AAFwkTag::DELEGATOR, "invalid ability property");
            continue;
        }

        if (name == it->fullName_) {
            TAG_LOGI(AAFwkTag::DELEGATOR, "property exist");
            return it;
        }
    }

    return {};
}

void CJAbilityDelegatorImpl::FinishUserTest(const std::string& msg, const int64_t resultCode)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "msg: %{public}s, code: %{public}" PRId64, msg.data(), resultCode);

    if (!observer_) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid observer");
        return;
    }

    auto delegatorArgs = AbilityDelegatorRegistry::GetArguments();
    if (!delegatorArgs) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid args");
        return;
    }

    auto realMsg(msg);
    if (realMsg.length() > INFORMATION_MAX_LENGTH) {
        TAG_LOGW(AAFwkTag::DELEGATOR, "too long message");
        realMsg.resize(INFORMATION_MAX_LENGTH);
    }

    const auto& bundleName = delegatorArgs->GetTestBundleName();
    auto err = AAFwk::AbilityManagerClient::GetInstance()->FinishUserTest(realMsg, resultCode, bundleName);
    if (err) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "call FinishUserTest failed: %{public}d", err);
    }
}

void CJAbilityDelegatorImpl::RegisterClearFunc(ClearFunc func)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "Enter");
    if (!func) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid func");
        return;
    }

    clearFunc_ = func;
}

inline void CJAbilityDelegatorImpl::CallClearFunc(const std::shared_ptr<ACJDelegatorAbilityProperty>& ability)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "Enter");
    if (clearFunc_) {
        clearFunc_(ability);
    }
}
} // namespace AppExecFwk
} // namespace OHOS
