/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_LIFECYCLE_DEAL_H
#define OHOS_ABILITY_RUNTIME_LIFECYCLE_DEAL_H

#include <memory>
#include <shared_mutex>

#include "ability_scheduler_interface.h"
#include "want.h"
#include "nocopyable.h"

namespace OHOS {
namespace AAFwk {
/**
 * @class LifecycleDeal
 * LifecycleDeal schedule ability life.
 */
class LifecycleDeal {
public:
    LifecycleDeal();
    virtual ~LifecycleDeal();

    /**
     * set scheduler for accessing ability
     *
     * @param scheduler, ability thread ipc proxy.
     */
    void SetScheduler(const sptr<IAbilityScheduler> &scheduler);

    /**
     * schedule ability life
     *
     */
    void Activate(const Want &want, LifeCycleStateInfo &stateInfo);
    void Inactivate(const Want &want, LifeCycleStateInfo &stateInfo, sptr<SessionInfo> sessionInfo = nullptr);
    /**
     * schedule ability life cycle to background
     */
    void MoveToBackground(const Want &want, LifeCycleStateInfo &stateInfo);
    /**
     * schedule ability onConnect
     */
    void ConnectAbility(const Want &want);
    /**
     * schedule ability onDisconnect
     */
    void DisconnectAbility(const Want &want);
    /**
     * schedule ability onDestroy
     */
    void Terminate(const Want &want, LifeCycleStateInfo &stateInfo, sptr<SessionInfo> sessionInfo = nullptr);
    /**
     * schedule ability onRequest
     */
    void CommandAbility(const Want &want, bool reStart, int startId);
    void CommandAbilityWindow(const Want &want, const sptr<SessionInfo> &sessionInfo, WindowCommand winCmd);
    void SaveAbilityState();
    void RestoreAbilityState(const PacMap &inState);
    /**
     * schedule ability life cycle to foreground
     */
    bool ForegroundNew(const Want &want, LifeCycleStateInfo &stateInfo,
        sptr<SessionInfo> sessionInfo = nullptr);
    /**
     * schedule ability life cycle to background
     */
    void BackgroundNew(const Want &want, LifeCycleStateInfo &stateInfo,
        sptr<SessionInfo> sessionInfo = nullptr);
    void ContinueAbility(const std::string& deviceId, uint32_t versionCode);
    void NotifyContinuationResult(int32_t result);
    void ShareData(const int32_t &uniqueId);
    bool PrepareTerminateAbility();
    void UpdateSessionToken(sptr<IRemoteObject> sessionToken);
    void ScheduleCollaborate(const Want &want);
    void NotifyAbilityRequestFailure(const std::string &requestId, const AppExecFwk::ElementName &element,
        const std::string &message);
    void NotifyAbilityRequestSuccess(const std::string &requestId, const AppExecFwk::ElementName &element);
    void NotifyAbilitiesRequestDone(const std::string &requestKey, int32_t resultCode);

private:
    sptr<IAbilityScheduler> GetScheduler();
    sptr<IAbilityScheduler> abilityScheduler_;  // kit interface used to schedule ability life
    std::shared_mutex schedulerMutex_;

    DISALLOW_COPY_AND_MOVE(LifecycleDeal);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_LIFECYCLE_DEAL_H
