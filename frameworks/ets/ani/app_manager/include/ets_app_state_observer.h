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

#ifndef OHOS_ABILITY_RUNTIME_ETS_APP_STATE_OBSERVER_H
#define OHOS_ABILITY_RUNTIME_ETS_APP_STATE_OBSERVER_H

#include "ani_common_util.h"
#include "application_state_observer_stub.h"
#include "event_handler.h"
#include "ets_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
using OHOS::AppExecFwk::ApplicationStateObserverStub;
using OHOS::AppExecFwk::AppStateData;
using OHOS::AppExecFwk::AbilityStateData;
using OHOS::AppExecFwk::ProcessData;
class EtsAppStateObserver : public ApplicationStateObserverStub {
public:
    explicit EtsAppStateObserver(ani_vm *etsVm);
    ~EtsAppStateObserver() override;
    void OnForegroundApplicationChanged(const AppStateData &appStateData) override;
    void OnAbilityStateChanged(const AbilityStateData &abilityStateData) override;
    void OnExtensionStateChanged(const AbilityStateData &abilityStateData) override;
    void OnProcessCreated(const ProcessData &processData) override;
    void OnProcessStateChanged(const ProcessData &processData) override;
    void OnProcessDied(const ProcessData &processData) override;
    void HandleOnForegroundApplicationChanged(const AppStateData &appStateData);
    void HandleOnAbilityStateChanged(const AbilityStateData &abilityStateData);
    void HandleOnExtensionStateChanged(const AbilityStateData &abilityStateData);
    void HandleOnProcessCreated(const ProcessData &processData);
    void HandleOnProcessStateChanged(const ProcessData &processData);
    void HandleOnProcessDied(const ProcessData &processData);
    void CallEtsFunction(ani_env* env, ani_object EtsObserverObject,
        const char *methodName, const char *signature, ...);
    void AddEtsObserverObject(ani_env *env, const int32_t observerId, ani_object EtsObserverObject);
    bool RemoveEtsObserverObject(const int32_t observerId);
    bool FindObserverByObserverId(const int32_t observerId);
    size_t GetEtsObserverMapSize();
    void SetValid(const bool valid);
    void OnAppStarted(const AppStateData &appStateData) override;
    void OnAppStopped(const AppStateData &appStateData) override;
    void HandleOnAppStarted(const AppStateData &appStateData);
    void HandleOnAppStopped(const AppStateData &appStateData);
    std::map<int32_t, ani_object> GetEtsObserverObjectMap();

private:
    ani_vm *etsVm_;
    volatile bool valid_ = true;
    std::map<int32_t, ani_object> etsObserverObjectMap_;
    std::mutex etsObserverObjectMapLock_;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_APP_STATE_OBSERVER_H