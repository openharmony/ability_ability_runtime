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

#ifndef OHOS_ABILITY_RUNTIME_ETS_ABILITY_FOREGROUND_STATE_OBSERVER_H
#define OHOS_ABILITY_RUNTIME_ETS_ABILITY_FOREGROUND_STATE_OBSERVER_H

#include <vector>

#include "ability_foreground_state_observer_stub.h"
#include "ability_state_data.h"
#include "ani_common_util.h"
#include "ets_runtime.h"
#include "event_handler.h"

namespace OHOS {
namespace AbilityRuntime {
using AppExecFwk::AbilityForegroundStateObserverStub;
using AppExecFwk::AbilityStateData;
class ETSAbilityForegroundStateObserver : public AbilityForegroundStateObserverStub {
public:
    explicit ETSAbilityForegroundStateObserver(ani_vm *etsVm);
    virtual ~ETSAbilityForegroundStateObserver();

    void OnAbilityStateChanged(const AbilityStateData &abilityStateData);
    void HandleOnAbilityStateChanged(const AbilityStateData &abilityStateData);
    void AddEtsObserverObject(ani_env *env, ani_object etsObserverObject);
    bool RemoveEtsObserverObject(const ani_object &observerObj);
    ani_ref GetObserverObject(const ani_object &observerObject);
    void RemoveAllEtsObserverObject();
    bool IsEmpty();
    void SetValid(bool valid);
    void CallEtsFunction(ani_env* env, ani_object etsObserverObject,
        const char *methodName, const char *signature, ...);
    inline size_t GetEtsObserverMapSize() { return etsObserverObjects_.size(); }
private:
    void ReleaseObjectReference(ani_ref etsObjRef);
    ani_status AniSendEvent(const std::function<void()> task);
    bool AttachAniEnv(ani_env *&env);
    void DetachAniEnv();
    bool IsStrictEquals(ani_ref observerRef, const ani_object &etsObserverObject);

    ani_vm *etsVm_;
    volatile bool valid_ = true;
    std::mutex mutexlock_;
    std::vector<ani_ref> etsObserverObjects_;
    std::shared_ptr<AppExecFwk::EventHandler> mainHandler_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_ABILITY_FOREGROUND_STATE_OBSERVER_H
