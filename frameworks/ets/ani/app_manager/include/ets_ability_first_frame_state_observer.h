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

#ifndef OHOS_ABILITY_RUNTIME_ETS_ABILITY_FIRST_FRAME_STATE_OBSERVER_H
#define OHOS_ABILITY_RUNTIME_ETS_ABILITY_FIRST_FRAME_STATE_OBSERVER_H

#ifdef SUPPORT_GRAPHICS
#include <mutex>
#include <set>

#include "ability_first_frame_state_data.h"
#include "ability_first_frame_state_observer_stub.h"
#include "ability_manager_interface.h"
#include "ani.h"
#include "ani_common_util.h"
#include "event_handler.h"
#include "singleton.h"

namespace OHOS {
namespace AbilityRuntime {
using AppExecFwk::AbilityFirstFrameStateObserverStub;
using AppExecFwk::AbilityFirstFrameStateData;
class ETSAbilityFirstFrameStateObserver : public AbilityFirstFrameStateObserverStub {
public:
    explicit ETSAbilityFirstFrameStateObserver(ani_vm *vm);
    virtual ~ETSAbilityFirstFrameStateObserver() = default;
    void OnAbilityFirstFrameState(const AbilityFirstFrameStateData &abilityFirstFrameStateData) override;
    void HandleOnAbilityFirstFrameState(const AbilityFirstFrameStateData &abilityFirstFrameStateData);
    void CallEtsFunction(
        ani_env *env, ani_object etsObserverObject, const char *methodName, const char *signature, ...);
    void SetEtsObserverObject(const ani_object &etsObserverObject);
    void ResetEtsObserverObject();
    bool IsStrictEquals(const ani_object &etsObserverObject);
    ani_ref GetAniObserver() { return etsObserverObject_; }
private:
    ani_vm *etsVm_ = nullptr;
    ani_ref etsObserverObject_ = nullptr;
};

class ETSAbilityFirstFrameStateObserverManager {
public:
    static ETSAbilityFirstFrameStateObserverManager *GetInstance()
    {
        static ETSAbilityFirstFrameStateObserverManager instance;
        return &instance;
    }
    ~ETSAbilityFirstFrameStateObserverManager() = default;
    void AddEtsAbilityFirstFrameStateObserver(const sptr<ETSAbilityFirstFrameStateObserver> observer);
    bool IsObserverObjectExist(const ani_object &esObserverObject);
    void RemoveAllEtsObserverObjects(sptr<OHOS::AAFwk::IAbilityManager> &abilityManager);
    void RemoveEtsObserverObject(sptr<OHOS::AAFwk::IAbilityManager> &abilityManager,
        const ani_object &etsObserverObject);
private:
    ETSAbilityFirstFrameStateObserverManager() = default;
    DISALLOW_COPY_AND_MOVE(ETSAbilityFirstFrameStateObserverManager);
    ani_ref GetObserverObject(const ani_object &etsObserverObject);

private:
    std::mutex observerListLock_;
    std::list<sptr<ETSAbilityFirstFrameStateObserver>> etsAbilityFirstFrameStateObserverList_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // SUPPORT_GRAPHICS
#endif // OHOS_ABILITY_RUNTIME_ETS_ABILITY_FIRST_FRAME_STATE_OBSERVER_H
