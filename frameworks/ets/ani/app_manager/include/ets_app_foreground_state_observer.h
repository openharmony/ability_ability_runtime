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

#ifndef OHOS_ABILITY_RUNTIME_ETS_APP_FOREGROUND_STATE_OBSERVER_H
#define OHOS_ABILITY_RUNTIME_ETS_APP_FOREGROUND_STATE_OBSERVER_H

#include <mutex>
#include <set>

#include "ani.h"
#include "ani_common_util.h"
#include "app_foreground_state_observer_stub.h"
#include "event_handler.h"

namespace OHOS {
namespace AbilityRuntime {
using AppExecFwk::AppForegroundStateObserverStub;
using AppExecFwk::AppStateData;
class ETSAppForegroundStateObserver : public AppForegroundStateObserverStub {
public:
virtual ~ETSAppForegroundStateObserver();
explicit ETSAppForegroundStateObserver(ani_vm *etsVm);
    void OnAppStateChanged(const AppStateData &appStateData);
    void HandleOnAppStateChanged(const AppStateData &appStateData);
    void AddEtsObserverObject(const ani_object &observerObj);
    void RemoveEtsObserverObject(const ani_object &observerObj);
    void RemoveAllEtsObserverObjects();
    ani_ref GetObserverObject(const ani_object &observerObject);
    void CallEtsFunction(ani_env* env, ani_object etsObserverObject,
        const char *methodName, const char *signature, ...);
    bool IsEmpty();
    void SetValid(bool valid);
private:
    bool IsStrictEquals(ani_ref observerRef, const ani_object &etsObserverObject);
    ani_vm *etsVm_ = nullptr;
    volatile bool valid_ = true;
    std::vector<ani_ref> etsObserverObjects_;
    std::mutex etsObserverObjectSetLock_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_APP_FOREGROUND_STATE_OBSERVER_H
