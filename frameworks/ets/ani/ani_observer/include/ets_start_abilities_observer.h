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

#ifndef OHOS_ABILITY_RUNTIME_ETS_START_ABILITIES_OBSERVER_H
#define OHOS_ABILITY_RUNTIME_ETS_START_ABILITIES_OBSERVER_H

#include "ability_business_error.h"
#include "ani.h"
#include "start_abilities_observer.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsStartAbilitiesObserver : StartAbilitiesObserver {
public:
    static EtsStartAbilitiesObserver &GetInstance();
    virtual ~EtsStartAbilitiesObserver();

    static void HandleFinished(const std::string &requestKey, int32_t resultCode);

    void AddObserver(ani_env *env, const std::string &requestKey, ani_object callback);
    
    void SetEtsVm(ani_vm *etsVm)
    {
        etsVm_ = etsVm;
    }

private:
    void HandleFinishedInner(const std::string &requestKey, int32_t resultCode);
    void CallCallback(ani_object callback, int32_t resultCode);

    std::mutex etsObserverObjectListLock_;
    std::mutex etsVmLock_;
    ani_vm *etsVm_ = nullptr;
    std::map<std::string, ani_ref> etsObserverObjectList_;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_ETS_START_ABILITIES_OBSERVER_H