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

#ifndef OHOS_ABILITY_RUNTIME_ABILITY_DELEGATOR_REGISTRY_H
#define OHOS_ABILITY_RUNTIME_ABILITY_DELEGATOR_REGISTRY_H

#include <memory>

#include "ability_delegator.h"
#include "ability_delegator_args.h"
#ifdef CJ_FRONTEND
#include "cj_ability_delegator_impl.h"
#endif
#include "iability_delegator.h"
#include "runtime.h"

namespace OHOS {
namespace AppExecFwk {
class AbilityDelegatorRegistry {
public:
    /**
     * Obtains the AbilityDelegator object of the application.
     *
     * @return the AbilityDelegator object initialized when the application is started.
     */
    static std::shared_ptr<AbilityDelegator> GetAbilityDelegator(
        const AbilityRuntime::Runtime::Language &language = AbilityRuntime::Runtime::Language::JS);

#ifdef CJ_FRONTEND
    /**
     * Obtains the AbilityDelegator object of the application.
     *
     * @return the AbilityDelegator object initialized when the application is started.
     */
    static std::shared_ptr<CJAbilityDelegatorImpl> GetCJAbilityDelegator();
#endif

    /**
     * Obtains test parameters stored in the AbilityDelegatorArgs object.
     *
     * @return the previously registered AbilityDelegatorArgs object.
     */
    static std::shared_ptr<AbilityDelegatorArgs> GetArguments();

    /**
     * Registers the instances of AbilityDelegator and AbilityDelegatorArgs as globally unique instances.
     * This method is called during application startup to initialize the test environment.
     *
     * @param delegator, Indicates the AbilityDelegator object.
     * @param args, Indicates the AbilityDelegatorArgs object.
     */
    static void RegisterInstance(
        const std::shared_ptr<IAbilityDelegator> &delegator, const std::shared_ptr<AbilityDelegatorArgs> &args,
        const AbilityRuntime::Runtime::Language &language);

private:
    static std::map<AbilityRuntime::Runtime::Language, std::shared_ptr<IAbilityDelegator>> abilityDelegator_;
    static std::shared_ptr<AbilityDelegatorArgs> abilityDelegatorArgs_;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_ABILITY_DELEGATOR_REGISTRY_H
