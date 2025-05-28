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

#ifndef OHOS_ABILITY_RUNTIME_ETS_ABILITY_DELEGATOR_REGISTRY_H
#define OHOS_ABILITY_RUNTIME_ETS_ABILITY_DELEGATOR_REGISTRY_H

#include "sts_runtime.h"

namespace OHOS {
namespace AbilityDelegatorEts {
enum class AbilityLifecycleState {
    /**
     * Indicates that the ability has not been initialized.
     */
    UNINITIALIZED,
    /**
     * Indicates that the ability is in the created state.
     */
    CREATE,
    /**
     * Indicates that the ability is in the foreground state.
     */
    FOREGROUND,
    /**
     * Indicates that the ability is in the background state.
     */
    BACKGROUND,
    /**
     * Indicates that the ability is in the destroyed state.
     */
    DESTROY,
};
void EtsAbilityDelegatorRegistryInit(ani_env *env);
} // namespace AbilityDelegatorEts
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_ABILITY_DELEGATOR_REGISTRY_H
