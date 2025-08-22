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

#ifndef OHOS_ABILITY_RUNTIME_ETS_UI_ABILITY_INSTANCE_H
#define OHOS_ABILITY_RUNTIME_ETS_UI_ABILITY_INSTANCE_H

#include "ui_ability.h"

namespace OHOS {
namespace AbilityRuntime {
class UIAbility;
class AbilityContext;
class Runtime;

UIAbility *CreateETSUIAbility(const std::unique_ptr<Runtime> &runtime);
void CreateAndBindETSUIAbilityContext(const std::shared_ptr<AbilityContext> &abilityContext,
    const std::unique_ptr<Runtime> &runtime);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_UI_ABILITY_INSTANCE_H