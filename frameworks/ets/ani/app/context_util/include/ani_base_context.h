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

#ifndef OHOS_ABILITY_RUNTIME_ANI_BASE_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_ANI_BASE_CONTEXT_H

#include "sts_runtime.h"

#include <array>
#include <iostream>
#include <unistd.h>
#include <memory>
#include "context.h"

namespace OHOS {

namespace AbilityRuntime {
    class Context;
}

namespace AppExecFwk {
    class Ability;
}

}
/**
 * @brief Get "stageMode" value of object.
 *
 * @param env NAPI environment.
 * @param object Native value contains "stageMode" object.
 * @param stageMode The value of "stageMode" object.
 * @return napi_status
 */
ani_status IsStageContext(ani_env* env, ani_object object, ani_boolean& stageMode);

/**
 * @brief Get stage mode context.
 *
 * @param env NAPI environment.
 * @param object Native value of context.
 * @return The stage mode context.
 */
std::shared_ptr<OHOS::AbilityRuntime::Context> GetStageModeContext(ani_env* env, ani_object object);

/**
 * @brief Get current ability.
 *
 * @param env NAPI environment.
 * @return The pointer of current ability.
 */
OHOS::AppExecFwk::Ability* GetCurrentAbility(ani_env* env);


#endif  // OHOS_ABILITY_RUNTIME_ANI_BASE_CONTEXT_H