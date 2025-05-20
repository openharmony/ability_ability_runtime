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

#ifndef OHOS_ABILITY_RUNTIME_ANI_COMMON_WANT_AGENT_H
#define OHOS_ABILITY_RUNTIME_ANI_COMMON_WANT_AGENT_H

#include "ani.h"
#include "want_agent.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS::AbilityRuntime::WantAgent;

ani_object WrapWantAgent(ani_env *env, WantAgent *wantAgent);
void UnwrapWantAgent(ani_env *env, ani_object agent, void** result);

} // namespace AppExecFwk
} // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ANI_COMMON_WANT_AGENT_H
