/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef OHOS_AGENT_RUNTIME_ETS_AGENT_MANAGER_UTILS_H
#define OHOS_AGENT_RUNTIME_ETS_AGENT_MANAGER_UTILS_H

#include <vector>

#include "agent_card.h"
#include "ani.h"

namespace OHOS {
namespace AgentManagerEts {
ani_object CreateEtsProvider(ani_env *env, const AgentRuntime::Provider &provider);
ani_object CreateEtsCapabilities(ani_env *env, const AgentRuntime::Capabilities &capabilities);
ani_object CreateEtsAuthentication(ani_env *env, const AgentRuntime::Authentication &authentication);
ani_object CreateEtsSkill(ani_env *env, const AgentRuntime::Skill &skill);
ani_object CreateEtsSkillArray(ani_env *env, const std::vector<std::shared_ptr<AgentRuntime::Skill>> &skills);
ani_object CreateEtsAgentCard(ani_env *env, const AgentRuntime::AgentCard &card);
ani_object CreateEtsAgentCardArray(ani_env *env, const std::vector<AgentRuntime::AgentCard> &cards);
} // namespace AgentManagerEts
} // namespace OHOS
#endif // OHOS_AGENT_RUNTIME_ETS_AGENT_MANAGER_UTILS_H
