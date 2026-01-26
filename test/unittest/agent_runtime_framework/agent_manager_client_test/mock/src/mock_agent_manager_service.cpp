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

#include "mock_agent_manager_service.h"

#include "mock_my_flag.h"

namespace OHOS {
namespace AgentRuntime {
int MyFlag::retGetAllAgentCards = 0;
int MyFlag::retGetAgentCardsByBundleName = 0;
int MyFlag::retGetAgentCardByAgentId = 0;

MockAgentManagerService::MockAgentManagerService()
{}

MockAgentManagerService::~MockAgentManagerService()
{}

int32_t MockAgentManagerService::GetAllAgentCards(AgentCardsRawData &rawData)
{
    return MyFlag::retGetAllAgentCards;
}

int32_t MockAgentManagerService::GetAgentCardsByBundleName(const std::string &bundleName,
    std::vector<AgentCard> &cards)
{
    return MyFlag::retGetAgentCardsByBundleName;
}

int32_t MockAgentManagerService::GetAgentCardByAgentId(const std::string &bundleName, const std::string &agentId,
    AgentCard &card)
{
    return MyFlag::retGetAgentCardByAgentId;
}
}  // namespace AgentRuntime
}  // namespace OHOS
