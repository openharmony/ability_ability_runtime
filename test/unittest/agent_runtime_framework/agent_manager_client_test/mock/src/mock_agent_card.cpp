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

#include "agent_card.h"

#include "mock_my_flag.h"

namespace OHOS {
namespace AgentRuntime {
int MyFlag::retToAgentCardVec = 0;
std::vector<AgentCard> MyFlag::convertedCards;

bool Provider::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool Provider::Marshalling(Parcel &parcel) const
{
    return true;
}

Provider *Provider::Unmarshalling(Parcel &parcel)
{
    Provider *provider = new (std::nothrow) Provider();
    return provider;
}

bool Capabilities::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool Capabilities::Marshalling(Parcel &parcel) const
{
    return true;
}

Capabilities *Capabilities::Unmarshalling(Parcel &parcel)
{
    Capabilities *capabilities = new (std::nothrow) Capabilities();
    return capabilities;
}

bool Authentication::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool Authentication::Marshalling(Parcel &parcel) const
{
    return true;
}

Authentication *Authentication::Unmarshalling(Parcel &parcel)
{
    Authentication *authentication = new (std::nothrow) Authentication();
    return authentication;
}

bool Skill::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool Skill::Marshalling(Parcel &parcel) const
{
    return true;
}

Skill *Skill::Unmarshalling(Parcel &parcel)
{
    Skill *skill = new (std::nothrow) Skill();
    return skill;
}

bool AgentCard::ReadFromParcel(Parcel &parcel)
{
    return true;
}

bool AgentCard::Marshalling(Parcel &parcel) const
{
    return true;
}

AgentCard *AgentCard::Unmarshalling(Parcel &parcel)
{
    AgentCard *agentCard = new (std::nothrow) AgentCard();
    return agentCard;
}

nlohmann::json AgentCard::ToJson() const
{
    nlohmann::json jsonObject;
    return jsonObject;
}

AgentCard AgentCard::FromJson(nlohmann::json jsonObject)
{
    AgentCard agentCard;
    return agentCard;
}

int32_t AgentCardsRawData::RawDataCpy(const void *readdata)
{
    return 0;
}

int32_t AgentCardsRawData::ToAgentCardVec(const AgentCardsRawData &rawData, std::vector<AgentCard> &cards)
{
    cards = MyFlag::convertedCards;
    return MyFlag::retToAgentCardVec;
}

AgentCardsRawData::~AgentCardsRawData()
{
}

void AgentCardsRawData::FromAgentCardVec(const std::vector<AgentCard> &cards, AgentCardsRawData &rawData)
{
}
} // namespace AgentRuntime
} // namespace OHOS