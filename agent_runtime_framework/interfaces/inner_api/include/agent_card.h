/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_AGENT_RUNTIME_AGENT_CARD_H
#define OHOS_AGENT_RUNTIME_AGENT_CARD_H

#include <iostream>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "parcel.h"

namespace OHOS {
namespace AgentRuntime {
struct Provider : public Parcelable {
    std::string organization;
    std::string url;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static Provider *Unmarshalling(Parcel &parcel);
    nlohmann::json ToJson();
    static Provider FromJson(const nlohmann::json &jsonObject);
};

struct Capabilities : public Parcelable {
    // optional param
    bool streaming;
    // optional param
    bool pushNotifications;
    // optional param
    bool stateTransitionHistory;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static Capabilities *Unmarshalling(Parcel &parcel);
    nlohmann::json ToJson();
    static Capabilities FromJson(const nlohmann::json &jsonObject);
};

struct Authentication : public Parcelable {
    std::vector<std::string> schemes;
    // optional param
    std::string credentials;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static Authentication *Unmarshalling(Parcel &parcel);
    nlohmann::json ToJson();
    static Authentication FromJson(const nlohmann::json &jsonObject);
};

struct Skill : public Parcelable {
    std::string id;
    std::string name;
    std::string description;
    std::vector<std::string> tags;
    // optional param
    std::vector<std::string> examples;
    // optional param
    std::vector<std::string> inputModes;
    // optional param
    std::vector<std::string> outputModes;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static Skill *Unmarshalling(Parcel &parcel);
    nlohmann::json ToJson();
    static Skill FromJson(const nlohmann::json &jsonObject);
};

struct AgentCard : public Parcelable {
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string agentId;
    std::string name;
    std::string description;
    std::string url;
    // optional param
    std::shared_ptr<Provider> provider = nullptr;
    std::string version;
    // optional param
    std::string documentationUrl;
    std::shared_ptr<Capabilities> capabilities = nullptr;
    std::shared_ptr<Authentication> authentication = nullptr;
    std::vector<std::string> defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    std::vector<std::shared_ptr<Skill>> skills;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    nlohmann::json ToJson() const;
    static AgentCard FromJson(nlohmann::json jsonObject);
    static AgentCard *Unmarshalling(Parcel &parcel);
};

class AgentCardsRawData {
public:
    std::string ownedData;
    uint32_t size = 0;
    const void* data = nullptr;
    bool isMalloc = false;

    static void FromAgentCardVec(const std::vector<AgentCard> &cards, AgentCardsRawData &rawData);
    static int32_t ToAgentCardVec(const AgentCardsRawData &rawData, std::vector<AgentCard> &cards);
    int32_t RawDataCpy(const void *readdata);
    ~AgentCardsRawData();
};
} // AgentRuntime
} // OHOS
#endif // OHOS_AGENT_RUNTIME_AGENT_CARD_H