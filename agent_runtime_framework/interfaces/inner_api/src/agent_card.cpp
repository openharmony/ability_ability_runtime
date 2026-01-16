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

#include "agent_card.h"
 
#include <sstream>

#include "ability_manager_errors.h"
#include "hilog_tag_wrapper.h"
#include "securec.h"
#include "string_ex.h"

using namespace OHOS::AAFwk;

namespace OHOS {
namespace AgentRuntime {
constexpr int32_t SKILLS_MAX_SIZE = 100;
constexpr uint32_t MAX_AGENT_CARD_COUNT = 200000;

bool Provider::ReadFromParcel(Parcel &parcel)
{
    organization = parcel.ReadString();
    url = parcel.ReadString();
    return true;
}

bool Provider::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(organization)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write organization failed");
        return false;
    }
    if (!parcel.WriteString(url)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write url failed");
        return false;
    }
    return true;
}

Provider *Provider::Unmarshalling(Parcel &parcel)
{
    Provider *provider = new (std::nothrow) Provider();
    if (provider && !provider->ReadFromParcel(parcel)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "provider unmarshalling failed");
        delete provider;
        provider = nullptr;
    }
    return provider;
}

nlohmann::json Provider::ToJson()
{
    return nlohmann::json {
        { "organization", organization },
        { "url", url },
    };
}

Provider Provider::FromJson(const nlohmann::json &jsonObject)
{
    Provider provider;
    if (jsonObject.contains("organization") && jsonObject["organization"].is_string()) {
        provider.organization = jsonObject.at("organization");
    }
    if (jsonObject.contains("url") && jsonObject["url"].is_string()) {
        provider.url = jsonObject.at("url");
    }
    return provider;
}

bool Capabilities::ReadFromParcel(Parcel &parcel)
{
    streaming = parcel.ReadBool();
    pushNotifications = parcel.ReadBool();
    stateTransitionHistory = parcel.ReadBool();
    return true;
}

bool Capabilities::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(streaming)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write streaming failed");
        return false;
    }
    if (!parcel.WriteBool(pushNotifications)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write pushNotifications failed");
        return false;
    }
    if (!parcel.WriteBool(stateTransitionHistory)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write stateTransitionHistory failed");
        return false;
    }
    return true;
}

Capabilities *Capabilities::Unmarshalling(Parcel &parcel)
{
    Capabilities *capabilities = new (std::nothrow) Capabilities();
    if (capabilities && !capabilities->ReadFromParcel(parcel)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "capabilities unmarshalling failed");
        delete capabilities;
        capabilities = nullptr;
    }
    return capabilities;
}

nlohmann::json Capabilities::ToJson()
{
    return nlohmann::json {
        { "streaming", streaming },
        { "pushNotifications", pushNotifications },
        { "stateTransitionHistory", stateTransitionHistory },
    };
}

Capabilities Capabilities::FromJson(const nlohmann::json &jsonObject)
{
    Capabilities capabilities;
    if (jsonObject.contains("streaming") && jsonObject["streaming"].is_boolean()) {
        capabilities.streaming = jsonObject.at("streaming");
    }
    if (jsonObject.contains("pushNotifications") && jsonObject["pushNotifications"].is_boolean()) {
        capabilities.pushNotifications = jsonObject.at("pushNotifications");
    }
    if (jsonObject.contains("stateTransitionHistory") && jsonObject["stateTransitionHistory"].is_boolean()) {
        capabilities.stateTransitionHistory = jsonObject.at("stateTransitionHistory");
    }
    return capabilities;
}

bool Authentication::ReadFromParcel(Parcel &parcel)
{
    if (!parcel.ReadStringVector(&schemes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "read schemes failed");
        return false;
    }
    credentials = parcel.ReadString();
    return true;
}

bool Authentication::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteStringVector(schemes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write schemes failed");
        return false;
    }
    if (!parcel.WriteString(credentials)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write credentials failed");
        return false;
    }
    return true;
}

Authentication *Authentication::Unmarshalling(Parcel &parcel)
{
    Authentication *authentication = new (std::nothrow) Authentication();
    if (authentication && !authentication->ReadFromParcel(parcel)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "authentication unmarshalling failed");
        delete authentication;
        authentication = nullptr;
    }
    return authentication;
}

nlohmann::json Authentication::ToJson()
{
    return nlohmann::json {
        { "schemes", schemes },
        { "credentials", credentials },
    };
}

Authentication Authentication::FromJson(const nlohmann::json &jsonObject)
{
    Authentication authentication;
    if (jsonObject.contains("schemes") && jsonObject["schemes"].is_array()) {
        authentication.schemes = jsonObject.at("schemes");
    }
    if (jsonObject.contains("credentials") && jsonObject["credentials"].is_string()) {
        authentication.credentials = jsonObject.at("credentials");
    }
    return authentication;
}

bool Skill::ReadFromParcel(Parcel &parcel)
{
    id = parcel.ReadString();
    name = parcel.ReadString();
    description = parcel.ReadString();
    if (!parcel.ReadStringVector(&tags)) {
        return false;
    }
    if (!parcel.ReadStringVector(&examples)) {
        return false;
    }
    if (!parcel.ReadStringVector(&inputModes)) {
        return false;
    }
    if (!parcel.ReadStringVector(&outputModes)) {
        return false;
    }
    return true;
}

bool Skill::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(id)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write id failed");
        return false;
    }
    if (!parcel.WriteString(name)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write name failed");
        return false;
    }
    if (!parcel.WriteString(description)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write description failed");
        return false;
    }
    if (!parcel.WriteStringVector(tags)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write tags failed");
        return false;
    }
    if (!parcel.WriteStringVector(examples)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write examples failed");
        return false;
    }
    if (!parcel.WriteStringVector(inputModes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write inputModes failed");
        return false;
    }
    if (!parcel.WriteStringVector(outputModes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write outputModes failed");
        return false;
    }
    return true;
}

Skill *Skill::Unmarshalling(Parcel &parcel)
{
    Skill *skill = new (std::nothrow) Skill();
    if (skill && !skill->ReadFromParcel(parcel)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "skill unmarshalling failed");
        delete skill;
        skill = nullptr;
    }
    return skill;
}

nlohmann::json Skill::ToJson()
{
    return nlohmann::json {
        { "id", id },
        { "name", name },
        { "description", description },
        { "tags", tags},
        { "examples", examples},
        { "inputModes", inputModes},
        { "outputModes", outputModes},
    };
}

Skill Skill::FromJson(const nlohmann::json &jsonObject)
{
    Skill skill;
    if (jsonObject.contains("id") && jsonObject["id"].is_string()) {
        skill.id = jsonObject.at("id");
    }
    if (jsonObject.contains("name") && jsonObject["name"].is_string()) {
        skill.name = jsonObject.at("name");
    }
    if (jsonObject.contains("description") && jsonObject["description"].is_string()) {
        skill.description = jsonObject.at("description");
    }
    if (jsonObject.contains("tags") && jsonObject["tags"].is_array()) {
        skill.tags = jsonObject.at("tags");
    }
    if (jsonObject.contains("examples") && jsonObject["examples"].is_array()) {
        skill.examples = jsonObject.at("examples");
    }
    if (jsonObject.contains("inputModes") && jsonObject["inputModes"].is_array()) {
        skill.inputModes = jsonObject.at("inputModes");
    }
    if (jsonObject.contains("outputModes") && jsonObject["outputModes"].is_array()) {
        skill.outputModes = jsonObject.at("outputModes");
    }
    return skill;
}

bool AgentCard::ReadFromParcel(Parcel &parcel)
{
    bundleName = parcel.ReadString();
    moduleName = parcel.ReadString();
    abilityName = parcel.ReadString();
    appIndex = parcel.ReadInt32();
    name = parcel.ReadString();
    description = parcel.ReadString();
    url = parcel.ReadString();
    provider.reset(parcel.ReadParcelable<Provider>());
    version = parcel.ReadString();
    documentationUrl = parcel.ReadString();
    capabilities.reset(parcel.ReadParcelable<Capabilities>());
    authentication.reset(parcel.ReadParcelable<Authentication>());
    if (!parcel.ReadStringVector(&defaultInputModes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "read defaultInputModes failed");
        return false;
    }
    if (!parcel.ReadStringVector(&defaultOutputModes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "read defaultOutputModes failed");
        return false;
    }
    uint32_t skillSize = parcel.ReadUint32();
    if (skillSize > SKILLS_MAX_SIZE) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "read skill size failed");
        return false;
    }
    for (uint32_t i = 0; i < skillSize; i++) {
        std::shared_ptr<Skill> skill(parcel.ReadParcelable<Skill>());
        skills.push_back(skill);
    }
    return true;
}

bool AgentCard::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(bundleName)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write bundleName failed");
        return false;
    }
    if (!parcel.WriteString(moduleName)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write moduleName failed");
        return false;
    }
    if (!parcel.WriteString(abilityName)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write abilityName failed");
        return false;
    }
    if (!parcel.WriteInt32(appIndex)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write appIndex failed");
        return false;
    }
    if (!parcel.WriteString(name)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write name failed");
        return false;
    }
    if (!parcel.WriteString(description)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write description failed");
        return false;
    }
    if (!parcel.WriteString(url)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write url failed");
        return false;
    }
    if (!parcel.WriteParcelable(provider.get())) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Write provider failed.");
        return false;
    }
    if (!parcel.WriteString(version)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write version failed");
        return false;
    }
    if (!parcel.WriteString(documentationUrl)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write documentationUrl failed");
        return false;
    }
    if (!parcel.WriteParcelable(capabilities.get())) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Write capabilities failed.");
        return false;
    }
    if (!parcel.WriteParcelable(authentication.get())) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Write authentication failed.");
        return false;
    }
    if (!parcel.WriteStringVector(defaultInputModes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write defaultInputModes failed");
        return false;
    }
    if (!parcel.WriteStringVector(defaultOutputModes)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "write defaultOutputModes failed");
        return false;
    }
    if (!parcel.WriteUint32(skills.size())) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "Write skill size failed.");
        return false;
    }
    for (auto skill : skills) {
        if (!parcel.WriteParcelable(skill.get())) {
            TAG_LOGE(AAFwkTag::SER_ROUTER, "Write skill failed.");
            return false;
        }
    }
    return true;
}

AgentCard *AgentCard::Unmarshalling(Parcel &parcel)
{
    AgentCard *agentCard = new (std::nothrow) AgentCard();
    if (agentCard && !agentCard->ReadFromParcel(parcel)) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "agentCard unmarshalling failed");
        delete agentCard;
        agentCard = nullptr;
    }
    return agentCard;
}

nlohmann::json AgentCard::ToJson() const
{
    nlohmann::json jsonObject = nlohmann::json {
        { "bundleName", bundleName },
        { "moduleName", moduleName },
        { "abilityName", abilityName },
        { "appIndex", appIndex },
        { "name", name },
        { "description", description },
        { "url", url },
        { "version", version},
        { "documentationUrl", documentationUrl},
        { "defaultInputModes", defaultInputModes},
        { "defaultOutputModes", defaultOutputModes},
    };

    // Add optional fields if they are not empty/null
    if (provider != nullptr) {
        jsonObject["provider"] = provider->ToJson();
    }

    if (capabilities != nullptr) {
        jsonObject["capabilities"] = capabilities->ToJson();
    }

    if (authentication != nullptr) {
        jsonObject["authentication"] = authentication->ToJson();
    }

    if (!skills.empty()) {
        nlohmann::json skillsArray = nlohmann::json::array();
        for (const auto& skill : skills) {
            if (skill != nullptr) {
                nlohmann::json skillJson = skill->ToJson();
                skillsArray.push_back(skillJson);
            }
        }
        jsonObject["skills"] = skillsArray;
    }

    return jsonObject;
}

AgentCard AgentCard::FromJson(nlohmann::json jsonObject)
{
    AgentCard agentCard;

    // Required fields
    if (jsonObject.contains("bundleName") && jsonObject["bundleName"].is_string()) {
        agentCard.bundleName = jsonObject["bundleName"];
    }
    if (jsonObject.contains("moduleName") && jsonObject["moduleName"].is_string()) {
        agentCard.moduleName = jsonObject["moduleName"];
    }
    if (jsonObject.contains("abilityName") && jsonObject["abilityName"].is_string()) {
        agentCard.abilityName = jsonObject["abilityName"];
    }
    if (jsonObject.contains("appIndex") && jsonObject["appIndex"].is_number()) {
        agentCard.appIndex = jsonObject["appIndex"];
    }
    if (jsonObject.contains("name") && jsonObject["name"].is_string()) {
        agentCard.name = jsonObject["name"];
    }
    if (jsonObject.contains("description") && jsonObject["description"].is_string()) {
        agentCard.description = jsonObject["description"];
    }
    if (jsonObject.contains("url") && jsonObject["url"].is_string()) {
        agentCard.url = jsonObject["url"];
    }

    // Optional fields
    if (jsonObject.contains("version") && jsonObject["version"].is_string()) {
        agentCard.version = jsonObject["version"];
    }
    if (jsonObject.contains("documentationUrl") && jsonObject["documentationUrl"].is_string()) {
        agentCard.documentationUrl = jsonObject["documentationUrl"];
    }

    if (jsonObject.contains("defaultInputModes") && jsonObject["defaultInputModes"].is_array()) {
        agentCard.defaultInputModes = jsonObject["defaultInputModes"].get<std::vector<std::string>>();
    }
    if (jsonObject.contains("defaultOutputModes") && jsonObject["defaultOutputModes"].is_array()) {
        agentCard.defaultOutputModes = jsonObject["defaultOutputModes"].get<std::vector<std::string>>();
    }

    // Optional objects
    if (jsonObject.contains("provider") && jsonObject["provider"].is_object()) {
        auto provider = std::make_shared<Provider>();
        *provider = Provider::FromJson(jsonObject["provider"]);
        agentCard.provider = provider;
    }

    if (jsonObject.contains("capabilities") && jsonObject["capabilities"].is_object()) {
        auto capabilities = std::make_shared<Capabilities>();
        *capabilities = Capabilities::FromJson(jsonObject["capabilities"]);
        agentCard.capabilities = capabilities;
    }

    if (jsonObject.contains("authentication") && jsonObject["authentication"].is_object()) {
        auto authentication = std::make_shared<Authentication>();
        *authentication = Authentication::FromJson(jsonObject["authentication"]);
        agentCard.authentication = authentication;
    }

    // Skills array
    if (jsonObject.contains("skills") && jsonObject["skills"].is_array()) {
        for (const auto& skillJson : jsonObject["skills"]) {
            if (skillJson.is_object()) {
                auto skill = std::make_shared<Skill>();
                *skill = Skill::FromJson(skillJson);
                agentCard.skills.push_back(skill);
            }
        }
    }

    return agentCard;
}

int32_t AgentCardsRawData::RawDataCpy(const void *readdata)
{
    if (readdata == nullptr || size == 0) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "null data or zero size");
        return ERR_INVALID_AGENT_CARD_DATA;
    }
    void* newData = malloc(size);
    if (newData == nullptr) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "malloc failed");
        return ERR_INVALID_AGENT_CARD_DATA;
    }
    if (memcpy_s(newData, size, readdata, size) != EOK) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "memcpy_s failed");
        free(newData);
        return ERR_INVALID_AGENT_CARD_DATA;
    }
    isMalloc = true;
    if (data != nullptr) {
        free(const_cast<void*>(data));
        data = nullptr;
    }
    data = newData;
    return ERR_OK;
}

int32_t AgentCardsRawData::ToAgentCardVec(const AgentCardsRawData &rawData, std::vector<AgentCard> &cards)
{
    std::stringstream ss;
    ss.write(reinterpret_cast<const char *>(rawData.data), rawData.size);
    ss.seekg(0, std::ios::beg);
    uint32_t ssLength = static_cast<uint32_t>(ss.str().length());
    uint32_t count = 0;
    ss.read(reinterpret_cast<char *>(&count), sizeof(count));
    if (count == 0 || count > MAX_AGENT_CARD_COUNT) {
        TAG_LOGE(AAFwkTag::SER_ROUTER, "cards empty or exceed maxSize %{public}d, count: %{public}d",
            MAX_AGENT_CARD_COUNT, count);
        return ERR_AGENT_CARD_LIST_OUT_OF_RANGE;
    }
    cards.resize(count);
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t cardSize = 0;
        ss.read(reinterpret_cast<char *>(&cardSize), sizeof(cardSize));
        if (cardSize > ssLength - static_cast<uint32_t>(ss.tellg())) {
            TAG_LOGE(AAFwkTag::SER_ROUTER, "cardSize:%{public}u is invalid", cardSize);
            return ERR_INVALID_AGENT_CARD_DATA;
        }
        std::string cardStr(cardSize, '\0');
        ss.read(cardStr.data(), cardSize);
        nlohmann::json jsonObject = nlohmann::json::parse(cardStr, nullptr, false);
        cards[i] = AgentCard::FromJson(jsonObject);
    }
    return ERR_OK;
}

AgentCardsRawData::~AgentCardsRawData()
{
    if (data != nullptr && isMalloc) {
        free(const_cast<void*>(data));
        isMalloc = false;
        data = nullptr;
    }
}

void AgentCardsRawData::FromAgentCardVec(const std::vector<AgentCard> &cards, AgentCardsRawData &rawData)
{
    std::stringstream ss;
    uint32_t count = cards.size();
    ss.write(reinterpret_cast<const char*>(&count), sizeof(count));

    for (uint32_t i = 0; i < count; ++i) {
        std::string dumped = cards[i].ToJson().dump();
        uint32_t strLen = dumped.length();
        ss.write(reinterpret_cast<const char*>(&strLen), sizeof(strLen));
        ss.write(dumped.c_str(), strLen);
    }
    std::string result = ss.str();
    rawData.ownedData = std::move(result);
    rawData.data = rawData.ownedData.data();
    rawData.size = rawData.ownedData.size();
}
} // namespace AgentRuntime
} // namespace OHOS