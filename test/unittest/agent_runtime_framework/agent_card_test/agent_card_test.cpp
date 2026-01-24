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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "ability_manager_errors.h"
#include "agent_card.h"
#include "securec.h"

using namespace OHOS;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace AgentRuntime {
constexpr uint32_t MAX_AGENT_CARD_COUNT = 200000;

class AgentCardTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void AgentCardTest::SetUpTestCase(void)
{}

void AgentCardTest::TearDownTestCase(void)
{}

void AgentCardTest::SetUp(void)
{}

void AgentCardTest::TearDown(void)
{}

/**
 * @tc.name: ProviderMarshallingTest_001
 * @tc.desc: Test Provider Marshalling method with valid data
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, ProviderMarshallingTest_001, TestSize.Level1)
{
    Provider provider;
    provider.organization = "test1";
    provider.url = "abc";

    Parcel parcelMock;
    bool result = provider.Marshalling(parcelMock);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: ProviderMarshallingTest_002
 * @tc.desc: Test Provider Marshalling method with empty strings
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, ProviderMarshallingTest_002, TestSize.Level1)
{
    Provider provider;
    provider.organization = "";
    provider.url = "";

    Parcel parcelMock;
    bool result = provider.Marshalling(parcelMock);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: ProviderMarshallingTest_003
 * @tc.desc: Test Provider Marshalling method when WriteString fails for organization
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, ProviderMarshallingTest_003, TestSize.Level1)
{
    Provider provider;
    provider.organization = "test";
    provider.url = "test";

    Parcel parcelMock;
    bool result = provider.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: ProviderMarshallingTest_004
 * @tc.desc: Test Provider Marshalling method when WriteString fails for url
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, ProviderMarshallingTest_004, TestSize.Level1)
{
    Provider provider;
    provider.organization = "test";
    provider.url = "test";

    Parcel parcelMock;
    bool result = provider.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: ProviderUnmarshalling_001
 * @tc.desc: ProviderUnmarshalling_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, ProviderUnmarshalling_001, TestSize.Level1)
{
    Parcel parcelMock;
    Provider *provider = Provider::Unmarshalling(parcelMock);

    EXPECT_TRUE(provider != nullptr);
}

/**
 * @tc.name: CapabilitiesMarshalling_001
 * @tc.desc: CapabilitiesMarshalling_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, CapabilitiesMarshalling_001, TestSize.Level1)
{
    Capabilities capabilities;
    capabilities.streaming = true;
    capabilities.pushNotifications = true;
    capabilities.stateTransitionHistory = true;

    Parcel parcelMock;
    bool result = capabilities.Marshalling(parcelMock);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: CapabilitiesMarshalling_002
 * @tc.desc: CapabilitiesMarshalling_002
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, CapabilitiesMarshalling_002, TestSize.Level1)
{
    Capabilities capabilities;
    capabilities.streaming = false;
    capabilities.pushNotifications = true;
    capabilities.stateTransitionHistory = true;

    Parcel parcelMock;
    bool result = capabilities.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: CapabilitiesMarshalling_003
 * @tc.desc: CapabilitiesMarshalling_003
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, CapabilitiesMarshalling_003, TestSize.Level1)
{
    Capabilities capabilities;
    capabilities.streaming = true;
    capabilities.pushNotifications = false;
    capabilities.stateTransitionHistory = true;

    Parcel parcelMock;
    bool result = capabilities.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: CapabilitiesMarshalling_004
 * @tc.desc: CapabilitiesMarshalling_004
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, CapabilitiesMarshalling_004, TestSize.Level1)
{
    Capabilities capabilities;
    capabilities.streaming = true;
    capabilities.pushNotifications = true;
    capabilities.stateTransitionHistory = false;

    Parcel parcelMock;
    bool result = capabilities.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: CapabilitiesUnmarshalling_001
 * @tc.desc: CapabilitiesUnmarshalling_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, CapabilitiesUnmarshalling_001, TestSize.Level1)
{
    Parcel parcelMock;
    Capabilities *capabilities = Capabilities::Unmarshalling(parcelMock);

    EXPECT_TRUE(capabilities != nullptr);
}

/**
 * @tc.name: AuthenticationMarshalling_001
 * @tc.desc: AuthenticationMarshalling_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AuthenticationMarshalling_001, TestSize.Level1)
{
    Authentication authentication;
    std::vector<std::string> schemes;
    schemes.push_back("test");
    authentication.schemes = schemes;
    authentication.credentials = "test1";

    Parcel parcelMock;
    bool result = authentication.Marshalling(parcelMock);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: AuthenticationMarshalling_002
 * @tc.desc: AuthenticationMarshalling_002
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AuthenticationMarshalling_002, TestSize.Level1)
{
    Authentication authentication;
    std::vector<std::string> schemes;
    authentication.schemes = schemes;
    authentication.credentials = "test1";

    Parcel parcelMock;
    bool result = authentication.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AuthenticationMarshalling_003
 * @tc.desc: AuthenticationMarshalling_003
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AuthenticationMarshalling_003, TestSize.Level1)
{
    Authentication authentication;
    std::vector<std::string> schemes;
    schemes.push_back("test");
    authentication.schemes = schemes;
    authentication.credentials = "test";

    Parcel parcelMock;
    bool result = authentication.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AuthenticationUnmarshalling_001
 * @tc.desc: AuthenticationUnmarshalling_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AuthenticationUnmarshalling_001, TestSize.Level1)
{
    Parcel parcelMock;
    Authentication *authentication = Authentication::Unmarshalling(parcelMock);

    EXPECT_TRUE(authentication == nullptr);
}

/**
 * @tc.name: SkillMarshalling_001
 * @tc.desc: SkillMarshalling_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, SkillMarshalling_001, TestSize.Level1)
{
    Skill skill;
    skill.id = "test1";
    skill.name = "test1";
    skill.description = "test1";
    std::vector<std::string> tags;
    tags.push_back("test");
    skill.tags = tags;
    std::vector<std::string> examples;
    examples.push_back("test");
    skill.examples = examples;
    std::vector<std::string> inputModes;
    inputModes.push_back("test");
    skill.inputModes = inputModes;
    std::vector<std::string> outputModes;
    outputModes.push_back("test");
    skill.outputModes = outputModes;

    Parcel parcelMock;
    bool result = skill.Marshalling(parcelMock);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: SkillMarshalling_002
 * @tc.desc: SkillMarshalling_002
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, SkillMarshalling_002, TestSize.Level1)
{
    Skill skill;
    skill.id = "test";
    skill.name = "test1";
    skill.description = "test1";
    std::vector<std::string> tags;
    tags.push_back("test");
    skill.tags = tags;
    std::vector<std::string> examples;
    examples.push_back("test");
    skill.examples = examples;
    std::vector<std::string> inputModes;
    inputModes.push_back("test");
    skill.inputModes = inputModes;
    std::vector<std::string> outputModes;
    outputModes.push_back("test");
    skill.outputModes = outputModes;

    Parcel parcelMock;
    bool result = skill.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: SkillMarshalling_003
 * @tc.desc: SkillMarshalling_003
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, SkillMarshalling_003, TestSize.Level1)
{
    Skill skill;
    skill.id = "test1";
    skill.name = "test";
    skill.description = "test1";
    std::vector<std::string> tags;
    tags.push_back("test");
    skill.tags = tags;
    std::vector<std::string> examples;
    examples.push_back("test");
    skill.examples = examples;
    std::vector<std::string> inputModes;
    inputModes.push_back("test");
    skill.inputModes = inputModes;
    std::vector<std::string> outputModes;
    outputModes.push_back("test");
    skill.outputModes = outputModes;

    Parcel parcelMock;
    bool result = skill.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: SkillMarshalling_004
 * @tc.desc: SkillMarshalling_004
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, SkillMarshalling_004, TestSize.Level1)
{
    Skill skill;
    skill.id = "test1";
    skill.name = "test1";
    skill.description = "test";
    std::vector<std::string> tags;
    tags.push_back("test");
    skill.tags = tags;
    std::vector<std::string> examples;
    examples.push_back("test");
    skill.examples = examples;
    std::vector<std::string> inputModes;
    inputModes.push_back("test");
    skill.inputModes = inputModes;
    std::vector<std::string> outputModes;
    outputModes.push_back("test");
    skill.outputModes = outputModes;

    Parcel parcelMock;
    bool result = skill.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: SkillMarshalling_005
 * @tc.desc: SkillMarshalling_005
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, SkillMarshalling_005, TestSize.Level1)
{
    Skill skill;
    skill.id = "test1";
    skill.name = "test1";
    skill.description = "test1";
    std::vector<std::string> tags;
    skill.tags = tags;
    std::vector<std::string> examples;
    examples.push_back("test");
    skill.examples = examples;
    std::vector<std::string> inputModes;
    inputModes.push_back("test");
    skill.inputModes = inputModes;
    std::vector<std::string> outputModes;
    outputModes.push_back("test");
    skill.outputModes = outputModes;

    Parcel parcelMock;
    bool result = skill.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: SkillMarshalling_006
 * @tc.desc: SkillMarshalling_006
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, SkillMarshalling_006, TestSize.Level1)
{
    Skill skill;
    skill.id = "test1";
    skill.name = "test1";
    skill.description = "test1";
    std::vector<std::string> tags;
    tags.push_back("test");
    skill.tags = tags;
    std::vector<std::string> examples;
    skill.examples = examples;
    std::vector<std::string> inputModes;
    inputModes.push_back("test");
    skill.inputModes = inputModes;
    std::vector<std::string> outputModes;
    outputModes.push_back("test");
    skill.outputModes = outputModes;

    Parcel parcelMock;
    bool result = skill.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: SkillMarshalling_007
 * @tc.desc: SkillMarshalling_007
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, SkillMarshalling_007, TestSize.Level1)
{
    Skill skill;
    skill.id = "test1";
    skill.name = "test1";
    skill.description = "test1";
    std::vector<std::string> tags;
    tags.push_back("test");
    skill.tags = tags;
    std::vector<std::string> examples;
    examples.push_back("test");
    skill.examples = examples;
    std::vector<std::string> inputModes;
    skill.inputModes = inputModes;
    std::vector<std::string> outputModes;
    outputModes.push_back("test");
    skill.outputModes = outputModes;

    Parcel parcelMock;
    bool result = skill.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: SkillMarshalling_008
 * @tc.desc: SkillMarshalling_008
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, SkillMarshalling_008, TestSize.Level1)
{
    Skill skill;
    skill.id = "test1";
    skill.name = "test1";
    skill.description = "test1";
    std::vector<std::string> tags;
    tags.push_back("test");
    skill.tags = tags;
    std::vector<std::string> examples;
    examples.push_back("test");
    skill.examples = examples;
    std::vector<std::string> inputModes;
    inputModes.push_back("test");
    skill.inputModes = inputModes;
    std::vector<std::string> outputModes;
    skill.outputModes = outputModes;

    Parcel parcelMock;
    bool result = skill.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: SkillUnmarshalling_001
 * @tc.desc: SkillUnmarshalling_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, SkillUnmarshalling_001, TestSize.Level1)
{
    Parcel parcelMock;
    Skill *skill = Skill::Unmarshalling(parcelMock);

    EXPECT_TRUE(skill == nullptr);
}

/**
 * @tc.name: AgentCardReadFromParcel_001
 * @tc.desc: AgentCardReadFromParcel_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardReadFromParcel_001, TestSize.Level1)
{
    AgentCard agentCard;
    std::vector<std::string> defaultInputModes;
    defaultInputModes.push_back("test");
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    defaultOutputModes.push_back("test");
    agentCard.defaultOutputModes = defaultOutputModes;
    Parcel parcelMock;
    bool result = agentCard.ReadFromParcel(parcelMock);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: AgentCardReadFromParcel_002
 * @tc.desc: AgentCardReadFromParcel_002
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardReadFromParcel_002, TestSize.Level1)
{
    AgentCard agentCard;
    std::vector<std::string> defaultInputModes;
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    defaultOutputModes.push_back("test");
    agentCard.defaultOutputModes = defaultOutputModes;
    Parcel parcelMock;
    bool result = agentCard.ReadFromParcel(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AgentCardReadFromParcel_003
 * @tc.desc: AgentCardReadFromParcel_003
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardReadFromParcel_003, TestSize.Level1)
{
    AgentCard agentCard;
    std::vector<std::string> defaultInputModes;
    defaultInputModes.push_back("test");
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    agentCard.defaultOutputModes = defaultOutputModes;
    Parcel parcelMock;
    bool result = agentCard.ReadFromParcel(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AgentCardMarshalling_001
 * @tc.desc: AgentCardMarshalling_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardMarshalling_001, TestSize.Level1)
{
    AgentCard agentCard;
    agentCard.bundleName = "bundleName";
    agentCard.moduleName = "moduleName";
    agentCard.abilityName = "abilityName";
    agentCard.agentId = "1";
    agentCard.name = "test1";
    agentCard.description = "test1";
    agentCard.url = "test1";
    std::shared_ptr<Provider> provider = std::make_shared<Provider>();
    agentCard.provider = provider;
    agentCard.version = "test1";
    agentCard.documentationUrl = "test1";
    std::shared_ptr<Capabilities> capabilities = std::make_shared<Capabilities>();
    agentCard.capabilities = capabilities;
    std::shared_ptr<Authentication> authentication = std::make_shared<Authentication>();
    agentCard.authentication = authentication;
    std::vector<std::string> defaultInputModes;
    defaultInputModes.push_back("test");
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    defaultOutputModes.push_back("test");
    agentCard.defaultOutputModes = defaultOutputModes;
    std::vector<std::shared_ptr<Skill>> skills;
    skills.push_back(std::make_shared<Skill>());
    agentCard.skills = skills;

    Parcel parcelMock;
    bool result = agentCard.Marshalling(parcelMock);

    EXPECT_TRUE(result);
}

/**
 * @tc.name: AgentCardMarshalling_002
 * @tc.desc: AgentCardMarshalling_002
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardMarshalling_002, TestSize.Level1)
{
    AgentCard agentCard;
    agentCard.bundleName = "bundleName";
    agentCard.moduleName = "moduleName";
    agentCard.abilityName = "abilityName";
    agentCard.agentId = "1";
    agentCard.name = "test";
    agentCard.description = "test1";
    agentCard.url = "test1";
    std::shared_ptr<Provider> provider = std::make_shared<Provider>();
    agentCard.provider = provider;
    agentCard.version = "test1";
    agentCard.documentationUrl = "test1";
    std::shared_ptr<Capabilities> capabilities = std::make_shared<Capabilities>();
    agentCard.capabilities = capabilities;
    std::shared_ptr<Authentication> authentication = std::make_shared<Authentication>();
    agentCard.authentication = authentication;
    std::vector<std::string> defaultInputModes;
    defaultInputModes.push_back("test");
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    defaultOutputModes.push_back("test");
    agentCard.defaultOutputModes = defaultOutputModes;
    std::vector<std::shared_ptr<Skill>> skills;
    skills.push_back(std::make_shared<Skill>());
    agentCard.skills = skills;

    Parcel parcelMock;
    bool result = agentCard.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AgentCardMarshalling_003
 * @tc.desc: AgentCardMarshalling_003
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardMarshalling_003, TestSize.Level1)
{
    AgentCard agentCard;
    agentCard.bundleName = "bundleName";
    agentCard.moduleName = "moduleName";
    agentCard.abilityName = "abilityName";
    agentCard.agentId = "1";
    agentCard.name = "test1";
    agentCard.description = "test";
    agentCard.url = "test1";
    std::shared_ptr<Provider> provider = std::make_shared<Provider>();
    agentCard.provider = provider;
    agentCard.version = "test1";
    agentCard.documentationUrl = "test1";
    std::shared_ptr<Capabilities> capabilities = std::make_shared<Capabilities>();
    agentCard.capabilities = capabilities;
    std::shared_ptr<Authentication> authentication = std::make_shared<Authentication>();
    agentCard.authentication = authentication;
    std::vector<std::string> defaultInputModes;
    defaultInputModes.push_back("test");
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    defaultOutputModes.push_back("test");
    agentCard.defaultOutputModes = defaultOutputModes;
    std::vector<std::shared_ptr<Skill>> skills;
    skills.push_back(std::make_shared<Skill>());
    agentCard.skills = skills;

    Parcel parcelMock;
    bool result = agentCard.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AgentCardMarshalling_004
 * @tc.desc: AgentCardMarshalling_004
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardMarshalling_004, TestSize.Level1)
{
    AgentCard agentCard;
    agentCard.bundleName = "bundleName";
    agentCard.moduleName = "moduleName";
    agentCard.abilityName = "abilityName";
    agentCard.agentId = "1";
    agentCard.name = "test1";
    agentCard.description = "test1";
    agentCard.url = "test";
    std::shared_ptr<Provider> provider = std::make_shared<Provider>();
    agentCard.provider = provider;
    agentCard.version = "test1";
    agentCard.documentationUrl = "test1";
    std::shared_ptr<Capabilities> capabilities = std::make_shared<Capabilities>();
    agentCard.capabilities = capabilities;
    std::shared_ptr<Authentication> authentication = std::make_shared<Authentication>();
    agentCard.authentication = authentication;
    std::vector<std::string> defaultInputModes;
    defaultInputModes.push_back("test");
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    defaultOutputModes.push_back("test");
    agentCard.defaultOutputModes = defaultOutputModes;
    std::vector<std::shared_ptr<Skill>> skills;
    skills.push_back(std::make_shared<Skill>());
    agentCard.skills = skills;

    Parcel parcelMock;
    bool result = agentCard.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AgentCardMarshalling_005
 * @tc.desc: AgentCardMarshalling_005
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardMarshalling_005, TestSize.Level1)
{
    AgentCard agentCard;
    agentCard.bundleName = "bundleName";
    agentCard.moduleName = "moduleName";
    agentCard.abilityName = "abilityName";
    agentCard.agentId = "1";
    agentCard.name = "test1";
    agentCard.description = "test1";
    agentCard.url = "test1";
    std::shared_ptr<Provider> provider = nullptr;
    agentCard.provider = provider;
    agentCard.version = "test1";
    agentCard.documentationUrl = "test1";
    std::shared_ptr<Capabilities> capabilities = std::make_shared<Capabilities>();
    agentCard.capabilities = capabilities;
    std::shared_ptr<Authentication> authentication = std::make_shared<Authentication>();
    agentCard.authentication = authentication;
    std::vector<std::string> defaultInputModes;
    defaultInputModes.push_back("test");
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    defaultOutputModes.push_back("test");
    agentCard.defaultOutputModes = defaultOutputModes;
    std::vector<std::shared_ptr<Skill>> skills;
    skills.push_back(std::make_shared<Skill>());
    agentCard.skills = skills;

    Parcel parcelMock;
    bool result = agentCard.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AgentCardMarshalling_006
 * @tc.desc: AgentCardMarshalling_006
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardMarshalling_006, TestSize.Level1)
{
    AgentCard agentCard;
    agentCard.bundleName = "bundleName";
    agentCard.moduleName = "moduleName";
    agentCard.abilityName = "abilityName";
    agentCard.agentId = "1";
    agentCard.name = "test1";
    agentCard.description = "test1";
    agentCard.url = "test1";
    std::shared_ptr<Provider> provider = std::make_shared<Provider>();
    agentCard.provider = provider;
    agentCard.version = "test";
    agentCard.documentationUrl = "test1";
    std::shared_ptr<Capabilities> capabilities = std::make_shared<Capabilities>();
    agentCard.capabilities = capabilities;
    std::shared_ptr<Authentication> authentication = std::make_shared<Authentication>();
    agentCard.authentication = authentication;
    std::vector<std::string> defaultInputModes;
    defaultInputModes.push_back("test");
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    defaultOutputModes.push_back("test");
    agentCard.defaultOutputModes = defaultOutputModes;
    std::vector<std::shared_ptr<Skill>> skills;
    skills.push_back(std::make_shared<Skill>());
    agentCard.skills = skills;

    Parcel parcelMock;
    bool result = agentCard.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AgentCardMarshalling_007
 * @tc.desc: AgentCardMarshalling_007
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardMarshalling_007, TestSize.Level1)
{
    AgentCard agentCard;
    agentCard.bundleName = "bundleName";
    agentCard.moduleName = "moduleName";
    agentCard.abilityName = "abilityName";
    agentCard.agentId = "1";
    agentCard.name = "test1";
    agentCard.description = "test1";
    agentCard.url = "test1";
    std::shared_ptr<Provider> provider = std::make_shared<Provider>();
    agentCard.provider = provider;
    agentCard.version = "test1";
    agentCard.documentationUrl = "test";
    std::shared_ptr<Capabilities> capabilities = std::make_shared<Capabilities>();
    agentCard.capabilities = capabilities;
    std::shared_ptr<Authentication> authentication = std::make_shared<Authentication>();
    agentCard.authentication = authentication;
    std::vector<std::string> defaultInputModes;
    defaultInputModes.push_back("test");
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    defaultOutputModes.push_back("test");
    agentCard.defaultOutputModes = defaultOutputModes;
    std::vector<std::shared_ptr<Skill>> skills;
    skills.push_back(std::make_shared<Skill>());
    agentCard.skills = skills;

    Parcel parcelMock;
    bool result = agentCard.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AgentCardMarshalling_008
 * @tc.desc: AgentCardMarshalling_008
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardMarshalling_008, TestSize.Level1)
{
    AgentCard agentCard;
    agentCard.bundleName = "bundleName";
    agentCard.moduleName = "moduleName";
    agentCard.abilityName = "abilityName";
    agentCard.agentId = "1";
    agentCard.name = "test1";
    agentCard.description = "test1";
    agentCard.url = "test1";
    std::shared_ptr<Provider> provider = std::make_shared<Provider>();
    agentCard.provider = provider;
    agentCard.version = "test1";
    agentCard.documentationUrl = "test1";
    std::shared_ptr<Capabilities> capabilities = nullptr;
    agentCard.capabilities = capabilities;
    std::shared_ptr<Authentication> authentication = std::make_shared<Authentication>();
    agentCard.authentication = authentication;
    std::vector<std::string> defaultInputModes;
    defaultInputModes.push_back("test");
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    defaultOutputModes.push_back("test");
    agentCard.defaultOutputModes = defaultOutputModes;
    std::vector<std::shared_ptr<Skill>> skills;
    skills.push_back(std::make_shared<Skill>());
    agentCard.skills = skills;

    Parcel parcelMock;
    bool result = agentCard.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AgentCardMarshalling_009
 * @tc.desc: AgentCardMarshalling_009
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardMarshalling_009, TestSize.Level1)
{
    AgentCard agentCard;
    agentCard.bundleName = "bundleName";
    agentCard.moduleName = "moduleName";
    agentCard.abilityName = "abilityName";
    agentCard.agentId = "1";
    agentCard.name = "test1";
    agentCard.description = "test1";
    agentCard.url = "test1";
    std::shared_ptr<Provider> provider = std::make_shared<Provider>();
    agentCard.provider = provider;
    agentCard.version = "test1";
    agentCard.documentationUrl = "test1";
    std::shared_ptr<Capabilities> capabilities = std::make_shared<Capabilities>();
    agentCard.capabilities = capabilities;
    std::shared_ptr<Authentication> authentication = nullptr;
    agentCard.authentication = authentication;
    std::vector<std::string> defaultInputModes;
    defaultInputModes.push_back("test");
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    defaultOutputModes.push_back("test");
    agentCard.defaultOutputModes = defaultOutputModes;
    std::vector<std::shared_ptr<Skill>> skills;
    skills.push_back(std::make_shared<Skill>());
    agentCard.skills = skills;

    Parcel parcelMock;
    bool result = agentCard.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AgentCardMarshalling_010
 * @tc.desc: AgentCardMarshalling_010
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardMarshalling_010, TestSize.Level1)
{
    AgentCard agentCard;
    agentCard.bundleName = "bundleName";
    agentCard.moduleName = "moduleName";
    agentCard.abilityName = "abilityName";
    agentCard.agentId = "1";
    agentCard.name = "test1";
    agentCard.description = "test1";
    agentCard.url = "test1";
    std::shared_ptr<Provider> provider = std::make_shared<Provider>();
    agentCard.provider = provider;
    agentCard.version = "test1";
    agentCard.documentationUrl = "test1";
    std::shared_ptr<Capabilities> capabilities = std::make_shared<Capabilities>();
    agentCard.capabilities = capabilities;
    std::shared_ptr<Authentication> authentication = std::make_shared<Authentication>();
    agentCard.authentication = authentication;
    std::vector<std::string> defaultInputModes;
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    defaultOutputModes.push_back("test");
    agentCard.defaultOutputModes = defaultOutputModes;
    std::vector<std::shared_ptr<Skill>> skills;
    skills.push_back(std::make_shared<Skill>());
    agentCard.skills = skills;

    Parcel parcelMock;
    bool result = agentCard.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AgentCardMarshalling_011
 * @tc.desc: AgentCardMarshalling_011
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardMarshalling_011, TestSize.Level1)
{
    AgentCard agentCard;
    agentCard.bundleName = "bundleName";
    agentCard.moduleName = "moduleName";
    agentCard.abilityName = "abilityName";
    agentCard.agentId = "1";
    agentCard.name = "test1";
    agentCard.description = "test1";
    agentCard.url = "test1";
    std::shared_ptr<Provider> provider = std::make_shared<Provider>();
    agentCard.provider = provider;
    agentCard.version = "test1";
    agentCard.documentationUrl = "test1";
    std::shared_ptr<Capabilities> capabilities = std::make_shared<Capabilities>();
    agentCard.capabilities = capabilities;
    std::shared_ptr<Authentication> authentication = std::make_shared<Authentication>();
    agentCard.authentication = authentication;
    std::vector<std::string> defaultInputModes;
    defaultInputModes.push_back("test");
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    agentCard.defaultOutputModes = defaultOutputModes;
    std::vector<std::shared_ptr<Skill>> skills;
    skills.push_back(std::make_shared<Skill>());
    agentCard.skills = skills;

    Parcel parcelMock;
    bool result = agentCard.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AgentCardMarshalling_012
 * @tc.desc: AgentCardMarshalling_012
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardMarshalling_012, TestSize.Level1)
{
    AgentCard agentCard;
    agentCard.bundleName = "bundleName";
    agentCard.moduleName = "moduleName";
    agentCard.abilityName = "abilityName";
    agentCard.agentId = "1";
    agentCard.name = "test1";
    agentCard.description = "test1";
    agentCard.url = "test1";
    std::shared_ptr<Provider> provider = std::make_shared<Provider>();
    agentCard.provider = provider;
    agentCard.version = "test1";
    agentCard.documentationUrl = "test1";
    std::shared_ptr<Capabilities> capabilities = std::make_shared<Capabilities>();
    agentCard.capabilities = capabilities;
    std::shared_ptr<Authentication> authentication = std::make_shared<Authentication>();
    agentCard.authentication = authentication;
    std::vector<std::string> defaultInputModes;
    defaultInputModes.push_back("test");
    agentCard.defaultInputModes = defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    defaultOutputModes.push_back("test");
    agentCard.defaultOutputModes = defaultOutputModes;
    std::vector<std::shared_ptr<Skill>> skills;
    agentCard.skills = skills;

    Parcel parcelMock;
    bool result = agentCard.Marshalling(parcelMock);

    EXPECT_FALSE(result);
}

/**
 * @tc.name: AgentCardUnmarshalling_001
 * @tc.desc: AgentCardUnmarshalling_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardUnmarshalling_001, TestSize.Level1)
{
    Parcel parcelMock;
    AgentCard *agentCard = AgentCard::Unmarshalling(parcelMock);

    EXPECT_TRUE(agentCard == nullptr);
}

/**
 * @tc.name: AgentCardToJson_001
 * @tc.desc: AgentCardToJson_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardToJson_001, TestSize.Level1)
{
    AgentCard agentCard;
    std::shared_ptr<Provider> provider = std::make_shared<Provider>();
    agentCard.provider = provider;
    std::shared_ptr<Capabilities> capabilities = std::make_shared<Capabilities>();
    agentCard.capabilities = capabilities;
    std::shared_ptr<Authentication> authentication = std::make_shared<Authentication>();
    agentCard.authentication = authentication;
    std::vector<std::shared_ptr<Skill>> skills;
    skills.push_back(std::make_shared<Skill>());
    agentCard.skills = skills;
    nlohmann::json jsonObject = agentCard.ToJson();
    EXPECT_TRUE(jsonObject.contains("provider"));

    agentCard.provider = nullptr;
    jsonObject = agentCard.ToJson();
    EXPECT_FALSE(jsonObject.contains("provider"));

    agentCard.capabilities = nullptr;
    jsonObject = agentCard.ToJson();
    EXPECT_FALSE(jsonObject.contains("capabilities"));

    agentCard.authentication = nullptr;
    jsonObject = agentCard.ToJson();
    EXPECT_FALSE(jsonObject.contains("authentication"));

    std::vector<std::shared_ptr<Skill>> skills1;
    agentCard.skills = skills1;
    jsonObject = agentCard.ToJson();
    EXPECT_FALSE(jsonObject.contains("skills"));
}

/**
 * @tc.name: AgentCardFromJson_001
 * @tc.desc: AgentCardFromJson_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AgentCardFromJson_001, TestSize.Level1)
{
    Provider provider;
    Capabilities capabilities;
    Authentication authentication;
    std::vector<std::string> defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    Skill skill;
    nlohmann::json jsonArray = { skill.ToJson() };
    nlohmann::json jsonObject = nlohmann::json {
        { "bundleName", "test" },
        { "moduleName", "test" },
        { "abilityName", "test" },
        { "agentId", "1" },
        { "name", "test" },
        { "description", "test" },
        { "url", "test" },
        { "provider", provider.ToJson() },
        { "version", "test" },
        { "documentationUrl", "test" },
        { "capabilities", capabilities.ToJson() },
        { "authentication", authentication.ToJson() },
        { "defaultInputModes", defaultInputModes },
        { "defaultOutputModes", defaultOutputModes },
        { "skills", jsonArray },
    };
    AgentCard agentCard = AgentCard::FromJson(jsonObject);

    EXPECT_TRUE(agentCard.bundleName == "test");
    EXPECT_TRUE(agentCard.moduleName == "test");
    EXPECT_TRUE(agentCard.abilityName == "test");
    EXPECT_TRUE(agentCard.agentId == "1");
    EXPECT_TRUE(agentCard.name == "test");
}

/**
 * @tc.name: ProviderToJson_001
 * @tc.desc: ProviderToJson_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, ProviderToJson_001, TestSize.Level1)
{
    Provider provider;
    provider.organization = "test";
    nlohmann::json jsonObject = provider.ToJson();

    EXPECT_TRUE(jsonObject["organization"] == "test");
}

/**
 * @tc.name: ProviderFromJson_001
 * @tc.desc: ProviderFromJson_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, ProviderFromJson_001, TestSize.Level1)
{
    nlohmann::json jsonObject = nlohmann::json {
        { "organization", "test" },
        { "url", "test" },
    };
    Provider provider = Provider::FromJson(jsonObject);
    EXPECT_TRUE(jsonObject["organization"] == provider.organization);

    nlohmann::json jsonObject1 = nlohmann::json {
        { "organization", "test" },
    };
    Provider provider1 = Provider::FromJson(jsonObject1);
    EXPECT_TRUE(jsonObject1["organization"] == provider1.organization);

    nlohmann::json jsonObject2 = nlohmann::json {
        { "url", "test" },
    };
    Provider provider2 = Provider::FromJson(jsonObject2);
    EXPECT_TRUE(provider2.url == "test");
}

/**
 * @tc.name: CapabilitiesToJson_001
 * @tc.desc: CapabilitiesToJson_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, CapabilitiesToJson_001, TestSize.Level1)
{
    Capabilities capabilities;
    capabilities.streaming = true;
    nlohmann::json jsonObject = capabilities.ToJson();

    EXPECT_TRUE(jsonObject["streaming"]);
}

/**
 * @tc.name: CapabilitiesFromJson_001
 * @tc.desc: CapabilitiesFromJson_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, CapabilitiesFromJson_001, TestSize.Level1)
{
    nlohmann::json jsonObject = nlohmann::json {
        { "streaming", true },
        { "pushNotifications", true },
        { "stateTransitionHistory", true },
    };
    Capabilities capabilities = Capabilities::FromJson(jsonObject);
    EXPECT_TRUE(jsonObject["streaming"]);

    jsonObject = nlohmann::json {};
    capabilities = Capabilities::FromJson(jsonObject);
    EXPECT_TRUE(jsonObject.contains("streaming") == false);
}

/**
 * @tc.name: AuthenticationToJson_001
 * @tc.desc: AuthenticationToJson_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AuthenticationToJson_001, TestSize.Level1)
{
    Authentication authentication;
    std::vector<std::string> schemes;
    authentication.schemes = schemes;
    nlohmann::json jsonObject = authentication.ToJson();

    EXPECT_TRUE(jsonObject["schemes"].size() == 0);
}

/**
 * @tc.name: AuthenticationFromJson_001
 * @tc.desc: AuthenticationFromJson_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, AuthenticationFromJson_001, TestSize.Level1)
{
    nlohmann::json jsonObject = nlohmann::json {
        { "schemes", nlohmann::json::array({ "test", "test" }) },
        { "credentials", "test" },
    };
    Authentication authentication = Authentication::FromJson(jsonObject);
    EXPECT_TRUE(authentication.credentials == "test");

    jsonObject = nlohmann::json {};
    authentication = Authentication::FromJson(jsonObject);
    EXPECT_TRUE(authentication.schemes.size() == 0);
}

/**
 * @tc.name: SkillToJson_001
 * @tc.desc: SkillToJson_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, SkillToJson_001, TestSize.Level1)
{
    Skill skill;
    skill.id = "test";
    nlohmann::json jsonObject = skill.ToJson();

    EXPECT_TRUE(jsonObject["id"] == "test");
}

/**
 * @tc.name: SkillFromJson_001
 * @tc.desc: SkillFromJson_001
 * @tc.type: FUNC
 * @tc.require: AR000H1N32
 */
HWTEST_F(AgentCardTest, SkillFromJson_001, TestSize.Level1)
{
    nlohmann::json jsonObject = nlohmann::json {
        { "id", "test" },
        { "name", "test" },
        { "description", "test" },
        { "tags", nlohmann::json::array({ "test", "test" }) },
        { "examples", nlohmann::json::array({ "test", "test" }) },
        { "inputModes", nlohmann::json::array({ "test", "test" }) },
        { "outputModes", nlohmann::json::array({ "test", "test" }) },
    };
    Skill skill = Skill::FromJson(jsonObject);
    EXPECT_TRUE(skill.id == "test");

    jsonObject = nlohmann::json {};
    skill = Skill::FromJson(jsonObject);
    EXPECT_TRUE(skill.id.empty());
}

/**
* @tc.name  : Marshalling_ShouldReturnTrue_WhenAllParcelWriteOperationsSucceed
* @tc.number: AgentCard_Marshalling_001
* @tc.desc  : Test that Marshalling returns true when all parcel write operations succeed.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_001, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "ExampleAbility";
    agentCard->agentId = "1";
    agentCard->name = "ExampleName";
    agentCard->description = "ExampleDescription";
    agentCard->url = "http://example.com";
    agentCard->provider = std::make_shared<Provider>();
    agentCard->version = "1.0.0";
    agentCard->documentationUrl = "http://docs.example.com";
    agentCard->capabilities = std::make_shared<Capabilities>();
    agentCard->authentication = std::make_shared<Authentication>();
    agentCard->defaultInputModes = {"input1", "input2"};
    agentCard->defaultOutputModes = {"output1", "output2"};
    agentCard->skills = {std::make_shared<Skill>()};

    EXPECT_TRUE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteBundleNameFails
* @tc.number: AgentCard_Marshalling_002
* @tc.desc  : Test that Marshalling returns false when writing bundleName fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_002, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "test";

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteModuleNameFails
* @tc.number: AgentCard_Marshalling_003
* @tc.desc  : Test that Marshalling returns false when writing moduleName fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_003, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "test";

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteAbilityNameFails
* @tc.number: AgentCard_Marshalling_004
* @tc.desc  : Test that Marshalling returns false when writing abilityName fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_004, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "test";

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteAgentIdFails
* @tc.number: AgentCard_Marshalling_005
* @tc.desc  : Test that Marshalling returns false when writing agentId fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_005, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "ExampleAbility";
    agentCard->agentId = "0";

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteNameFails
* @tc.number: AgentCard_Marshalling_006
* @tc.desc  : Test that Marshalling returns false when writing name fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_006, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "ExampleAbility";
    agentCard->agentId = "1";
    agentCard->name = "test";

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteDescriptionFails
* @tc.number: AgentCard_Marshalling_007
* @tc.desc  : Test that Marshalling returns false when writing description fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_007, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "ExampleAbility";
    agentCard->agentId = "1";
    agentCard->name = "ExampleName";
    agentCard->description = "test";

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteUrlFails
* @tc.number: AgentCard_Marshalling_008
* @tc.desc  : Test that Marshalling returns false when writing url fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_008, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "ExampleAbility";
    agentCard->agentId = "1";
    agentCard->name = "ExampleName";
    agentCard->description = "ExampleDescription";
    agentCard->url = "test";

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteProviderFails
* @tc.number: AgentCard_Marshalling_009
* @tc.desc  : Test that Marshalling returns false when writing provider fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_009, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "ExampleAbility";
    agentCard->agentId = "1";
    agentCard->name = "ExampleName";
    agentCard->description = "ExampleDescription";
    agentCard->url = "http://example.com";

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteVersionFails
* @tc.number: AgentCard_Marshalling_010
* @tc.desc  : Test that Marshalling returns false when writing version fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_010, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "ExampleAbility";
    agentCard->agentId = "1";
    agentCard->name = "ExampleName";
    agentCard->description = "ExampleDescription";
    agentCard->url = "http://example.com";
    agentCard->provider = std::make_shared<Provider>();
    agentCard->version = "test";

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteDocumentationUrlFails
* @tc.number: AgentCard_Marshalling_011
* @tc.desc  : Test that Marshalling returns false when writing documentationUrl fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_011, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "ExampleAbility";
    agentCard->agentId = "1";
    agentCard->name = "ExampleName";
    agentCard->description = "ExampleDescription";
    agentCard->url = "http://example.com";
    agentCard->provider = std::make_shared<Provider>();
    agentCard->version = "1.0.0";
    agentCard->documentationUrl = "test";

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteCapabilitiesFails
* @tc.number: AgentCard_Marshalling_012
* @tc.desc  : Test that Marshalling returns false when writing capabilities fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_012, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "ExampleAbility";
    agentCard->agentId = "1";
    agentCard->name = "ExampleName";
    agentCard->description = "ExampleDescription";
    agentCard->url = "http://example.com";
    agentCard->provider = std::make_shared<Provider>();
    agentCard->version = "1.0.0";
    agentCard->documentationUrl = "http://docs.example.com";

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteAuthenticationFails
* @tc.number: AgentCard_Marshalling_013
* @tc.desc  : Test that Marshalling returns false when writing authentication fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_013, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "ExampleAbility";
    agentCard->agentId = "1";
    agentCard->name = "ExampleName";
    agentCard->description = "ExampleDescription";
    agentCard->url = "http://example.com";
    agentCard->provider = std::make_shared<Provider>();
    agentCard->version = "1.0.0";
    agentCard->documentationUrl = "http://docs.example.com";
    agentCard->capabilities = std::make_shared<Capabilities>();

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteDefaultInputModesFails
* @tc.number: AgentCard_Marshalling_014
* @tc.desc  : Test that Marshalling returns false when writing defaultInputModes fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_014, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "ExampleAbility";
    agentCard->agentId = "1";
    agentCard->name = "ExampleName";
    agentCard->description = "ExampleDescription";
    agentCard->url = "http://example.com";
    agentCard->provider = std::make_shared<Provider>();
    agentCard->version = "1.0.0";
    agentCard->documentationUrl = "http://docs.example.com";
    agentCard->capabilities = std::make_shared<Capabilities>();
    agentCard->authentication = std::make_shared<Authentication>();

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteDefaultOutputModesFails
* @tc.number: AgentCard_Marshalling_015
* @tc.desc  : Test that Marshalling returns false when writing defaultOutputModes fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_015, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "ExampleAbility";
    agentCard->agentId = "1";
    agentCard->name = "ExampleName";
    agentCard->description = "ExampleDescription";
    agentCard->url = "http://example.com";
    agentCard->provider = std::make_shared<Provider>();
    agentCard->version = "1.0.0";
    agentCard->documentationUrl = "http://docs.example.com";
    agentCard->capabilities = std::make_shared<Capabilities>();
    agentCard->authentication = std::make_shared<Authentication>();
    agentCard->defaultInputModes = {"input1", "input2"};

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteSkillSizeFails
* @tc.number: AgentCard_Marshalling_016
* @tc.desc  : Test that Marshalling returns false when writing skill size fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_016, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "ExampleAbility";
    agentCard->agentId = "1";
    agentCard->name = "ExampleName";
    agentCard->description = "ExampleDescription";
    agentCard->url = "http://example.com";
    agentCard->provider = std::make_shared<Provider>();
    agentCard->version = "1.0.0";
    agentCard->documentationUrl = "http://docs.example.com";
    agentCard->capabilities = std::make_shared<Capabilities>();
    agentCard->authentication = std::make_shared<Authentication>();
    agentCard->defaultInputModes = {"input1", "input2"};
    agentCard->defaultOutputModes = {"output1", "output2"};

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : Marshalling_ShouldReturnFalse_WhenWriteSkillFails
* @tc.number: AgentCard_Marshalling_017
* @tc.desc  : Test that Marshalling returns false when writing skill fails.
*/
HWTEST_F(AgentCardTest, AgentCard_Marshalling_017, TestSize.Level1)
{
    Parcel parcelMock;
    auto agentCard = std::make_shared<AgentCard>();
    agentCard->bundleName = "com.example.bundle";
    agentCard->moduleName = "ExampleModule";
    agentCard->abilityName = "ExampleAbility";
    agentCard->agentId = "1";
    agentCard->name = "ExampleName";
    agentCard->description = "ExampleDescription";
    agentCard->url = "http://example.com";
    agentCard->provider = std::make_shared<Provider>();
    agentCard->version = "1.0.0";
    agentCard->documentationUrl = "http://docs.example.com";
    agentCard->capabilities = std::make_shared<Capabilities>();
    agentCard->authentication = std::make_shared<Authentication>();
    agentCard->defaultInputModes = {"input1", "input2"};
    agentCard->defaultOutputModes = {"output1", "output2"};
    agentCard->skills = { nullptr };

    EXPECT_FALSE(agentCard->Marshalling(parcelMock));
}

/**
* @tc.name  : RawDataCpy_ShouldReturnError_WhenReadDataIsNull
* @tc.number: RawDataCpy_001
* @tc.desc  : Test that RawDataCpy returns ERR_INVALID_AGENT_CARD_DATA when readdata is nullptr
*/
HWTEST_F(AgentCardTest, RawDataCpy_001, TestSize.Level1)
{
    AgentCardsRawData* agentCardData = new AgentCardsRawData();
    const void* readdata = nullptr;
    int32_t result = agentCardData->RawDataCpy(readdata);
    EXPECT_EQ(result, ERR_INVALID_AGENT_CARD_DATA);
    delete agentCardData;
}

/**
* @tc.name  : RawDataCpy_ShouldReturnError_WhenSizeIsZero
* @tc.number: RawDataCpy_002
* @tc.desc  : Test that RawDataCpy returns ERR_INVALID_AGENT_CARD_DATA when size is zero
*/
HWTEST_F(AgentCardTest, RawDataCpy_002, TestSize.Level1)
{
    AgentCardsRawData* agentCardData = new AgentCardsRawData();
    agentCardData->size = 0;
    const void* readdata = malloc(10);
    int32_t result = agentCardData->RawDataCpy(readdata);
    EXPECT_EQ(result, ERR_INVALID_AGENT_CARD_DATA);
    free(const_cast<void*>(readdata));
    delete agentCardData;
}

/**
* @tc.name  : RawDataCpy_ShouldCopyDataSuccessfully_WhenInputsAreValid
* @tc.number: RawDataCpy_005
* @tc.desc  : Test that RawDataCpy successfully copies data when inputs are valid
*/
HWTEST_F(AgentCardTest, RawDataCpy_005, TestSize.Level1)
{
    AgentCardsRawData* agentCardData = new AgentCardsRawData();
    const void* readdata = malloc(10);
    agentCardData->size = 10;
    memset(const_cast<void*>(readdata), 0xAA, 10);

    int32_t result = agentCardData->RawDataCpy(readdata);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_NE(agentCardData->data, nullptr);
    EXPECT_EQ(agentCardData->isMalloc, true);

    free(const_cast<void*>(readdata));
    delete agentCardData;
}

/**
* @tc.name  : RawDataCpy_ShouldFreeOldData_WhenDataIsNotNull
* @tc.number: RawDataCpy_006
* @tc.desc  : Test that RawDataCpy frees the old data when data is not nullptr
*/
HWTEST_F(AgentCardTest, RawDataCpy_006, TestSize.Level1)
{
    AgentCardsRawData* agentCardData = new AgentCardsRawData();
    // Initialize old data
    agentCardData->data = malloc(10);
    agentCardData->size = 10;

    const void* readdata = malloc(10);
    memset(const_cast<void*>(readdata), 0xAA, 10);

    int32_t result = agentCardData->RawDataCpy(readdata);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_NE(agentCardData->data, nullptr);
    EXPECT_EQ(agentCardData->isMalloc, true);

    // Verify the old data is freed
    EXPECT_NE(agentCardData->data, const_cast<void*>(readdata));

    free(const_cast<void*>(readdata));
    delete agentCardData;
}

/**
* @tc.name  : ToAgentCardVec_ShouldReturnError_WhenCountIsZero
* @tc.number: ToAgentCardVec_001
* @tc.desc  : Test that ToAgentCardVec returns ERR_AGENT_CARD_LIST_OUT_OF_RANGE when count is zero.
*/
HWTEST_F(AgentCardTest, ToAgentCardVec_001, TestSize.Level1)
{
    AgentCardsRawData rawData;
    rawData.data = new uint8_t[4]{0, 0, 0, 0}; // count = 0
    rawData.isMalloc = true;
    rawData.size = 4;

    std::vector<AgentCard> cards;
    int32_t result = AgentCardsRawData::ToAgentCardVec(rawData, cards);

    EXPECT_EQ(result, ERR_AGENT_CARD_LIST_OUT_OF_RANGE);
}

/**
* @tc.name  : ToAgentCardVec_ShouldReturnError_WhenCountExceedsMaxLimit
* @tc.number: ToAgentCardVec_002
* @tc.desc  : Test that ToAgentCardVec returns ERR_AGENT_CARD_LIST_OUT_OF_RANGE when count exceeds MAX_AGENT_CARD_COUNT.
*/
HWTEST_F(AgentCardTest, ToAgentCardVec_002, TestSize.Level1)
{
    AgentCardsRawData rawData;
    uint32_t count = MAX_AGENT_CARD_COUNT + 1;
    rawData.data = new uint8_t[4]{static_cast<uint8_t>(count), static_cast<uint8_t>(count >> 8),
                                  static_cast<uint8_t>(count >> 16), static_cast<uint8_t>(count >> 24)};
    rawData.isMalloc = true;
    rawData.size = 4;

    std::vector<AgentCard> cards;
    int32_t result = AgentCardsRawData::ToAgentCardVec(rawData, cards);

    EXPECT_EQ(result, ERR_AGENT_CARD_LIST_OUT_OF_RANGE);
}

/**
* @tc.name  : ToAgentCardVec_ShouldReturnError_WhenCardSizeIsInvalid
* @tc.number: ToAgentCardVec_003
* @tc.desc  : Test that ToAgentCardVec returns ERR_INVALID_AGENT_CARD_DATA when cardSize is invalid.
*/
HWTEST_F(AgentCardTest, ToAgentCardVec_003, TestSize.Level1)
{
    AgentCardsRawData rawData;
    uint32_t count = 1;
    uint32_t cardSize = 100; // Invalid card size
    rawData.data = new uint8_t[8]{static_cast<uint8_t>(count), static_cast<uint8_t>(count >> 8),
                                  static_cast<uint8_t>(count >> 16), static_cast<uint8_t>(count >> 24),
                                  static_cast<uint8_t>(cardSize), static_cast<uint8_t>(cardSize >> 8),
                                  static_cast<uint8_t>(cardSize >> 16), static_cast<uint8_t>(cardSize >> 24)};
    rawData.isMalloc = true;
    rawData.size = 8;

    std::vector<AgentCard> cards;
    int32_t result = AgentCardsRawData::ToAgentCardVec(rawData, cards);

    EXPECT_EQ(result, ERR_INVALID_AGENT_CARD_DATA);
}

/**
* @tc.name  : ToAgentCardVec_ShouldReturnSuccess_WhenDataIsValid
* @tc.number: ToAgentCardVec_004
* @tc.desc  : Test that ToAgentCardVec returns ERR_OK when the input data is valid.
*/
HWTEST_F(AgentCardTest, ToAgentCardVec_004, TestSize.Level1)
{
    AgentCard agentCard;
    agentCard.bundleName = "com.example.bundle";
    agentCard.moduleName = "ExampleModule";
    agentCard.abilityName = "ExampleAbility";
    agentCard.agentId = "1";
    agentCard.name = "ExampleName";
    agentCard.description = "ExampleDescription";
    agentCard.url = "http://example.com";
    agentCard.provider = std::make_shared<Provider>();
    agentCard.version = "1.0.0";
    agentCard.documentationUrl = "http://docs.example.com";
    agentCard.capabilities = std::make_shared<Capabilities>();
    agentCard.authentication = std::make_shared<Authentication>();
    agentCard.defaultInputModes = {"input1", "input2"};
    agentCard.defaultOutputModes = {"output1", "output2"};
    agentCard.skills = {std::make_shared<Skill>()};

    AgentCardsRawData rawData;
    std::vector<AgentCard> vec = { agentCard };
    AgentCardsRawData::FromAgentCardVec(vec, rawData);
    EXPECT_NE(rawData.data, nullptr);
    EXPECT_TRUE(rawData.size > 0);

    std::vector<AgentCard> cards;
    int32_t result = AgentCardsRawData::ToAgentCardVec(rawData, cards);

    EXPECT_EQ(result, ERR_OK);
}

/**
* @tc.name  : FromAgentCardVec
* @tc.number: FromAgentCardVec_001
* @tc.desc  : FromAgentCardVec_001
*/
HWTEST_F(AgentCardTest, FromAgentCardVec_001, TestSize.Level1)
{
    AgentCard agentCard;
    agentCard.bundleName = "com.example.bundle";
    agentCard.moduleName = "ExampleModule";
    agentCard.abilityName = "ExampleAbility";
    agentCard.agentId = "1";
    agentCard.name = "ExampleName";
    agentCard.description = "ExampleDescription";
    agentCard.url = "http://example.com";
    agentCard.provider = std::make_shared<Provider>();
    agentCard.version = "1.0.0";
    agentCard.documentationUrl = "http://docs.example.com";
    agentCard.capabilities = std::make_shared<Capabilities>();
    agentCard.authentication = std::make_shared<Authentication>();
    agentCard.defaultInputModes = {"input1", "input2"};
    agentCard.defaultOutputModes = {"output1", "output2"};
    agentCard.skills = {std::make_shared<Skill>()};

    AgentCardsRawData rawData;
    std::vector<AgentCard> vec = { agentCard };
    AgentCardsRawData::FromAgentCardVec(vec, rawData);
    EXPECT_NE(rawData.data, nullptr);
    EXPECT_TRUE(rawData.size > 0);
}
} // namespace AgentRuntime
} // namespace OHOS