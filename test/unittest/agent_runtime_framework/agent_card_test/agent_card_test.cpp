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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "agent_card.h"

using namespace OHOS;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AgentRuntime {
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

    EXPECT_TRUE(authentication != nullptr);
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

    EXPECT_TRUE(skill != nullptr);
}
} // namespace AgentRuntime
} // namespace OHOS