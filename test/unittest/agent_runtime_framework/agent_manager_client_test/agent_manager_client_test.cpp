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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "agent_card.h"
#define private public
#include "ability_manager_errors.h"
#include "agent_manager_client.h"
#include "agent_load_callback.h"
#include "hilog_tag_wrapper.h"
#undef private
#include "mock_agent_manager_service.h"
#include "mock_my_flag.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AgentRuntime;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace AgentRuntime {
class AgentManagerClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void AgentManagerClientTest::SetUpTestCase(void)
{}

void AgentManagerClientTest::TearDownTestCase(void)
{}

void AgentManagerClientTest::SetUp(void)
{}

void AgentManagerClientTest::TearDown(void)
{}

/**
* @tc.name  : GetAllAgentCards_ShouldReturnError_WhenProxyIsNull
* @tc.number: GetAllAgentCards_001
* @tc.desc  : Test that GetAllAgentCards returns ERR_NULL_AGENT_MGR_PROXY when the agent manager proxy is null.
*/
HWTEST_F(AgentManagerClientTest, GetAllAgentCards_001, TestSize.Level1)
{
    AgentManagerClient client;
    MyFlag::nullSystemAbility = true;
    
    std::vector<AgentCard> cards;
    int32_t result = client.GetAllAgentCards(cards);
    EXPECT_EQ(result, ERR_NULL_AGENT_MGR_PROXY);
}

/**
* @tc.name  : GetAllAgentCards_ShouldReturnError_WhenRawDataRetrievalFails
* @tc.number: GetAllAgentCards_002
* @tc.desc  : Test that GetAllAgentCards returns the error code when retrieving raw data fails.
*/
HWTEST_F(AgentManagerClientTest, GetAllAgentCards_002, TestSize.Level1)
{
    AgentManagerClient client;
    MyFlag::nullSystemAbility = false;
    auto mockAgentMgr = sptr<MockAgentManagerService>::MakeSptr();
    client.agentMgr_ = mockAgentMgr;
    MyFlag::retGetAllAgentCards = -1;

    std::vector<AgentCard> cards;
    int32_t result = client.GetAllAgentCards(cards);
    EXPECT_EQ(result, -1);
}

/**
* @tc.name  : GetAllAgentCards_ShouldReturnError_WhenToAgentCardVecFails
* @tc.number: GetAllAgentCards_003
* @tc.desc  : Test that GetAllAgentCards returns the error code when retrieving raw data fails.
*/
HWTEST_F(AgentManagerClientTest, GetAllAgentCards_003, TestSize.Level1)
{
    AgentManagerClient client;
    MyFlag::nullSystemAbility = false;
    auto mockAgentMgr = sptr<MockAgentManagerService>::MakeSptr();
    client.agentMgr_ = mockAgentMgr;
    MyFlag::retGetAllAgentCards = ERR_OK;
    MyFlag::retToAgentCardVec = -1;

    std::vector<AgentCard> cards;
    int32_t result = client.GetAllAgentCards(cards);
    EXPECT_EQ(result, -1);
}

/**
* @tc.name  : GetAllAgentCards_ShouldReturnSuccess_WhenAllOperationsSucceed
* @tc.number: GetAllAgentCards_004
* @tc.desc  : Test that GetAllAgentCards returns ERR_OK when all operations succeed.
*/
HWTEST_F(AgentManagerClientTest, GetAllAgentCards_004, TestSize.Level1)
{
    AgentManagerClient client;
    MyFlag::nullSystemAbility = false;
    auto mockAgentMgr = sptr<MockAgentManagerService>::MakeSptr();
    client.agentMgr_ = mockAgentMgr;
    MyFlag::retGetAllAgentCards = ERR_OK;
    MyFlag::retToAgentCardVec = ERR_OK;

    std::vector<AgentCard> cards;
    int32_t result = client.GetAllAgentCards(cards);
    EXPECT_EQ(result, ERR_OK);
}

/**
* @tc.name  : GetAgentCardsByBundleName_ShouldReturnError_WhenProxyIsNull
* @tc.number: GetAgentCardsByBundleName_001
* @tc.desc  : Test that GetAgentCardsByBundleName returns ERR_NULL_AGENT_MGR_PROXY when the agent manager proxy is null.
*/
HWTEST_F(AgentManagerClientTest, GetAgentCardsByBundleName_001, TestSize.Level1)
{
    AgentManagerClient client;
    MyFlag::nullSystemAbility = true;
    
    std::vector<AgentCard> cards;
    std::string bundleName = "bundle";
    int32_t result = client.GetAgentCardsByBundleName(bundleName, cards);
    EXPECT_EQ(result, ERR_NULL_AGENT_MGR_PROXY);
}

/**
* @tc.name  : GetAgentCardsByBundleName_ShouldReturnError_WhenRawDataRetrievalFails
* @tc.number: GetAgentCardsByBundleName_002
* @tc.desc  : Test that GetAgentCardsByBundleName returns the error code when retrieving raw data fails.
*/
HWTEST_F(AgentManagerClientTest, GetAgentCardsByBundleName_002, TestSize.Level1)
{
    AgentManagerClient client;
    MyFlag::nullSystemAbility = false;
    auto mockAgentMgr = sptr<MockAgentManagerService>::MakeSptr();
    client.agentMgr_ = mockAgentMgr;
    MyFlag::retGetAgentCardsByBundleName = -1;

    std::vector<AgentCard> cards;
    std::string bundleName = "bundle";
    int32_t result = client.GetAgentCardsByBundleName(bundleName, cards);
    EXPECT_EQ(result, -1);
}

/**
* @tc.name  : GetAgentCardsByBundleName_ShouldReturnSuccess_WhenAllOperationsSucceed
* @tc.number: GetAgentCardsByBundleName_003
* @tc.desc  : Test that GetAgentCardsByBundleName returns ERR_OK when all operations succeed.
*/
HWTEST_F(AgentManagerClientTest, GetAgentCardsByBundleName_003, TestSize.Level1)
{
    AgentManagerClient client;
    MyFlag::nullSystemAbility = false;
    auto mockAgentMgr = sptr<MockAgentManagerService>::MakeSptr();
    client.agentMgr_ = mockAgentMgr;
    MyFlag::retGetAgentCardsByBundleName = ERR_OK;

    std::vector<AgentCard> cards;
    std::string bundleName = "bundle";
    int32_t result = client.GetAgentCardsByBundleName(bundleName, cards);
    EXPECT_EQ(result, ERR_OK);
}

/**
* @tc.name  : GetAgentCardByUrl_ShouldReturnError_WhenProxyIsNull
* @tc.number: GetAgentCardByUrl_001
* @tc.desc  : Test that GetAgentCardByUrl returns ERR_NULL_AGENT_MGR_PROXY when the agent manager proxy is null.
*/
HWTEST_F(AgentManagerClientTest, GetAgentCardByUrl_001, TestSize.Level1)
{
    AgentManagerClient client;
    MyFlag::nullSystemAbility = true;
    
    AgentCard card;
    std::string bundleName = "bundle";
    std::string url = "url";
    int32_t result = client.GetAgentCardByUrl(bundleName, url, card);
    EXPECT_EQ(result, ERR_NULL_AGENT_MGR_PROXY);
}

/**
* @tc.name  : GetAgentCardByUrl_ShouldReturnError_WhenRawDataRetrievalFails
* @tc.number: GetAgentCardByUrl_002
* @tc.desc  : Test that GetAgentCardByUrl returns the error code when retrieving raw data fails.
*/
HWTEST_F(AgentManagerClientTest, GetAgentCardByUrl_002, TestSize.Level1)
{
    AgentManagerClient client;
    MyFlag::nullSystemAbility = false;
    auto mockAgentMgr = sptr<MockAgentManagerService>::MakeSptr();
    client.agentMgr_ = mockAgentMgr;
    MyFlag::retGetAgentCardByUrl = -1;

    AgentCard card;
    std::string bundleName = "bundle";
    std::string url = "url";
    int32_t result = client.GetAgentCardByUrl(bundleName, url, card);
    EXPECT_EQ(result, -1);
}

/**
* @tc.name  : GetAgentCardByUrl_ShouldReturnSuccess_WhenAllOperationsSucceed
* @tc.number: GetAgentCardByUrl_003
* @tc.desc  : Test that GetAgentCardByUrl returns ERR_OK when all operations succeed.
*/
HWTEST_F(AgentManagerClientTest, GetAgentCardByUrl_003, TestSize.Level1)
{
    AgentManagerClient client;
    MyFlag::nullSystemAbility = false;
    auto mockAgentMgr = sptr<MockAgentManagerService>::MakeSptr();
    client.agentMgr_ = mockAgentMgr;
    MyFlag::retGetAgentCardByUrl = ERR_OK;

    AgentCard card;
    std::string bundleName = "bundle";
    std::string url = "url";
    int32_t result = client.GetAgentCardByUrl(bundleName, url, card);
    EXPECT_EQ(result, ERR_OK);
}

/**
* @tc.name  : GetAgentMgrProxy_ShouldReturnAgentMgr_WhenAgentMgrIsAlreadyStarted
* @tc.number: GetAgentMgrProxy_001
* @tc.desc  : Test that GetAgentMgrProxy returns the existing agent manager when it is already started.
*/
HWTEST_F(AgentManagerClientTest, GetAgentMgrProxy_001, TestSize.Level1)
{
    AgentManagerClient client;
    auto mockAgentMgr = sptr<MockAgentManagerService>::MakeSptr();
    client.agentMgr_ = mockAgentMgr;

    auto result = client.GetAgentMgrProxy();
    EXPECT_EQ(result->AsObject(), mockAgentMgr->AsObject());
}

/**
* @tc.name  : GetAgentMgrProxy_ShouldReturnNull_WhenLoadAgentMgrServiceFails
* @tc.number: GetAgentMgrProxy_002
* @tc.desc  : Test that GetAgentMgrProxy returns nullptr when loading the agent manager service fails.
*/
HWTEST_F(AgentManagerClientTest, GetAgentMgrProxy_002, TestSize.Level1)
{
    AgentManagerClient client;
    MyFlag::nullSystemAbility = true;

    auto result = client.GetAgentMgrProxy();
    EXPECT_EQ(result, nullptr);
}

/**
* @tc.name  : GetAgentMgrProxy_ShouldReturnNull_WhenGetAgentMgrFailsAfterLoad
* @tc.number: GetAgentMgrProxy_003
* @tc.desc  : Test that GetAgentMgrProxy returns nullptr when getting the agent manager fails after loading the service.
*/
HWTEST_F(AgentManagerClientTest, GetAgentMgrProxy_003, TestSize.Level1)
{
    MyFlag::nullSystemAbility = false;
    MyFlag::retLoadSystemAbility = 0;
    MyFlag::agentMgr = nullptr;
    MyFlag::shouldCallback = true;

    auto result = AgentManagerClient::GetInstance().GetAgentMgrProxy();
    EXPECT_EQ(result, nullptr);
}

/**
* @tc.name  : GetAgentMgrProxy_ShouldReturnAgentMgr_WhenAgentMgrIsSuccessfullyLoaded
* @tc.number: GetAgentMgrProxy_004
* @tc.desc  : Test that GetAgentMgrProxy returns the agent manager when it is successfully loaded.
*/
HWTEST_F(AgentManagerClientTest, GetAgentMgrProxy_004, TestSize.Level1)
{
    MyFlag::nullSystemAbility = false;
    MyFlag::retLoadSystemAbility = 0;
    auto mockAgentMgr = sptr<MockAgentManagerService>::MakeSptr();
    MyFlag::agentMgr = mockAgentMgr;
    MyFlag::shouldCallback = true;

    auto result = AgentManagerClient::GetInstance().GetAgentMgrProxy();
    EXPECT_EQ(result->AsObject(), mockAgentMgr->AsObject());
}

/**
* @tc.name  : ClearProxy_ShouldSetAgentMgrToNull_WhenCalled
* @tc.number: ClearProxy_001
* @tc.desc  : Verify that the agentMgr_ pointer is set to nullptr when ClearProxy is called.
*/
HWTEST_F(AgentManagerClientTest, ClearProxy_001, TestSize.Level1)
{
    AgentManagerClient client;
    auto mockAgentMgr = sptr<MockAgentManagerService>::MakeSptr();
    client.agentMgr_ = mockAgentMgr;

    // Act: Call ClearProxy
    client.ClearProxy();
    EXPECT_EQ(client.agentMgr_, nullptr);
}

/**
* @tc.name  : LoadAgentMgrService_ShouldReturnFalse_WhenSystemAbilityManagerIsNull
* @tc.number: LoadAgentMgrService_001
* @tc.desc  : Test that LoadAgentMgrService returns false when SystemAbilityManager is null
*/
HWTEST_F(AgentManagerClientTest, LoadAgentMgrService_001, TestSize.Level1)
{
    MyFlag::nullSystemAbility = true;

    EXPECT_FALSE(AgentManagerClient::GetInstance().LoadAgentMgrService());
}

/**
* @tc.name  : LoadAgentMgrService_ShouldReturnFalse_WhenLoadSystemAbilityFails
* @tc.number: LoadAgentMgrService_002
* @tc.desc  : Test that LoadAgentMgrService returns false when LoadSystemAbility fails
*/
HWTEST_F(AgentManagerClientTest, LoadAgentMgrService_002, TestSize.Level1)
{
    MyFlag::nullSystemAbility = false;
    MyFlag::retLoadSystemAbility = -1;

    EXPECT_FALSE(AgentManagerClient::GetInstance().LoadAgentMgrService());
}

/**
* @tc.name  : LoadAgentMgrService_ShouldReturnFalse_WhenLoadSaTimeout
* @tc.number: LoadAgentMgrService_003
* @tc.desc  : Test that LoadAgentMgrService returns false when waiting for system ability loading times out
*/
HWTEST_F(AgentManagerClientTest, LoadAgentMgrService_003, TestSize.Level1)
{
    MyFlag::nullSystemAbility = false;
    MyFlag::retLoadSystemAbility = 0;
    MyFlag::shouldCallback = false;

    EXPECT_FALSE(AgentManagerClient::GetInstance().LoadAgentMgrService());
}

/**
* @tc.name  : LoadAgentMgrService_ShouldReturnTrue_WhenAllStepsSucceed
* @tc.number: LoadAgentMgrService_004
* @tc.desc  : Test that LoadAgentMgrService returns true when all steps succeed
*/
HWTEST_F(AgentManagerClientTest, LoadAgentMgrService_004, TestSize.Level1)
{
    MyFlag::nullSystemAbility = false;
    MyFlag::retLoadSystemAbility = 0;
    MyFlag::shouldCallback = true;

    EXPECT_TRUE(AgentManagerClient::GetInstance().LoadAgentMgrService());
}

/**
* @tc.name  : SetAgentMgr_ShouldSetAgentMgr_WhenValidRemoteObjectIsPassed
* @tc.number: SetAgentMgr_001
* @tc.desc  : Test that the agentMgr_ is set correctly when a valid remoteObject is passed.
*/
HWTEST_F(AgentManagerClientTest, SetAgentMgr_001, TestSize.Level1)
{
    AgentManagerClient client;
    auto mockAgentMgr = sptr<MockAgentManagerService>::MakeSptr();
    ASSERT_NE(mockAgentMgr, nullptr);

    client.SetAgentMgr(mockAgentMgr);

    EXPECT_NE(client.agentMgr_, nullptr);
}

/**
* @tc.name  : SetAgentMgr_ShouldSetAgentMgrToNull_WhenNullRemoteObjectIsPassed
* @tc.number: SetAgentMgr_002
* @tc.desc  : Test that the agentMgr_ is set to nullptr when a nullptr is passed.
*/
HWTEST_F(AgentManagerClientTest, SetAgentMgr_002, TestSize.Level1)
{
    AgentManagerClient client;

    client.SetAgentMgr(nullptr);

    EXPECT_EQ(client.agentMgr_, nullptr);
}

/**
* @tc.name  : GetAgentMgr_ShouldReturnAgentMgr_WhenCalled
* @tc.number: GetAgentMgr_001
* @tc.desc  : Test that GetAgentMgr returns the agentMgr_ object when called.
*/
HWTEST_F(AgentManagerClientTest, GetAgentMgr_001, TestSize.Level1)
{
    AgentManagerClient client;
    auto mockAgentMgr = sptr<MockAgentManagerService>::MakeSptr();
    client.agentMgr_ = mockAgentMgr;

    // Act
    sptr<IAgentManager> actualAgentMgr = client.GetAgentMgr();

    // Assert
    EXPECT_EQ(mockAgentMgr->AsObject(), actualAgentMgr->AsObject());
}

/**
* @tc.name  : GetAgentMgr_ShouldReturnAgentMgr_WhenCalled
* @tc.number: GetAgentMgr_002
* @tc.desc  : Test that GetAgentMgr returns the agentMgr_ object when called.
*/
HWTEST_F(AgentManagerClientTest, GetAgentMgr_002, TestSize.Level1)
{
    AgentManagerClient client;

    // Act
    sptr<IAgentManager> actualAgentMgr = client.GetAgentMgr();

    // Assert
    EXPECT_EQ(actualAgentMgr, nullptr);
}

/**
* @tc.name  : SetAgentMgr_ShouldBeCalledWithRemoteObject_WhenOnLoadSystemAbilitySuccessIsCalled
* @tc.number: OnLoadSystemAbilitySuccess_001
* @tc.desc  : Verify that SetAgentMgr is called with the correct remoteObject
*/
HWTEST_F(AgentManagerClientTest, OnLoadSystemAbilitySuccess_001, TestSize.Level1)
{
    AgentManagerClient client;
    auto mockAgentMgr = sptr<MockAgentManagerService>::MakeSptr();

    // Act
    client.OnLoadSystemAbilitySuccess(mockAgentMgr);

    EXPECT_EQ(client.agentMgr_->AsObject(), mockAgentMgr->AsObject());
    EXPECT_TRUE(client.loadSaFinished_);
}

/**
* @tc.name  : SetAgentMgr_ShouldBeCalledWithRemoteObject_WhenOnLoadSystemAbilityFailIsCalled
* @tc.number: OnLoadSystemAbilityFail_001
* @tc.desc  : Verify that SetAgentMgr is called with the correct remoteObject
*/
HWTEST_F(AgentManagerClientTest, OnLoadSystemAbilityFail_001, TestSize.Level1)
{
    AgentManagerClient client;

    // Act
    client.OnLoadSystemAbilityFail();

    EXPECT_EQ(client.agentMgr_, nullptr);
    EXPECT_TRUE(client.loadSaFinished_);
}

/**
* @tc.name  : OnRemoteDied_001
* @tc.number: OnRemoteDied_001
* @tc.desc  : Test that the OnRemoteDied function calls the proxy callback when proxy_ is not nullptr.
*/
HWTEST_F(AgentManagerClientTest, OnRemoteDied_001, TestSize.Level1)
{
    // Mock the proxy callback
    bool proxyCalled = false;
    auto proxy = [&proxyCalled](const wptr<IRemoteObject> &) {
        proxyCalled = true;
    };
    
    // Arrange
    auto deathRecipient = sptr<AgentManagerClient::AgentManagerServiceDeathRecipient>::MakeSptr(proxy);
    wptr<IRemoteObject> remoteObject = nullptr;

    // Act
    deathRecipient->OnRemoteDied(remoteObject);

    // Assert
    EXPECT_TRUE(proxyCalled);
}

/**
* @tc.name  : OnRemoteDied_002
* @tc.number: OnRemoteDied_002
* @tc.desc  : Test that the OnRemoteDied function does not call the proxy callback when proxy_ is nullptr.
*/
HWTEST_F(AgentManagerClientTest, OnRemoteDied_002, TestSize.Level1)
{
    // Mock the proxy callback
    bool proxyCalled = false;
    auto proxy = [&proxyCalled](const wptr<IRemoteObject> &) {
        proxyCalled = true;
    };
    
    // Arrange
    auto deathRecipient = sptr<AgentManagerClient::AgentManagerServiceDeathRecipient>::MakeSptr(proxy);
    wptr<IRemoteObject> remoteObject = nullptr;

    // Act
    deathRecipient->proxy_ = nullptr;
    deathRecipient->OnRemoteDied(remoteObject);

    // Assert
    EXPECT_FALSE(proxyCalled);
}
} // namespace AgentRuntime
} // namespace OHOS