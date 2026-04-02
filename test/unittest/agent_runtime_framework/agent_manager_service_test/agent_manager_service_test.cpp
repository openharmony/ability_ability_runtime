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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "ability_connect_callback_interface.h"
#include "ability_manager_errors.h"
#include "agent_card.h"
#include "agent_extension_connection_constants.h"

#define private public
#include "agent_bundle_event_callback.h"
#include "agent_manager_service.h"
#include "agent_load_callback.h"
#undef private
#include "hilog_tag_wrapper.h"
#include "ipc_object_stub.h"
#include "iremote_object.h"
#include "mock_my_flag.h"
#include "system_ability.h"
#include "want.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AgentRuntime;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace AgentRuntime {
const int BUNDLE_MGR_SERVICE_SYS_ABILITY_ID = 401;

class AgentManagerServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void AgentManagerServiceTest::SetUpTestCase(void)
{}

void AgentManagerServiceTest::TearDownTestCase(void)
{}

void AgentManagerServiceTest::SetUp(void)
{
    MyFlag::isAddSystemAbilityListenerCalled = false;
    MyFlag::isRegisterBundleEventCallbackCalled = false;
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retVerifyConnectAgentPermission = true;
    MyFlag::retVerifyGetAgentCardPermission = true;
    MyFlag::retJudgeCallerIsAllowedToUseSystemAPI = true;
    MyFlag::retVerifyModifyAgentCardPermission = true;
    MyFlag::retRegisterAgentCard = ERR_OK;
    MyFlag::retUpdateAgentCard = ERR_OK;
    MyFlag::retDeleteAgentCard = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    MyFlag::retDisconnectAbility = ERR_OK;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::extensionAbilityType = AppExecFwk::ExtensionAbilityType::AGENT;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::retGetBundleNameByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::agentCardAgentId = "testAgent";
    MyFlag::agentCardBundleName = "test.bundle";
    MyFlag::agentCardModuleName = "";
    MyFlag::agentCardAbilityName = "TestAbility";
    MyFlag::shouldCreateAgentCardAppInfo = true;
    MyFlag::lastConnectAbilityConnection = nullptr;
    MyFlag::lastDisconnectAbilityConnection = nullptr;
    auto service = AgentManagerService::GetInstance();
    service->trackedConnections_.clear();
    service->callerConnectionCounts_.clear();
}

void AgentManagerServiceTest::TearDown(void)
{}

/**
* @tc.name  : GetInstance_ShouldReturnNewInstance_WhenCalledFirstTime
* @tc.number: GetInstance_001
* @tc.desc  : Test that GetInstance returns a new instance when called for the first time
*/
HWTEST_F(AgentManagerServiceTest, GetInstance_001, TestSize.Level1)
{
    sptr<AgentManagerService> instance = AgentManagerService::GetInstance();
    EXPECT_NE(instance, nullptr);
}

/**
* @tc.name  : GetInstance_ShouldReturnSameInstance_WhenCalledSubsequently
* @tc.number: GetInstance_002
* @tc.desc  : Test that GetInstance returns the same instance when called subsequently
*/
HWTEST_F(AgentManagerServiceTest, GetInstance_002, TestSize.Level1)
{
    sptr<AgentManagerService> instance1 = AgentManagerService::GetInstance();
    sptr<AgentManagerService> instance2 = AgentManagerService::GetInstance();
    EXPECT_EQ(instance1, instance2);
}

/**
* @tc.name  : GetInstance_ShouldReturnNullptr_WhenMemoryAllocationFails
* @tc.number: GetInstance_003
* @tc.desc  : Test that GetInstance returns nullptr when memory allocation fails
*/
HWTEST_F(AgentManagerServiceTest, GetInstance_003, TestSize.Level1)
{
    sptr<AgentManagerService> instance = sptr<AgentManagerService>::MakeSptr();
    AgentManagerService::instance_ = instance;
    auto outputInstance = AgentManagerService::GetInstance();
    EXPECT_EQ(instance, outputInstance);
}

/**
* @tc.name  : OnStart_ShouldLogPublishFailure_WhenPublishFails
* @tc.number: OnStart_001
* @tc.desc  : Test that OnStart logs a publish failure message when Publish fails.
*/
HWTEST_F(AgentManagerServiceTest, OnStart_001, TestSize.Level1)
{
    AgentManagerService::GetInstance()->OnStart();
    EXPECT_FALSE(MyFlag::isAddSystemAbilityListenerCalled);
}

/**
* @tc.name  : OnStart_ShouldLogAddBundleMgrFailure_WhenAddSystemAbilityListenerFails
* @tc.number: OnStart_002
* @tc.desc  : Test that OnStart logs an addBundleMgr failure message when AddSystemAbilityListener fails.
*/
HWTEST_F(AgentManagerServiceTest, OnStart_002, TestSize.Level1)
{
    MyFlag::retPublish = true;
    MyFlag::retAddSystemAbilityListener = false;
    AgentManagerService::GetInstance()->OnStart();
    EXPECT_TRUE(MyFlag::isAddSystemAbilityListenerCalled);
}

/**
* @tc.name  : OnStart_ShouldLogStartAndInitialize_WhenPublishAndAddSystemAbilityListenerSucceed
* @tc.number: OnStart_003
* @tc.desc  : Test when Publish and AddSystemAbilityListener succeed.
*/
HWTEST_F(AgentManagerServiceTest, OnStart_003, TestSize.Level1)
{
    MyFlag::retPublish = true;
    MyFlag::retAddSystemAbilityListener = true;
    AgentManagerService::GetInstance()->OnStart();
    EXPECT_TRUE(MyFlag::isAddSystemAbilityListenerCalled);
}

/**
* @tc.name  : OnStop_001
* @tc.number: OnStop_001
* @tc.desc  : Test OnStop clears tracked connections and caller counts
*/
HWTEST_F(AgentManagerServiceTest, OnStop_001, TestSize.Level1)
{
    auto connection = sptr<IRemoteObject>(new (std::nothrow) IPCObjectStub(u"tracked.remote"));
    AgentManagerService::TrackedConnectionRecord record;
    record.callerUid = 100;
    AgentManagerService::GetInstance()->trackedConnections_.emplace(connection, record);
    AgentManagerService::GetInstance()->callerConnectionCounts_[100] = 1;

    AgentManagerService::GetInstance()->OnStop();

    EXPECT_TRUE(AgentManagerService::GetInstance()->trackedConnections_.empty());
    EXPECT_TRUE(AgentManagerService::GetInstance()->callerConnectionCounts_.empty());
}

/**
* @tc.name  : OnAddSystemAbility_001
* @tc.number: OnAddSystemAbility_001
* @tc.desc  : OnAddSystemAbility_001
*/
HWTEST_F(AgentManagerServiceTest, OnAddSystemAbility_001, TestSize.Level1)
{
    int32_t invalidSystemAbilityId = BUNDLE_MGR_SERVICE_SYS_ABILITY_ID + 1;
    AgentManagerService::GetInstance()->OnAddSystemAbility(invalidSystemAbilityId, "123");
    EXPECT_FALSE(MyFlag::isRegisterBundleEventCallbackCalled);
}

/**
* @tc.name  : OnAddSystemAbility_002
* @tc.number: OnAddSystemAbility_002
* @tc.desc  : OnAddSystemAbility_002
*/
HWTEST_F(AgentManagerServiceTest, OnAddSystemAbility_002, TestSize.Level1)
{
    int32_t systemAbilityId = BUNDLE_MGR_SERVICE_SYS_ABILITY_ID;
    AgentManagerService::GetInstance()->bundleEventCallback_ = nullptr;
    AgentManagerService::GetInstance()->OnAddSystemAbility(systemAbilityId, "123");
    EXPECT_TRUE(MyFlag::isRegisterBundleEventCallbackCalled);
}

/**
* @tc.name  : RegisterBundleEventCallback_ShouldNotRegister_WhenCallbackAlreadyExists
* @tc.number: RegisterBundleEventCallback_001
* @tc.desc  : Test that the function returns immediately when the callback is already registered.
*/
HWTEST_F(AgentManagerServiceTest, RegisterBundleEventCallback_001, TestSize.Level1)
{
    // Set the bundleEventCallback_ to a non-null value
    AgentManagerService::GetInstance()->bundleEventCallback_ = sptr<AgentBundleEventCallback>::MakeSptr();

    // Call the function
    AgentManagerService::GetInstance()->RegisterBundleEventCallback();

    // Verify that the callback is not registered again
    EXPECT_NE(AgentManagerService::GetInstance()->bundleEventCallback_, nullptr);
    EXPECT_FALSE(MyFlag::isRegisterBundleEventCallbackCalled);
}

/**
* @tc.name  : RegisterBundleEventCallback_ShouldRegisterSuccessfully_WhenCallbackNotRegistered
* @tc.number: RegisterBundleEventCallback_002
* @tc.desc  : Test that the function successfully registers the callback when it is not already registered.
*/
HWTEST_F(AgentManagerServiceTest, RegisterBundleEventCallback_002, TestSize.Level1)
{
    // Ensure bundleEventCallback_ is nullptr
    AgentManagerService::GetInstance()->bundleEventCallback_ = nullptr;
    MyFlag::retRegisterBundleEventCallback = true;

    // Call the function
    AgentManagerService::GetInstance()->RegisterBundleEventCallback();

    // Verify that the callback is registered
    EXPECT_NE(AgentManagerService::GetInstance()->bundleEventCallback_, nullptr);
    EXPECT_TRUE(MyFlag::isRegisterBundleEventCallbackCalled);
}

/**
* @tc.name  : RegisterBundleEventCallback_ShouldNotRegister_WhenRegistrationFails
* @tc.number: RegisterBundleEventCallback_003
* @tc.desc  : Test that the function does not register the callback when the registration attempt fails.
*/
HWTEST_F(AgentManagerServiceTest, RegisterBundleEventCallback_003, TestSize.Level1)
{
    // Ensure bundleEventCallback_ is nullptr
    AgentManagerService::GetInstance()->bundleEventCallback_ = nullptr;
    MyFlag::retRegisterBundleEventCallback = false;

    // Call the function
    AgentManagerService::GetInstance()->RegisterBundleEventCallback();

    // Verify that the callback is registered
    EXPECT_EQ(AgentManagerService::GetInstance()->bundleEventCallback_, nullptr);
    EXPECT_TRUE(MyFlag::isRegisterBundleEventCallbackCalled);
}

/**
* @tc.name  : GetAllAgentCards
* @tc.number: GetAllAgentCards_001
* @tc.desc  : GetAllAgentCards_001
*/
HWTEST_F(AgentManagerServiceTest, GetAllAgentCards_001, TestSize.Level1)
{
    MyFlag::retJudgeCallerIsAllowedToUseSystemAPI = false;
    AgentCardsRawData rawData;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAllAgentCards(rawData), ERR_NOT_SYSTEM_APP);
}

/**
* @tc.name  : GetAllAgentCards_002
* @tc.number: GetAllAgentCards_002
* @tc.desc  : GetAllAgentCards success
*/
HWTEST_F(AgentManagerServiceTest, GetAllAgentCards_002, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    AgentCardsRawData rawData;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAllAgentCards(rawData), ERR_OK);
}

/**
* @tc.name  : GetAllAgentCards_003
* @tc.number: GetAllAgentCards_003
* @tc.desc  : Test GetAllAgentCards when permission verification fails
*/
HWTEST_F(AgentManagerServiceTest, GetAllAgentCards_003, TestSize.Level1)
{
    MyFlag::retVerifyGetAgentCardPermission = false;
    AgentCardsRawData rawData;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAllAgentCards(rawData), ERR_PERMISSION_DENIED);
    MyFlag::retVerifyGetAgentCardPermission = true;
}

/**
* @tc.name  : GetAllAgentCards_004
* @tc.number: GetAllAgentCards_004
* @tc.desc  : Test GetAllAgentCards propagates AgentCardMgr failure
*/
HWTEST_F(AgentManagerServiceTest, GetAllAgentCards_004, TestSize.Level1)
{
    MyFlag::retGetAllAgentCards = ERR_INVALID_VALUE;
    AgentCardsRawData rawData;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAllAgentCards(rawData), ERR_INVALID_VALUE);
    MyFlag::retGetAllAgentCards = ERR_OK;
}

/**
* @tc.name  : GetAgentCardsByBundleName
* @tc.number: GetAgentCardsByBundleName_000
* @tc.desc  : Test GetAgentCardsByBundleName when caller is not allowed to use system API
*/
HWTEST_F(AgentManagerServiceTest, GetAgentCardsByBundleName_000, TestSize.Level1)
{
    MyFlag::retJudgeCallerIsAllowedToUseSystemAPI = false;
    std::string bundleName = "bundle";
    std::vector<AgentCard> cards;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAgentCardsByBundleName(bundleName, cards), ERR_NOT_SYSTEM_APP);
}

/**
* @tc.name  : GetAgentCardsByBundleName
* @tc.number: GetAgentCardsByBundleName_001
* @tc.desc  : GetAgentCardsByBundleName_001
*/
HWTEST_F(AgentManagerServiceTest, GetAgentCardsByBundleName_001, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retGetAgentCardsByBundleName = ERR_NAME_NOT_FOUND;
    MyFlag::retGetApplicationInfo = true;
    std::string bundleName = "bundle";
    std::vector<AgentCard> cards;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAgentCardsByBundleName(bundleName, cards), ERR_OK);
    MyFlag::retGetAgentCardsByBundleName = ERR_OK;
}

/**
* @tc.name  : GetAgentCardsByBundleName_002
* @tc.number: GetAgentCardsByBundleName_002
* @tc.desc  : Test GetAgentCardsByBundleName when permission verification fails
*/
HWTEST_F(AgentManagerServiceTest, GetAgentCardsByBundleName_002, TestSize.Level1)
{
    MyFlag::retVerifyGetAgentCardPermission = false;
    std::string bundleName = "bundle";
    std::vector<AgentCard> cards;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAgentCardsByBundleName(bundleName, cards), ERR_PERMISSION_DENIED);
    MyFlag::retVerifyGetAgentCardPermission = true;
}

/**
* @tc.name  : GetAgentCardsByBundleName_003
* @tc.number: GetAgentCardsByBundleName_003
* @tc.desc  : Test GetAgentCardsByBundleName when GetAgentCardsByBundleName returns error
*/
HWTEST_F(AgentManagerServiceTest, GetAgentCardsByBundleName_003, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retGetAgentCardsByBundleName = ERR_INVALID_VALUE;
    std::string bundleName = "bundle";
    std::vector<AgentCard> cards;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAgentCardsByBundleName(bundleName, cards), ERR_INVALID_VALUE);
    MyFlag::retGetAgentCardsByBundleName = ERR_OK;
}

/**
* @tc.name  : GetAgentCardsByBundleName_004
* @tc.number: GetAgentCardsByBundleName_004
* @tc.desc  : Test GetAgentCardsByBundleName success case
*/
HWTEST_F(AgentManagerServiceTest, GetAgentCardsByBundleName_004, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retGetAgentCardsByBundleName = ERR_OK;
    std::string bundleName = "bundle";
    std::vector<AgentCard> cards;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAgentCardsByBundleName(bundleName, cards), ERR_OK);
}

/**
* @tc.name  : GetAgentCardsByBundleName_005
* @tc.number: GetAgentCardsByBundleName_005
* @tc.desc  : Test GetAgentCardsByBundleName when GetApplicationInfo returns false (bundle doesn't exist)
*/
HWTEST_F(AgentManagerServiceTest, GetAgentCardsByBundleName_005, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retGetAgentCardsByBundleName = ERR_NAME_NOT_FOUND;
    MyFlag::retGetApplicationInfo = false;
    std::string bundleName = "bundle";
    std::vector<AgentCard> cards;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAgentCardsByBundleName(bundleName, cards),
        AAFwk::ERR_BUNDLE_NOT_EXIST);
    MyFlag::retGetAgentCardsByBundleName = ERR_OK;
    MyFlag::retGetApplicationInfo = true;
}

/**
* @tc.name  : GetAgentCardByAgentId
* @tc.number: GetAgentCardByAgentId_000
* @tc.desc  : Test GetAgentCardByAgentId when caller is not allowed to use system API
*/
HWTEST_F(AgentManagerServiceTest, GetAgentCardByAgentId_000, TestSize.Level1)
{
    MyFlag::retJudgeCallerIsAllowedToUseSystemAPI = false;
    std::string bundleName = "bundle";
    std::string agentId = "agentId";
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAgentCardByAgentId(bundleName, agentId, card),
        ERR_NOT_SYSTEM_APP);
}

/**
* @tc.name  : GetAgentCardByAgentId
* @tc.number: GetAgentCardByAgentId_001
* @tc.desc  : GetAgentCardByAgentId_001
*/
HWTEST_F(AgentManagerServiceTest, GetAgentCardByAgentId_001, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retGetAgentCardByAgentId = ERR_NAME_NOT_FOUND;
    MyFlag::retGetApplicationInfo = true;
    std::string bundleName = "bundle";
    std::string agentId = "agentId";
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAgentCardByAgentId(bundleName, agentId, card),
        AAFwk::ERR_INVALID_AGENT_CARD_ID);
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
}

/**
* @tc.name  : GetAgentCardByAgentId_002
* @tc.number: GetAgentCardByAgentId_002
* @tc.desc  : Test GetAgentCardByAgentId when permission verification fails
*/
HWTEST_F(AgentManagerServiceTest, GetAgentCardByAgentId_002, TestSize.Level1)
{
    MyFlag::retVerifyGetAgentCardPermission = false;
    std::string bundleName = "bundle";
    std::string agentId = "agentId";
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAgentCardByAgentId(bundleName, agentId, card),
        ERR_PERMISSION_DENIED);
    MyFlag::retVerifyGetAgentCardPermission = true;
}

/**
* @tc.name  : GetAgentCardByAgentId_003
* @tc.number: GetAgentCardByAgentId_003
* @tc.desc  : Test GetAgentCardByAgentId when GetAgentCardByAgentId returns error
*/
HWTEST_F(AgentManagerServiceTest, GetAgentCardByAgentId_003, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retGetAgentCardByAgentId = ERR_INVALID_VALUE;
    std::string bundleName = "bundle";
    std::string agentId = "agentId";
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAgentCardByAgentId(bundleName, agentId, card), ERR_INVALID_VALUE);
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
}

/**
* @tc.name  : GetAgentCardByAgentId_004
* @tc.number: GetAgentCardByAgentId_004
* @tc.desc  : Test GetAgentCardByAgentId success case
*/
HWTEST_F(AgentManagerServiceTest, GetAgentCardByAgentId_004, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    std::string bundleName = "bundle";
    std::string agentId = "agentId";
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAgentCardByAgentId(bundleName, agentId, card), ERR_OK);
}

/**
* @tc.name  : GetAgentCardByAgentId_005
* @tc.number: GetAgentCardByAgentId_005
* @tc.desc  : Test GetAgentCardByAgentId when GetApplicationInfo returns false (bundle doesn't exist)
*/
HWTEST_F(AgentManagerServiceTest, GetAgentCardByAgentId_005, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retGetAgentCardByAgentId = ERR_NAME_NOT_FOUND;
    MyFlag::retGetApplicationInfo = false;
    std::string bundleName = "bundle";
    std::string agentId = "agentId";
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetAgentCardByAgentId(bundleName, agentId, card),
        AAFwk::ERR_BUNDLE_NOT_EXIST);
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retGetApplicationInfo = true;
}

/**
* @tc.name  : GetCallerAgentCardByAgentId_001
* @tc.number: GetCallerAgentCardByAgentId_001
* @tc.desc  : Test GetCallerAgentCardByAgentId when GetBundleNameByPid fails
*/
HWTEST_F(AgentManagerServiceTest, GetCallerAgentCardByAgentId_001, TestSize.Level1)
{
    MyFlag::retGetBundleNameByPid = ERR_INVALID_VALUE;
    std::string agentId = "agentId";
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetCallerAgentCardByAgentId(agentId, card), ERR_INVALID_VALUE);
    MyFlag::retGetBundleNameByPid = ERR_OK;
}

/**
* @tc.name  : GetCallerAgentCardByAgentId_002
* @tc.number: GetCallerAgentCardByAgentId_002
* @tc.desc  : Test GetCallerAgentCardByAgentId returns invalid card id when caller bundle exists but card is missing
*/
HWTEST_F(AgentManagerServiceTest, GetCallerAgentCardByAgentId_002, TestSize.Level1)
{
    MyFlag::retGetAgentCardByAgentId = ERR_NAME_NOT_FOUND;
    MyFlag::retGetApplicationInfo = true;
    std::string agentId = "agentId";
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetCallerAgentCardByAgentId(agentId, card),
        AAFwk::ERR_INVALID_AGENT_CARD_ID);
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
}

/**
* @tc.name  : GetCallerAgentCardByAgentId_003
* @tc.number: GetCallerAgentCardByAgentId_003
 * @tc.desc : Test GetCallerAgentCardByAgentId returns bundle not exist when caller bundle lookup succeeds but app info
 * is missing
*/
HWTEST_F(AgentManagerServiceTest, GetCallerAgentCardByAgentId_003, TestSize.Level1)
{
    MyFlag::retGetAgentCardByAgentId = ERR_NAME_NOT_FOUND;
    MyFlag::retGetApplicationInfo = false;
    std::string agentId = "agentId";
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetCallerAgentCardByAgentId(agentId, card),
        AAFwk::ERR_BUNDLE_NOT_EXIST);
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retGetApplicationInfo = true;
}

/**
* @tc.name  : GetCallerAgentCardByAgentId_004
* @tc.number: GetCallerAgentCardByAgentId_004
* @tc.desc  : Test GetCallerAgentCardByAgentId success case
*/
HWTEST_F(AgentManagerServiceTest, GetCallerAgentCardByAgentId_004, TestSize.Level1)
{
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    std::string agentId = "agentId";
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetCallerAgentCardByAgentId(agentId, card), ERR_OK);
}

/**
* @tc.name  : GetCallerAgentCardByAgentId_005
* @tc.number: GetCallerAgentCardByAgentId_005
* @tc.desc  : Test GetCallerAgentCardByAgentId propagates non-name-not-found errors from AgentCardMgr
*/
HWTEST_F(AgentManagerServiceTest, GetCallerAgentCardByAgentId_005, TestSize.Level1)
{
    MyFlag::retGetAgentCardByAgentId = ERR_INVALID_VALUE;
    std::string agentId = "agentId";
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->GetCallerAgentCardByAgentId(agentId, card), ERR_INVALID_VALUE);
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
}

/**
* @tc.name  : UpdateAgentCard_001
* @tc.number: UpdateAgentCard_001
* @tc.desc  : Test UpdateAgentCard when permission verification fails
*/
HWTEST_F(AgentManagerServiceTest, UpdateAgentCard_001, TestSize.Level1)
{
    MyFlag::retVerifyModifyAgentCardPermission = false;
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->UpdateAgentCard(card), ERR_PERMISSION_DENIED);
    MyFlag::retVerifyModifyAgentCardPermission = true;
}

/**
* @tc.name  : RegisterAgentCard_001
* @tc.number: RegisterAgentCard_001
* @tc.desc  : Test RegisterAgentCard when permission verification fails
*/
HWTEST_F(AgentManagerServiceTest, RegisterAgentCard_001, TestSize.Level1)
{
    MyFlag::retVerifyModifyAgentCardPermission = false;
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->RegisterAgentCard(card), ERR_PERMISSION_DENIED);
    MyFlag::retVerifyModifyAgentCardPermission = true;
}

/**
* @tc.name  : RegisterAgentCard_002
* @tc.number: RegisterAgentCard_002
* @tc.desc  : Test RegisterAgentCard propagates manager error
*/
HWTEST_F(AgentManagerServiceTest, RegisterAgentCard_002, TestSize.Level1)
{
    MyFlag::retRegisterAgentCard = AAFwk::ERR_AGENT_CARD_DUPLICATE_REGISTER;
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->RegisterAgentCard(card),
        AAFwk::ERR_AGENT_CARD_DUPLICATE_REGISTER);
}

/**
* @tc.name  : RegisterAgentCard_003
* @tc.number: RegisterAgentCard_003
* @tc.desc  : Test RegisterAgentCard success case
*/
HWTEST_F(AgentManagerServiceTest, RegisterAgentCard_003, TestSize.Level1)
{
    MyFlag::retRegisterAgentCard = ERR_OK;
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->RegisterAgentCard(card), ERR_OK);
}

/**
* @tc.name  : UpdateAgentCard_002
* @tc.number: UpdateAgentCard_002
* @tc.desc  : Test UpdateAgentCard propagates manager error
*/
HWTEST_F(AgentManagerServiceTest, UpdateAgentCard_002, TestSize.Level1)
{
    MyFlag::retUpdateAgentCard = AAFwk::ERR_AGENT_CARD_VERSION_TOO_OLD;
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->UpdateAgentCard(card),
        AAFwk::ERR_AGENT_CARD_VERSION_TOO_OLD);
}

/**
* @tc.name  : UpdateAgentCard_003
* @tc.number: UpdateAgentCard_003
* @tc.desc  : Test UpdateAgentCard success case
*/
HWTEST_F(AgentManagerServiceTest, UpdateAgentCard_003, TestSize.Level1)
{
    MyFlag::retUpdateAgentCard = ERR_OK;
    AgentCard card;
    EXPECT_EQ(AgentManagerService::GetInstance()->UpdateAgentCard(card), ERR_OK);
}

/**
* @tc.name  : DeleteAgentCard_001
* @tc.number: DeleteAgentCard_001
* @tc.desc  : Test DeleteAgentCard when permission verification fails
*/
HWTEST_F(AgentManagerServiceTest, DeleteAgentCard_001, TestSize.Level1)
{
    MyFlag::retVerifyModifyAgentCardPermission = false;
    EXPECT_EQ(AgentManagerService::GetInstance()->DeleteAgentCard("bundle", "agentId"), ERR_PERMISSION_DENIED);
    MyFlag::retVerifyModifyAgentCardPermission = true;
}

/**
* @tc.name  : DeleteAgentCard_002
* @tc.number: DeleteAgentCard_002
* @tc.desc  : Test DeleteAgentCard propagates manager error
*/
HWTEST_F(AgentManagerServiceTest, DeleteAgentCard_002, TestSize.Level1)
{
    MyFlag::retDeleteAgentCard = AAFwk::ERR_INVALID_AGENT_CARD_ID;
    EXPECT_EQ(AgentManagerService::GetInstance()->DeleteAgentCard("bundle", "agentId"),
        AAFwk::ERR_INVALID_AGENT_CARD_ID);
}

/**
* @tc.name  : DeleteAgentCard_003
* @tc.number: DeleteAgentCard_003
* @tc.desc  : Test DeleteAgentCard success case
*/
HWTEST_F(AgentManagerServiceTest, DeleteAgentCard_003, TestSize.Level1)
{
    MyFlag::retDeleteAgentCard = ERR_OK;
    EXPECT_EQ(AgentManagerService::GetInstance()->DeleteAgentCard("bundle", "agentId"), ERR_OK);
}

namespace {
class MockAbilityConnection : public IRemoteStub<AAFwk::IAbilityConnection> {
public:
    MockAbilityConnection() = default;
    ~MockAbilityConnection() override = default;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        return 0;
    }

    void OnAbilityConnectDone(
        const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject,
        int32_t resultCode) override
    {}

    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode) override
    {}
};
}

/**
* @tc.name  : ConnectAgentExtensionAbility_000
* @tc.number: ConnectAgentExtensionAbility_000
* @tc.desc  : Test ConnectAgentExtensionAbility when caller is not allowed to use system API
*/
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_000, TestSize.Level1)
{
    MyFlag::retJudgeCallerIsAllowedToUseSystemAPI = false;
    AAFwk::Want want;
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_NOT_SYSTEM_APP);
}

/**
* @tc.name  : ConnectAgentExtensionAbility_001
* @tc.number: ConnectAgentExtensionAbility_001
* @tc.desc  : Test ConnectAgentExtensionAbility when permission verification fails
*/
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_001, TestSize.Level1)
{
    MyFlag::retVerifyConnectAgentPermission = false;
    AAFwk::Want want;
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection),
        ERR_PERMISSION_DENIED);
    MyFlag::retVerifyConnectAgentPermission = true;
}

/**
* @tc.name  : ConnectAgentExtensionAbility_002
* @tc.number: ConnectAgentExtensionAbility_002
* @tc.desc  : Test ConnectAgentExtensionAbility when process is not foreground
*/
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_002, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_BACKGROUND;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection),
        AAFwk::NOT_TOP_ABILITY);
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
}

/**
* @tc.name  : ConnectAgentExtensionAbility_003
* @tc.number: ConnectAgentExtensionAbility_003
* @tc.desc  : Test ConnectAgentExtensionAbility bypasses GetAgentCard permission path and fails on missing card
*/
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_003, TestSize.Level1)
{
    MyFlag::retVerifyConnectAgentPermission = true;
    MyFlag::retVerifyGetAgentCardPermission = false;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_NAME_NOT_FOUND;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("nonExistentAgentId"));
    want.SetBundle("test.bundle");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    // ConnectAgentExtensionAbility should not rely on the extra GetAgentCard permission check.
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection),
        AAFwk::ERR_INVALID_AGENT_CARD_ID);
    MyFlag::retVerifyGetAgentCardPermission = true;
}

/**
* @tc.name  : ConnectAgentExtensionAbility_004
* @tc.number: ConnectAgentExtensionAbility_004
* @tc.desc  : Test ConnectAgentExtensionAbility when agentId is empty
*/
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_004, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    AAFwk::Want want;
    // agentId is not set, so it will be empty
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection),
        ERR_INVALID_VALUE);
}

/**
* @tc.name  : ConnectAgentExtensionAbility_005
* @tc.number: ConnectAgentExtensionAbility_005
* @tc.desc  : Test ConnectAgentExtensionAbility when connection is null
*/
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_005, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::agentCardAgentId = "testAgent";
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    sptr<AAFwk::IAbilityConnection> connection = nullptr;
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection),
        ERR_INVALID_VALUE);
}

/**
* @tc.name  : ConnectAgentExtensionAbility_006
* @tc.number: ConnectAgentExtensionAbility_006
* @tc.desc  : Test ConnectAgentExtensionAbility when ConnectAbilityWithExtensionType fails
*/
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_006, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::agentCardAgentId = "testAgent";
    MyFlag::retConnectAbilityWithExtensionType = ERR_INVALID_VALUE;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection),
        ERR_INVALID_VALUE);
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
}

/**
* @tc.name  : ConnectAgentExtensionAbility_007
* @tc.number: ConnectAgentExtensionAbility_007
* @tc.desc  : Test ConnectAgentExtensionAbility when extension ability does not exist
*/
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_007, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retQueryExtensionAbilityInfos = false;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection),
        AAFwk::RESOLVE_ABILITY_ERR);
    MyFlag::retQueryExtensionAbilityInfos = true;
}

/**
* @tc.name  : ConnectAgentExtensionAbility_008
* @tc.number: ConnectAgentExtensionAbility_008
* @tc.desc  : Test ConnectAgentExtensionAbility when GetRunningProcessInfoByPid fails
*/
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_008, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_INVALID_VALUE;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection),
        ERR_INVALID_VALUE);
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
}

/**
* @tc.name  : ConnectAgentExtensionAbility_009
* @tc.number: ConnectAgentExtensionAbility_009
* @tc.desc  : Test ConnectAgentExtensionAbility success case
*/
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_009, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::agentCardAgentId = "testAgent";
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_OK);
}

/**
 * @tc.name  : ConnectAgentExtensionAbility_014
 * @tc.number: ConnectAgentExtensionAbility_014
 * @tc.desc  : Test ConnectAgentExtensionAbility rejects want target mismatch with card appInfo
 */
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_014, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "OtherAbility");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection),
        AAFwk::ERR_WRONG_INTERFACE_CALL);
}

/**
 * @tc.name  : ConnectAgentExtensionAbility_015
 * @tc.number: ConnectAgentExtensionAbility_015
 * @tc.desc  : Test ConnectAgentExtensionAbility ignores module mismatch when want module is absent
 */
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_015, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    MyFlag::agentCardModuleName = "entry";
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_OK);
}

/**
 * @tc.name  : ConnectAgentExtensionAbility_016
 * @tc.number: ConnectAgentExtensionAbility_016
 * @tc.desc  : Test ConnectAgentExtensionAbility accepts explicit module when card module is empty
 */
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_016, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    MyFlag::agentCardModuleName = "";
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("", "test.bundle", "TestAbility", "entry");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_OK);
}

/**
 * @tc.name  : ConnectAgentExtensionAbility_017
 * @tc.number: ConnectAgentExtensionAbility_017
 * @tc.desc  : Test ConnectAgentExtensionAbility accepts explicit module when it matches card module
 */
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_017, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    MyFlag::agentCardModuleName = "entry";
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("", "test.bundle", "TestAbility", "entry");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_OK);
}

/**
 * @tc.name  : ConnectAgentExtensionAbility_018
 * @tc.number: ConnectAgentExtensionAbility_018
 * @tc.desc  : Test ConnectAgentExtensionAbility rejects explicit module mismatch with card appInfo
 */
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_018, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    MyFlag::agentCardModuleName = "entry";
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("", "test.bundle", "TestAbility", "feature");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection),
        AAFwk::ERR_WRONG_INTERFACE_CALL);
}

/**
 * @tc.name  : ConnectAgentExtensionAbility_019
 * @tc.number: ConnectAgentExtensionAbility_019
 * @tc.desc  : Test ConnectAgentExtensionAbility rejects want bundle mismatch with card appInfo
 */
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_019, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("other.bundle", "TestAbility");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection),
        AAFwk::ERR_WRONG_INTERFACE_CALL);
}

/**
 * @tc.name  : ConnectAgentExtensionAbility_020
 * @tc.number: ConnectAgentExtensionAbility_020
 * @tc.desc  : Test ConnectAgentExtensionAbility rejects card without appInfo
 */
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_020, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    MyFlag::shouldCreateAgentCardAppInfo = false;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection),
        AAFwk::ERR_WRONG_INTERFACE_CALL);
}

/**
* @tc.name  : ConnectAgentExtensionAbility_010
* @tc.number: ConnectAgentExtensionAbility_010
* @tc.desc  : Test ConnectAgentExtensionAbility when extension ability type is not AGENT
*/
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_010, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::extensionAbilityType = AppExecFwk::ExtensionAbilityType::SERVICE;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection),
        AAFwk::ERR_WRONG_INTERFACE_CALL);
    MyFlag::extensionAbilityType = AppExecFwk::ExtensionAbilityType::AGENT;
}

/**
* @tc.name  : DisconnectAgentExtensionAbility_000
* @tc.number: DisconnectAgentExtensionAbility_000
* @tc.desc  : Test DisconnectAgentExtensionAbility when caller is not allowed to use system API
*/
HWTEST_F(AgentManagerServiceTest, DisconnectAgentExtensionAbility_000, TestSize.Level1)
{
    MyFlag::retJudgeCallerIsAllowedToUseSystemAPI = false;
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->DisconnectAgentExtensionAbility(connection), ERR_NOT_SYSTEM_APP);
}

/**
* @tc.name  : DisconnectAgentExtensionAbility_001
* @tc.number: DisconnectAgentExtensionAbility_001
* @tc.desc  : Test DisconnectAgentExtensionAbility when permission verification fails
*/
HWTEST_F(AgentManagerServiceTest, DisconnectAgentExtensionAbility_001, TestSize.Level1)
{
    MyFlag::retVerifyConnectAgentPermission = false;
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->DisconnectAgentExtensionAbility(connection),
        ERR_PERMISSION_DENIED);
    MyFlag::retVerifyConnectAgentPermission = true;
}

/**
* @tc.name  : DisconnectAgentExtensionAbility_002
* @tc.number: DisconnectAgentExtensionAbility_002
* @tc.desc  : Test DisconnectAgentExtensionAbility when connection is null
*/
HWTEST_F(AgentManagerServiceTest, DisconnectAgentExtensionAbility_002, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    sptr<AAFwk::IAbilityConnection> connection = nullptr;
    EXPECT_EQ(AgentManagerService::GetInstance()->DisconnectAgentExtensionAbility(connection),
        ERR_INVALID_VALUE);
}

/**
* @tc.name  : DisconnectAgentExtensionAbility_003
* @tc.number: DisconnectAgentExtensionAbility_003
* @tc.desc  : Test DisconnectAgentExtensionAbility success case
*/
HWTEST_F(AgentManagerServiceTest, DisconnectAgentExtensionAbility_003, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    MyFlag::retDisconnectAbility = ERR_OK;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_OK);
    EXPECT_EQ(AgentManagerService::GetInstance()->DisconnectAgentExtensionAbility(connection), ERR_OK);
}

/**
* @tc.name  : DisconnectAgentExtensionAbility_004
* @tc.number: DisconnectAgentExtensionAbility_004
* @tc.desc  : Test DisconnectAgentExtensionAbility when DisconnectAbility fails
*/
HWTEST_F(AgentManagerServiceTest, DisconnectAgentExtensionAbility_004, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    MyFlag::retDisconnectAbility = ERR_INVALID_VALUE;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");
    sptr<MockAbilityConnection> connection = new MockAbilityConnection();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_OK);
    EXPECT_EQ(AgentManagerService::GetInstance()->DisconnectAgentExtensionAbility(connection),
        ERR_INVALID_VALUE);
    MyFlag::retDisconnectAbility = ERR_OK;
}

/**
* @tc.name  : ConnectAgentExtensionAbility_011
* @tc.number: ConnectAgentExtensionAbility_011
* @tc.desc  : Test ConnectAgentExtensionAbility enforces max connections per caller on the service side
*/
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_011, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");

    std::vector<sptr<MockAbilityConnection>> connections;
    for (size_t i = 0; i < AgentManagerService::MAX_CONNECTIONS_PER_CALLER; i++) {
        auto connection = sptr<MockAbilityConnection>::MakeSptr();
        connections.emplace_back(connection);
        EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_OK);
    }

    auto overflowConnection = sptr<MockAbilityConnection>::MakeSptr();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, overflowConnection),
        ERR_MAX_AGENT_CONNECTIONS_REACHED);
}

/**
* @tc.name  : ConnectAgentExtensionAbility_012
* @tc.number: ConnectAgentExtensionAbility_012
* @tc.desc  : Test ConnectAgentExtensionAbility rollback on connect failure callback
*/
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_012, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");
    auto connection = sptr<MockAbilityConnection>::MakeSptr();

    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_OK);
    ASSERT_NE(MyFlag::lastConnectAbilityConnection, nullptr);
    ASSERT_EQ(AgentManagerService::GetInstance()->callerConnectionCounts_.size(), 1);
    EXPECT_EQ(AgentManagerService::GetInstance()->callerConnectionCounts_.begin()->second, 1);

    AppExecFwk::ElementName element;
    MyFlag::lastConnectAbilityConnection->OnAbilityConnectDone(element, nullptr, ERR_INVALID_VALUE);
    EXPECT_TRUE(AgentManagerService::GetInstance()->trackedConnections_.empty());
    EXPECT_TRUE(AgentManagerService::GetInstance()->callerConnectionCounts_.empty());
}

/**
* @tc.name  : DisconnectAgentExtensionAbility_005
* @tc.number: DisconnectAgentExtensionAbility_005
* @tc.desc  : Test DisconnectAgentExtensionAbility uses service wrapper and releases count before callback
*/
HWTEST_F(AgentManagerServiceTest, DisconnectAgentExtensionAbility_005, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    MyFlag::retDisconnectAbility = ERR_OK;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");
    auto connection = sptr<MockAbilityConnection>::MakeSptr();

    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_OK);
    ASSERT_NE(MyFlag::lastConnectAbilityConnection, nullptr);
    EXPECT_NE(MyFlag::lastConnectAbilityConnection->AsObject(), connection->AsObject());

    EXPECT_EQ(AgentManagerService::GetInstance()->DisconnectAgentExtensionAbility(connection), ERR_OK);
    EXPECT_EQ(MyFlag::lastDisconnectAbilityConnection, MyFlag::lastConnectAbilityConnection);
    EXPECT_TRUE(AgentManagerService::GetInstance()->callerConnectionCounts_.empty());
    ASSERT_EQ(AgentManagerService::GetInstance()->trackedConnections_.size(), 1);

    AppExecFwk::ElementName element;
    MyFlag::lastConnectAbilityConnection->OnAbilityDisconnectDone(element, ERR_OK);
    EXPECT_TRUE(AgentManagerService::GetInstance()->trackedConnections_.empty());
    EXPECT_TRUE(AgentManagerService::GetInstance()->callerConnectionCounts_.empty());
}

/**
* @tc.name  : DisconnectAgentExtensionAbility_007
* @tc.number: DisconnectAgentExtensionAbility_007
* @tc.desc  : Test DisconnectAgentExtensionAbility restores count when disconnect request fails immediately
*/
HWTEST_F(AgentManagerServiceTest, DisconnectAgentExtensionAbility_007, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    MyFlag::retDisconnectAbility = ERR_INVALID_VALUE;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");
    auto connection = sptr<MockAbilityConnection>::MakeSptr();

    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_OK);
    EXPECT_EQ(AgentManagerService::GetInstance()->DisconnectAgentExtensionAbility(connection), ERR_INVALID_VALUE);
    ASSERT_EQ(AgentManagerService::GetInstance()->callerConnectionCounts_.size(), 1);
    EXPECT_EQ(AgentManagerService::GetInstance()->callerConnectionCounts_.begin()->second, 1);
    ASSERT_EQ(AgentManagerService::GetInstance()->trackedConnections_.size(), 1);
    EXPECT_FALSE(AgentManagerService::GetInstance()->trackedConnections_.begin()->second.isDisconnecting);
    MyFlag::retDisconnectAbility = ERR_OK;
}

/**
* @tc.name  : DisconnectAgentExtensionAbility_008
* @tc.number: DisconnectAgentExtensionAbility_008
* @tc.desc  : Test DisconnectAgentExtensionAbility frees quota for immediate reconnect
*/
HWTEST_F(AgentManagerServiceTest, DisconnectAgentExtensionAbility_008, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    MyFlag::retDisconnectAbility = ERR_OK;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");

    std::vector<sptr<MockAbilityConnection>> connections;
    for (size_t i = 0; i < AgentManagerService::MAX_CONNECTIONS_PER_CALLER; i++) {
        auto connection = sptr<MockAbilityConnection>::MakeSptr();
        connections.emplace_back(connection);
        EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_OK);
    }

    EXPECT_EQ(AgentManagerService::GetInstance()->DisconnectAgentExtensionAbility(connections[0]), ERR_OK);
    auto newConnection = sptr<MockAbilityConnection>::MakeSptr();
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, newConnection), ERR_OK);
}

/**
* @tc.name  : DisconnectAgentExtensionAbility_009
* @tc.number: DisconnectAgentExtensionAbility_009
* @tc.desc  : Test DisconnectAgentExtensionAbility is idempotent while the connection is disconnecting
*/
HWTEST_F(AgentManagerServiceTest, DisconnectAgentExtensionAbility_009, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    MyFlag::retDisconnectAbility = ERR_OK;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");
    auto connection = sptr<MockAbilityConnection>::MakeSptr();

    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_OK);
    EXPECT_EQ(AgentManagerService::GetInstance()->DisconnectAgentExtensionAbility(connection), ERR_OK);
    EXPECT_EQ(AgentManagerService::GetInstance()->DisconnectAgentExtensionAbility(connection), ERR_OK);
    ASSERT_EQ(AgentManagerService::GetInstance()->trackedConnections_.size(), 1);
    EXPECT_TRUE(AgentManagerService::GetInstance()->trackedConnections_.begin()->second.isDisconnecting);
}

/**
* @tc.name  : ConnectAgentExtensionAbility_013
* @tc.number: ConnectAgentExtensionAbility_013
* @tc.desc  : Test ConnectAgentExtensionAbility rejects duplicate tracked connection registration
*/
HWTEST_F(AgentManagerServiceTest, ConnectAgentExtensionAbility_013, TestSize.Level1)
{
    MyFlag::retVerifyCallingPermission = true;
    MyFlag::retQueryExtensionAbilityInfos = true;
    MyFlag::retGetProcessRunningInfoByPid = ERR_OK;
    MyFlag::processState = AppExecFwk::AppProcessState::APP_STATE_FOREGROUND;
    MyFlag::retGetAgentCardByAgentId = ERR_OK;
    MyFlag::retConnectAbilityWithExtensionType = ERR_OK;
    AAFwk::Want want;
    want.SetParam(AGENTID_KEY, std::string("testAgent"));
    want.SetBundle("test.bundle");
    want.SetElementName("test.bundle", "TestAbility");
    auto connection = sptr<MockAbilityConnection>::MakeSptr();

    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_OK);
    EXPECT_EQ(AgentManagerService::GetInstance()->ConnectAgentExtensionAbility(want, connection), ERR_INVALID_VALUE);
}

/**
* @tc.name  : DisconnectAgentExtensionAbility_006
* @tc.number: DisconnectAgentExtensionAbility_006
* @tc.desc  : Test DisconnectAgentExtensionAbility rejects untracked connection
*/
HWTEST_F(AgentManagerServiceTest, DisconnectAgentExtensionAbility_006, TestSize.Level1)
{
    auto connection = sptr<MockAbilityConnection>::MakeSptr();
    EXPECT_EQ(AgentManagerService::GetInstance()->DisconnectAgentExtensionAbility(connection), ERR_INVALID_VALUE);
}

/**
* @tc.name  : ReleaseTrackedConnection_001
* @tc.number: ReleaseTrackedConnection_001
* @tc.desc  : Test ReleaseTrackedConnection erases tracking even when caller count entry is absent
*/
HWTEST_F(AgentManagerServiceTest, ReleaseTrackedConnection_001, TestSize.Level1)
{
    auto connection = sptr<MockAbilityConnection>::MakeSptr();
    AgentManagerService::TrackedConnectionRecord record;
    record.callerUid = 100;
    AgentManagerService::GetInstance()->trackedConnections_.emplace(connection->AsObject(), record);

    AgentManagerService::GetInstance()->ReleaseTrackedConnection(connection);
    EXPECT_TRUE(AgentManagerService::GetInstance()->trackedConnections_.empty());
    EXPECT_TRUE(AgentManagerService::GetInstance()->callerConnectionCounts_.empty());
}

/**
* @tc.name  : ReleaseTrackedConnection_002
* @tc.number: ReleaseTrackedConnection_002
* @tc.desc  : Test ReleaseTrackedConnection decrements caller count when multiple connections remain
*/
HWTEST_F(AgentManagerServiceTest, ReleaseTrackedConnection_002, TestSize.Level1)
{
    auto connection = sptr<MockAbilityConnection>::MakeSptr();
    AgentManagerService::TrackedConnectionRecord record;
    record.callerUid = 100;
    AgentManagerService::GetInstance()->trackedConnections_.emplace(connection->AsObject(), record);
    AgentManagerService::GetInstance()->callerConnectionCounts_[100] = 2;

    AgentManagerService::GetInstance()->ReleaseTrackedConnection(connection);
    EXPECT_TRUE(AgentManagerService::GetInstance()->trackedConnections_.empty());
    ASSERT_EQ(AgentManagerService::GetInstance()->callerConnectionCounts_.size(), 1);
    EXPECT_EQ(AgentManagerService::GetInstance()->callerConnectionCounts_[100], 1);
}

/**
* @tc.name  : ReleaseCallerConnectionCountLocked_001
* @tc.number: ReleaseCallerConnectionCountLocked_001
* @tc.desc  : Test ReleaseCallerConnectionCountLocked returns false for unknown connection
*/
HWTEST_F(AgentManagerServiceTest, ReleaseCallerConnectionCountLocked_001, TestSize.Level1)
{
    auto callerRemote = sptr<IRemoteObject>(new (std::nothrow) IPCObjectStub(u"unknown.remote"));
    EXPECT_FALSE(AgentManagerService::GetInstance()->ReleaseCallerConnectionCountLocked(callerRemote));
}

/**
* @tc.name  : ReleaseCallerConnectionCountLocked_002
* @tc.number: ReleaseCallerConnectionCountLocked_002
* @tc.desc  : Test ReleaseCallerConnectionCountLocked returns false when caller count entry is missing
*/
HWTEST_F(AgentManagerServiceTest, ReleaseCallerConnectionCountLocked_002, TestSize.Level1)
{
    auto connection = sptr<MockAbilityConnection>::MakeSptr();
    AgentManagerService::TrackedConnectionRecord record;
    record.callerUid = 100;
    record.callerRemote = connection->AsObject();
    AgentManagerService::GetInstance()->trackedConnections_.emplace(connection->AsObject(), record);

    EXPECT_FALSE(AgentManagerService::GetInstance()->ReleaseCallerConnectionCountLocked(connection->AsObject()));
}

/**
* @tc.name  : ReleaseCallerConnectionCountLocked_003
* @tc.number: ReleaseCallerConnectionCountLocked_003
* @tc.desc  : Test ReleaseCallerConnectionCountLocked decrements remaining count
*/
HWTEST_F(AgentManagerServiceTest, ReleaseCallerConnectionCountLocked_003, TestSize.Level1)
{
    auto connection = sptr<MockAbilityConnection>::MakeSptr();
    AgentManagerService::TrackedConnectionRecord record;
    record.callerUid = 100;
    record.callerRemote = connection->AsObject();
    AgentManagerService::GetInstance()->trackedConnections_.emplace(connection->AsObject(), record);
    AgentManagerService::GetInstance()->callerConnectionCounts_[100] = 2;

    EXPECT_TRUE(AgentManagerService::GetInstance()->ReleaseCallerConnectionCountLocked(connection->AsObject()));
    ASSERT_EQ(AgentManagerService::GetInstance()->callerConnectionCounts_.size(), 1);
    EXPECT_EQ(AgentManagerService::GetInstance()->callerConnectionCounts_[100], 1);
}

/**
* @tc.name  : ReleaseCallerConnectionCountLocked_004
* @tc.number: ReleaseCallerConnectionCountLocked_004
* @tc.desc  : Test ReleaseCallerConnectionCountLocked erases the last caller count entry
*/
HWTEST_F(AgentManagerServiceTest, ReleaseCallerConnectionCountLocked_004, TestSize.Level1)
{
    auto connection = sptr<MockAbilityConnection>::MakeSptr();
    AgentManagerService::TrackedConnectionRecord record;
    record.callerUid = 100;
    record.callerRemote = connection->AsObject();
    AgentManagerService::GetInstance()->trackedConnections_.emplace(connection->AsObject(), record);
    AgentManagerService::GetInstance()->callerConnectionCounts_[100] = 1;

    EXPECT_TRUE(AgentManagerService::GetInstance()->ReleaseCallerConnectionCountLocked(connection->AsObject()));
    EXPECT_TRUE(AgentManagerService::GetInstance()->callerConnectionCounts_.empty());
}

/**
* @tc.name  : ReleaseTrackedConnection_003
* @tc.number: ReleaseTrackedConnection_003
* @tc.desc  : Test ReleaseTrackedConnection ignores null connection
*/
HWTEST_F(AgentManagerServiceTest, ReleaseTrackedConnection_003, TestSize.Level1)
{
    sptr<AAFwk::IAbilityConnection> connection = nullptr;
    AgentManagerService::GetInstance()->callerConnectionCounts_[100] = 1;

    AgentManagerService::GetInstance()->ReleaseTrackedConnection(connection);

    ASSERT_EQ(AgentManagerService::GetInstance()->callerConnectionCounts_.size(), 1);
    EXPECT_EQ(AgentManagerService::GetInstance()->callerConnectionCounts_[100], 1);
}

/**
* @tc.name  : ReleaseTrackedConnection_004
* @tc.number: ReleaseTrackedConnection_004
* @tc.desc  : Test ReleaseTrackedConnection ignores untracked connection
*/
HWTEST_F(AgentManagerServiceTest, ReleaseTrackedConnection_004, TestSize.Level1)
{
    auto connection = sptr<MockAbilityConnection>::MakeSptr();
    AgentManagerService::GetInstance()->callerConnectionCounts_[100] = 1;

    AgentManagerService::GetInstance()->ReleaseTrackedConnection(connection);

    ASSERT_EQ(AgentManagerService::GetInstance()->callerConnectionCounts_.size(), 1);
    EXPECT_EQ(AgentManagerService::GetInstance()->callerConnectionCounts_[100], 1);
}

/**
* @tc.name  : HandleCallerConnectionDied_001
* @tc.number: HandleCallerConnectionDied_001
* @tc.desc  : Test HandleCallerConnectionDied ignores null remote object
*/
HWTEST_F(AgentManagerServiceTest, HandleCallerConnectionDied_001, TestSize.Level1)
{
    wptr<IRemoteObject> remote;
    AgentManagerService::GetInstance()->HandleCallerConnectionDied(remote);
    EXPECT_EQ(MyFlag::lastDisconnectAbilityConnection, nullptr);
}

/**
* @tc.name  : HandleCallerConnectionDied_002
* @tc.number: HandleCallerConnectionDied_002
* @tc.desc  : Test HandleCallerConnectionDied ignores unknown remote object
*/
HWTEST_F(AgentManagerServiceTest, HandleCallerConnectionDied_002, TestSize.Level1)
{
    sptr<IRemoteObject> remoteObject = new (std::nothrow) IPCObjectStub(u"test.remote");
    AgentManagerService::GetInstance()->HandleCallerConnectionDied(wptr<IRemoteObject>(remoteObject));
    EXPECT_EQ(MyFlag::lastDisconnectAbilityConnection, nullptr);
}

/**
* @tc.name  : HandleCallerConnectionDied_003
* @tc.number: HandleCallerConnectionDied_003
* @tc.desc  : Test HandleCallerConnectionDied releases tracking when DisconnectAbility fails
*/
HWTEST_F(AgentManagerServiceTest, HandleCallerConnectionDied_003, TestSize.Level1)
{
    MyFlag::retDisconnectAbility = ERR_INVALID_VALUE;
    auto callerConnection = sptr<MockAbilityConnection>::MakeSptr();
    auto serviceConnection = sptr<MockAbilityConnection>::MakeSptr();
    auto callerRemote = callerConnection->AsObject();
    AgentManagerService::TrackedConnectionRecord record;
    record.callerUid = 100;
    record.serviceConnection = serviceConnection;
    record.callerRemote = callerRemote;
    AgentManagerService::GetInstance()->trackedConnections_.emplace(callerRemote, record);
    AgentManagerService::GetInstance()->callerConnectionCounts_[100] = 1;

    AgentManagerService::GetInstance()->HandleCallerConnectionDied(wptr<IRemoteObject>(callerRemote));
    EXPECT_EQ(MyFlag::lastDisconnectAbilityConnection->AsObject(), serviceConnection->AsObject());
    EXPECT_TRUE(AgentManagerService::GetInstance()->trackedConnections_.empty());
    EXPECT_TRUE(AgentManagerService::GetInstance()->callerConnectionCounts_.empty());
    MyFlag::retDisconnectAbility = ERR_OK;
}

/**
* @tc.name  : HandleCallerConnectionDied_004
* @tc.number: HandleCallerConnectionDied_004
* @tc.desc  : Test HandleCallerConnectionDied releases tracking even when no service connection is stored
*/
HWTEST_F(AgentManagerServiceTest, HandleCallerConnectionDied_004, TestSize.Level1)
{
    auto callerConnection = sptr<MockAbilityConnection>::MakeSptr();
    auto callerRemote = callerConnection->AsObject();
    AgentManagerService::TrackedConnectionRecord record;
    record.callerUid = 100;
    record.callerRemote = callerRemote;
    AgentManagerService::GetInstance()->trackedConnections_.emplace(callerRemote, record);
    AgentManagerService::GetInstance()->callerConnectionCounts_[100] = 1;

    AgentManagerService::GetInstance()->HandleCallerConnectionDied(wptr<IRemoteObject>(callerRemote));

    EXPECT_EQ(MyFlag::lastDisconnectAbilityConnection, nullptr);
    EXPECT_TRUE(AgentManagerService::GetInstance()->trackedConnections_.empty());
    EXPECT_TRUE(AgentManagerService::GetInstance()->callerConnectionCounts_.empty());
}

/**
* @tc.name  : HandleConnectionDone_001
* @tc.number: HandleConnectionDone_001
* @tc.desc  : Test HandleConnectionDone keeps tracking on successful connect callback
*/
HWTEST_F(AgentManagerServiceTest, HandleConnectionDone_001, TestSize.Level1)
{
    auto connection = sptr<MockAbilityConnection>::MakeSptr();
    AgentManagerService::TrackedConnectionRecord record;
    record.callerUid = 100;
    AgentManagerService::GetInstance()->trackedConnections_.emplace(connection->AsObject(), record);
    AgentManagerService::GetInstance()->callerConnectionCounts_[100] = 1;

    AgentManagerService::GetInstance()->HandleConnectionDone(connection, ERR_OK, false);

    ASSERT_EQ(AgentManagerService::GetInstance()->trackedConnections_.size(), 1);
    ASSERT_EQ(AgentManagerService::GetInstance()->callerConnectionCounts_.size(), 1);
    EXPECT_EQ(AgentManagerService::GetInstance()->callerConnectionCounts_[100], 1);
}

/**
* @tc.name  : HandleConnectionDone_002
* @tc.number: HandleConnectionDone_002
* @tc.desc  : Test HandleConnectionDone releases tracking on disconnect callback
*/
HWTEST_F(AgentManagerServiceTest, HandleConnectionDone_002, TestSize.Level1)
{
    auto connection = sptr<MockAbilityConnection>::MakeSptr();
    AgentManagerService::TrackedConnectionRecord record;
    record.callerUid = 100;
    AgentManagerService::GetInstance()->trackedConnections_.emplace(connection->AsObject(), record);
    AgentManagerService::GetInstance()->callerConnectionCounts_[100] = 1;

    AgentManagerService::GetInstance()->HandleConnectionDone(connection, ERR_OK, true);

    EXPECT_TRUE(AgentManagerService::GetInstance()->trackedConnections_.empty());
    EXPECT_TRUE(AgentManagerService::GetInstance()->callerConnectionCounts_.empty());
}
} // namespace AgentRuntime
} // namespace OHOS
