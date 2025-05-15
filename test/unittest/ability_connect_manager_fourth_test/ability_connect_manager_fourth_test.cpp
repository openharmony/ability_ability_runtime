/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <memory>

#define private public
#define protected public
#include "ability_connect_manager.h"
#undef private
#undef protected

#include "ability_config.h"
#include "ability_manager_errors.h"
#include "ability_scheduler.h"
#include "ability_util.h"
#include "bundlemgr/mock_bundle_manager.h"
#include "hilog_tag_wrapper.h"
#include "mock_ability_connect_callback.h"
#include "mock_sa_call.h"
#include "mock_task_handler_wrap.h"
#include "sa_mgr_client.h"
#include "system_ability_definition.h"
#include "session/host/include/session.h"
#include <thread>
#include <chrono>

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using testing::_;
using testing::Invoke;
using testing::Return;
using testing::SetArgReferee;
using ::testing::DoAll;

namespace {
const std::string PARAM_RESV_CALLER_APP_ID("ohos.aafwk.param.callerAppId");
}

namespace OHOS {
namespace AAFwk {
class AbilityConnectManagerFourthTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    AbilityConnectManager* ConnectManager() const;
    std::shared_ptr<MockTaskHandlerWrap> TaskHandler() const;
    std::shared_ptr<EventHandlerWrap> EventHandler() const;

    AbilityRequest GenerateAbilityRequest(const std::string& deviceName, const std::string& abilityName,
        const std::string& appName, const std::string& bundleName, const std::string& moduleName);

    sptr<SessionInfo> MockSessionInfo(int32_t persistentId);
    std::shared_ptr<AbilityRecord> InitAbilityRecord();
    std::shared_ptr<MockTaskHandlerWrap> taskHandler_;
protected:
    AbilityRequest abilityRequest_{};
    AbilityRequest abilityRequest1_{};
    AbilityRequest abilityRequest2_{};
    std::shared_ptr<AbilityRecord> serviceRecord_{ nullptr };
    std::shared_ptr<AbilityRecord> serviceRecord1_{ nullptr };
    std::shared_ptr<AbilityRecord> serviceRecord2_{ nullptr };
    OHOS::sptr<Token> serviceToken_{ nullptr };
    OHOS::sptr<Token> serviceToken1_{ nullptr };
    OHOS::sptr<Token> serviceToken2_{ nullptr };
    OHOS::sptr<IAbilityConnection> callbackA_{ nullptr };
    OHOS::sptr<IAbilityConnection> callbackB_{ nullptr };

private:
    std::shared_ptr<AbilityConnectManager> connectManager_;
    std::shared_ptr<EventHandlerWrap> eventHandler_;
};

AbilityRequest AbilityConnectManagerFourthTest::GenerateAbilityRequest(const std::string& deviceName,
    const std::string& abilityName, const std::string& appName, const std::string& bundleName,
    const std::string& moduleName)
{
    ElementName element(deviceName, bundleName, abilityName, moduleName);
    Want want;
    want.SetElement(element);

    AbilityInfo abilityInfo;
    abilityInfo.visible = true;
    abilityInfo.applicationName = appName;
    abilityInfo.type = AbilityType::SERVICE;
    abilityInfo.name = abilityName;
    abilityInfo.bundleName = bundleName;
    abilityInfo.moduleName = moduleName;
    abilityInfo.deviceId = deviceName;
    ApplicationInfo appinfo;
    appinfo.name = appName;
    abilityInfo.applicationInfo = appinfo;
    AbilityRequest abilityRequest;
    abilityRequest.want = want;
    abilityRequest.abilityInfo = abilityInfo;
    abilityRequest.appInfo = appinfo;
    abilityInfo.process = bundleName;

    return abilityRequest;
}

sptr<SessionInfo> AbilityConnectManagerFourthTest::MockSessionInfo(int32_t persistentId)
{
    sptr<SessionInfo> sessionInfo = new (std::nothrow) SessionInfo();
    if (!sessionInfo) {
        TAG_LOGE(AAFwkTag::TEST, "sessionInfo is nullptr");
        return nullptr;
    }
    sessionInfo->persistentId = persistentId;
    return sessionInfo;
}

std::shared_ptr<AbilityRecord> AbilityConnectManagerFourthTest::InitAbilityRecord()
{
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    return abilityRecord;
}

void AbilityConnectManagerFourthTest::SetUpTestCase(void)
{}

void AbilityConnectManagerFourthTest::TearDownTestCase(void)
{}

void AbilityConnectManagerFourthTest::SetUp(void)
{
    connectManager_ = std::make_unique<AbilityConnectManager>(0);
    taskHandler_ = MockTaskHandlerWrap::CreateQueueHandler("AbilityConnectManagerFourthTest");
    eventHandler_ = std::make_shared<EventHandlerWrap>(taskHandler_);
    // generate ability request
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest_ = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    serviceRecord_ = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    serviceToken_ = serviceRecord_->GetToken();
    std::string deviceName1 = "device";
    std::string abilityName1 = "musicServiceAbility";
    std::string appName1 = "musicservcie";
    std::string bundleName1 = "com.ix.musicservcie";
    std::string moduleName1 = "entry";
    abilityRequest1_ = GenerateAbilityRequest(deviceName1, abilityName1, appName1, bundleName1, moduleName1);
    serviceRecord1_ = AbilityRecord::CreateAbilityRecord(abilityRequest1_);
    std::string deviceName2 = "device";
    std::string abilityName2 = "residentServiceAbility";
    std::string appName2 = "residentservcie";
    std::string bundleName2 = "com.ix.residentservcie";
    std::string moduleName2 = "entry";
    abilityRequest2_ = GenerateAbilityRequest(deviceName2, abilityName2, appName2, bundleName2, moduleName2);
    serviceRecord2_ = AbilityRecord::CreateAbilityRecord(abilityRequest2_);
    serviceToken2_ = serviceRecord_->GetToken();
    serviceToken1_ = serviceRecord_->GetToken();
    callbackA_ = new AbilityConnectCallback();
    callbackB_ = new AbilityConnectCallback();
}

void AbilityConnectManagerFourthTest::TearDown(void)
{
    // reset the callback count
    AbilityConnectCallback::onAbilityConnectDoneCount = 0;
    AbilityConnectCallback::onAbilityDisconnectDoneCount = 0;
    serviceRecord_ = nullptr;
}

AbilityConnectManager* AbilityConnectManagerFourthTest::ConnectManager() const
{
    return connectManager_.get();
}

std::shared_ptr<MockTaskHandlerWrap> AbilityConnectManagerFourthTest::TaskHandler() const
{
    return taskHandler_;
}

std::shared_ptr<EventHandlerWrap> AbilityConnectManagerFourthTest::EventHandler() const
{
    return eventHandler_;
}

/*
 * Feature: AbilityConnectManager
 * Function: DispatchForeground
 */
HWTEST_F(AbilityConnectManagerFourthTest, DispatchForeground_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DispatchForeground_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    EXPECT_NE(abilityRecord, nullptr);
    taskHandler_ = MockTaskHandlerWrap::CreateQueueHandler("AbilityConnectManagerFourthTest");
    connectManager->taskHandler_ = taskHandler_;
    int result = connectManager->DispatchForeground(abilityRecord);

    EXPECT_EQ(result, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "DispatchForeground_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: NeedExtensionControl
 */
HWTEST_F(AbilityConnectManagerFourthTest, NeedExtensionControl_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "NeedExtensionControl_003 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI;
    abilityRecord->customProcessFlag_ = "true";
    abilityRecord->extensionProcessMode_ = 0;
    ASSERT_NE(abilityRecord, nullptr);

    bool result = connectManager->NeedExtensionControl(abilityRecord);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "NeedExtensionControl_003 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: NeedExtensionControl
 */
HWTEST_F(AbilityConnectManagerFourthTest, NeedExtensionControl_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "NeedExtensionControl_004 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI;
    abilityRecord->customProcessFlag_ = "true";
    abilityRecord->extensionProcessMode_ = 1;
    ASSERT_NE(abilityRecord, nullptr);

    bool result = connectManager->NeedExtensionControl(abilityRecord);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "NeedExtensionControl_004 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: TerminateRecord
 */
HWTEST_F(AbilityConnectManagerFourthTest, TerminateRecord_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "TerminateRecord_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    ASSERT_NE(abilityRecord, nullptr);
    abilityRecord->recordId_ = 1;
    EXPECT_EQ(connectManager->GetExtensionByIdFromServiceMap(abilityRecord->GetRecordId()), nullptr);

    connectManager->AddToServiceMap("testKey", abilityRecord);
    connectManager->TerminateRecord(abilityRecord);
    EXPECT_NE(connectManager->GetExtensionByIdFromTerminatingMap(abilityRecord->GetRecordId()), nullptr);
    TAG_LOGI(AAFwkTag::TEST, "TerminateRecord_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetExtensionByTokenFromTerminatingMap
 */
HWTEST_F(AbilityConnectManagerFourthTest, GetExtensionByTokenFromTerminatingMap_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionByTokenFromTerminatingMap_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    OHOS::sptr<OHOS::IRemoteObject> nullToken = nullptr;
    auto result = connectManager->GetExtensionByTokenFromTerminatingMap(nullToken);
    EXPECT_EQ(result, nullptr);
    connectManager->terminatingExtensionList_.clear();
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionByTokenFromTerminatingMap_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetExtensionByTokenFromTerminatingMap
 */
HWTEST_F(AbilityConnectManagerFourthTest, GetExtensionByTokenFromTerminatingMap_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionByTokenFromTerminatingMap_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::PAGE;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SHARE;
    std::shared_ptr<AbilityRecord> validRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    OHOS::sptr<OHOS::IRemoteObject> validToken = new OHOS::AAFwk::Token(validRecord);
    auto result = connectManager->GetExtensionByTokenFromTerminatingMap(validToken);
    EXPECT_EQ(result, nullptr);
    connectManager->terminatingExtensionList_.clear();
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionByTokenFromTerminatingMap_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: DispatchInactive
 */
HWTEST_F(AbilityConnectManagerFourthTest, DispatchInactive_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DispatchInactive_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    const std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    abilityRecord->currentState_ = AbilityState::INACTIVATING;
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SERVICE;
    EXPECT_NE(abilityRecord, nullptr);
    taskHandler_ = MockTaskHandlerWrap::CreateQueueHandler("AbilityConnectManagerFourthTest");
    std::shared_ptr<EventHandlerWrap> eventHandler1_ = std::make_shared<EventHandlerWrap>(taskHandler_);
    EXPECT_NE(eventHandler1_, nullptr);
    connectManager->eventHandler_ = eventHandler1_;

    connectManager->DispatchInactive(abilityRecord, 0);
    EXPECT_EQ(abilityRecord->GetAbilityState(), AbilityState::INACTIVE);
    TAG_LOGI(AAFwkTag::TEST, "DispatchInactive_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: DispatchInactive
 */
HWTEST_F(AbilityConnectManagerFourthTest, DispatchInactive_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DispatchInactive_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    abilityRecord->currentState_ = AbilityState::INACTIVATING;
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SERVICE;
    EXPECT_NE(abilityRecord, nullptr);
    abilityRecord->SetCreateByConnectMode(false);
    auto taskHandler1_ = MockTaskHandlerWrap::CreateQueueHandler("AbilityConnectManagerFourthTest");
    std::shared_ptr<EventHandlerWrap> eventHandler1_ = std::make_shared<EventHandlerWrap>(taskHandler_);
    EXPECT_NE(eventHandler1_, nullptr);
    connectManager->eventHandler_ = eventHandler1_;
    Want want;
    want.SetParam("ability.want.params.is_preload_uiextension_ability", false);
    abilityRecord->SetWant(want);
    connectManager->uiExtensionAbilityRecordMgr_= nullptr;

    int result = connectManager->DispatchInactive(abilityRecord, AbilityState::INACTIVATING);
    EXPECT_EQ(result, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "DispatchInactive_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: DispatchInactive
 */
HWTEST_F(AbilityConnectManagerFourthTest, DispatchInactive_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DispatchInactive_003 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    abilityRecord->currentState_ = AbilityState::INACTIVATING;
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SERVICE;
    abilityRecord->SetUIExtensionAbilityId(1);
    EXPECT_NE(abilityRecord, nullptr);
    abilityRecord->SetCreateByConnectMode(false);
    taskHandler_ = MockTaskHandlerWrap::CreateQueueHandler("AbilityConnectManagerFourthTest");
    std::shared_ptr<EventHandlerWrap> eventHandler1_ = std::make_shared<EventHandlerWrap>(taskHandler_);
    EXPECT_NE(eventHandler1_, nullptr);
    connectManager->eventHandler_ = eventHandler1_;
    Want want;
    want.SetParam("ability.want.params.is_preload_uiextension_ability", false);
    abilityRecord->SetWant(want);

    int result = connectManager->DispatchInactive(abilityRecord, AbilityState::INACTIVATING);
    EXPECT_EQ(result, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "DispatchInactive_003 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: DispatchInactive
 */
HWTEST_F(AbilityConnectManagerFourthTest, DispatchInactive_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DispatchInactive_004 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    abilityRecord->currentState_ = AbilityState::INACTIVATING;
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SERVICE;
    abilityRecord->SetUIExtensionAbilityId(1);

    EXPECT_NE(abilityRecord, nullptr);
    abilityRecord->SetCreateByConnectMode(false);
    auto taskHandler1_ = MockTaskHandlerWrap::CreateQueueHandler("AbilityConnectManagerFourthTest");
    std::shared_ptr<EventHandlerWrap> eventHandler1_ = std::make_shared<EventHandlerWrap>(taskHandler1_);
    EXPECT_NE(eventHandler1_, nullptr);
    connectManager->eventHandler_ = eventHandler1_;
    Want want;
    want.SetParam("ability.want.params.is_preload_uiextension_ability", true);
    abilityRecord->SetWant(want);

    int result = connectManager->DispatchInactive(abilityRecord, 0);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "DispatchInactive_004 end");
}

/*
* Feature: AbilityConnectManager
* Function: HandleUIExtensionDied
*/
HWTEST_F(AbilityConnectManagerFourthTest, HandleUIExtensionDied_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleUIExtensionDied_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    sptr<Token> token = serviceToken_;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> sessionToken = abilityRecord->GetToken();
    connectManager->AddUIExtWindowDeathRecipient(sessionToken);
    connectManager->uiExtensionMap_[sessionToken] = {std::weak_ptr<AbilityRecord>(), nullptr};
    EXPECT_EQ(connectManager->uiExtensionMap_.size(), 1);

    connectManager->HandleUIExtensionDied(abilityRecord);
    EXPECT_EQ(connectManager->uiExtensionMap_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "HandleUIExtensionDied_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: HandleUIExtensionDied
 */
HWTEST_F(AbilityConnectManagerFourthTest, HandleUIExtensionDied_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleUIExtensionDied_003 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    sptr<Token> token = serviceToken_;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> sessionToken = abilityRecord->GetToken();
    connectManager->uiExtensionMap_[sessionToken] = {abilityRecord, nullptr};
    EXPECT_EQ(connectManager->uiExtensionMap_.size(), 1);

    connectManager->HandleUIExtensionDied(abilityRecord);
    EXPECT_EQ(connectManager->uiExtensionMap_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "HandleUIExtensionDied_003 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: HandleUIExtensionDied
 */
HWTEST_F(AbilityConnectManagerFourthTest, HandleUIExtensionDied_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleUIExtensionDied_004 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    sptr<Token> token = serviceToken_;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    std::shared_ptr<AbilityRecord> anotherAbilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest1_);
    ASSERT_NE(anotherAbilityRecord, nullptr);
    sptr<IRemoteObject> sessionToken = abilityRecord->GetToken();
    connectManager->uiExtensionMap_[sessionToken] = {anotherAbilityRecord, nullptr};
    EXPECT_EQ(connectManager->uiExtensionMap_.size(), 1);

    connectManager->HandleUIExtensionDied(abilityRecord);
    EXPECT_EQ(connectManager->uiExtensionMap_.size(), 1);
    TAG_LOGI(AAFwkTag::TEST, "HandleUIExtensionDied_004 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetServiceKey
 */
HWTEST_F(AbilityConnectManagerFourthTest, GetServiceKey_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetServiceKey_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    ASSERT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    abilityRecord->uri_ = "com.example.test";
    abilityRecord->abilityInfo_.bundleName = "com.ohos.formrenderservice";
    Want want;
    want.SetParam("com.ohos.formrenderservice", 0);
    abilityRecord->SetWant(want);

    std::string serviceKey = connectManager->GetServiceKey(abilityRecord);
    EXPECT_EQ(serviceKey, "com.example.test0");
    TAG_LOGI(AAFwkTag::TEST, "GetServiceKey_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetExtensionRunningInfos
 */
HWTEST_F(AbilityConnectManagerFourthTest, GetExtensionRunningInfos_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionRunningInfos_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::vector<ExtensionRunningInfo> info;
    int upperLimit = 2;
    int32_t userId = 0;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    connectManager->AddToServiceMap("testServiceKey1", abilityRecord);
    info.emplace_back();

    connectManager->GetExtensionRunningInfos(upperLimit, info, userId, true);
    EXPECT_EQ(info.size(), upperLimit);
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionRunningInfos_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetExtensionRunningInfos
 */
HWTEST_F(AbilityConnectManagerFourthTest, GetExtensionRunningInfos_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionRunningInfos_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::vector<ExtensionRunningInfo> info;
    int upperLimit = 2;
    int32_t userId = 0;
    connectManager->AddToServiceMap("testServiceKey2", nullptr);

    connectManager->GetExtensionRunningInfos(upperLimit, info, userId, true);
    EXPECT_EQ(info.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionRunningInfos_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetExtensionRunningInfos
 */
HWTEST_F(AbilityConnectManagerFourthTest, GetExtensionRunningInfos_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionRunningInfos_003 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::vector<ExtensionRunningInfo> info;
    int upperLimit = 2;
    int32_t userId = 0;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    connectManager->AddToServiceMap("testServiceKey3", abilityRecord);

    connectManager->GetExtensionRunningInfos(upperLimit, info, userId, true);
    EXPECT_EQ(info.size(), 1);
    TAG_LOGI(AAFwkTag::TEST, "GetExtensionRunningInfos_003 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetAbilityRunningInfos
 */
HWTEST_F(AbilityConnectManagerFourthTest, GetAbilityRunningInfos_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAbilityRunningInfos_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::vector<AbilityRunningInfo> info;
    connectManager->AddToServiceMap("testServiceKey1", nullptr);

    connectManager->GetAbilityRunningInfos(info, true);
    EXPECT_EQ(info.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "GetAbilityRunningInfos_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetAbilityRunningInfos
 */
HWTEST_F(AbilityConnectManagerFourthTest, GetAbilityRunningInfos_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAbilityRunningInfos_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::vector<AbilityRunningInfo> info;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    connectManager->AddToServiceMap("testServiceKey2", abilityRecord);

    connectManager->GetAbilityRunningInfos(info, true);
    EXPECT_GT(info.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "GetAbilityRunningInfos_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetAbilityRunningInfos
 */
HWTEST_F(AbilityConnectManagerFourthTest, GetAbilityRunningInfos_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetAbilityRunningInfos_003 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::vector<AbilityRunningInfo> info;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    abilityRecord->abilityInfo_.applicationInfo.accessTokenId = IPCSkeleton::GetCallingTokenID();
    connectManager->AddToServiceMap("testServiceKey3", abilityRecord);

    connectManager->GetAbilityRunningInfos(info, false);
    EXPECT_GT(info.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "GetAbilityRunningInfos_003 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: IsLauncher
 */
HWTEST_F(AbilityConnectManagerFourthTest, IsLauncher_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsLauncher_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> nullAbilityRecord = nullptr;
    bool result = connectManager->IsLauncher(nullAbilityRecord);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "IsLauncher_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: IsLauncher
 */
HWTEST_F(AbilityConnectManagerFourthTest, IsLauncher_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsLauncher_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    abilityRecord->abilityInfo_.name = "NotLauncher";
    abilityRecord->abilityInfo_.bundleName = "com.ohos.launcher";

    bool result = connectManager->IsLauncher(abilityRecord);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "IsLauncher_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: IsLauncher
 */
HWTEST_F(AbilityConnectManagerFourthTest, IsLauncher_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsLauncher_003 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    abilityRecord->abilityInfo_.name = "com.ohos.launcher.MainAbility";
    abilityRecord->abilityInfo_.bundleName = "NotLauncherBundle";

    bool result = connectManager->IsLauncher(abilityRecord);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "IsLauncher_003 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: IsLauncher
 */
HWTEST_F(AbilityConnectManagerFourthTest, IsLauncher_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsLauncher_004 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    abilityRecord->abilityInfo_.name = "com.ohos.launcher.MainAbility";
    abilityRecord->abilityInfo_.bundleName = "com.ohos.launcher";

    bool result = connectManager->IsLauncher(abilityRecord);
    EXPECT_TRUE(result);
    TAG_LOGI(AAFwkTag::TEST, "IsLauncher_004 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: IsUIExtensionFocused
 */
HWTEST_F(AbilityConnectManagerFourthTest, IsUIExtensionFocused_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsUIExtensionFocused_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    uint32_t uiExtensionTokenId = 1;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> focusToken = abilityRecord->GetToken();
    abilityRecord->abilityInfo_.applicationInfo.accessTokenId = 5;
    connectManager->uiExtensionMap_.clear();
    connectManager->uiExtensionMap_.emplace(focusToken, std::make_pair(abilityRecord, nullptr));

    bool result = connectManager->IsUIExtensionFocused(uiExtensionTokenId, focusToken);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "IsUIExtensionFocused_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: IsUIExtensionFocused
 */
HWTEST_F(AbilityConnectManagerFourthTest, IsUIExtensionFocused_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsUIExtensionFocused_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    uint32_t uiExtensionTokenId = 1;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> focusToken = abilityRecord->GetToken();
    abilityRecord->abilityInfo_.applicationInfo.accessTokenId = uiExtensionTokenId;
    sptr<SessionInfo> sessionInfo = new (std::nothrow) SessionInfo();
    sessionInfo->callerToken = focusToken;
    connectManager->uiExtensionMap_.clear();
    connectManager->uiExtensionMap_.emplace(focusToken, std::make_pair(abilityRecord, sessionInfo));

    bool result = connectManager->IsUIExtensionFocused(uiExtensionTokenId, focusToken);
    EXPECT_TRUE(result);
    TAG_LOGI(AAFwkTag::TEST, "IsUIExtensionFocused_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetUIExtensionSourceToken
 */
HWTEST_F(AbilityConnectManagerFourthTest, GetUIExtensionSourceToken_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    sptr<IRemoteObject> nulltoken = nullptr;
    sptr<IRemoteObject> resultToken = connectManager->GetUIExtensionSourceToken(nulltoken);
    EXPECT_EQ(resultToken, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetUIExtensionSourceToken
 */
HWTEST_F(AbilityConnectManagerFourthTest, GetUIExtensionSourceToken_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    connectManager->uiExtensionMap_.emplace(token, std::make_pair(abilityRecord, nullptr));

    sptr<IRemoteObject> resultToken = connectManager->GetUIExtensionSourceToken(token);
    EXPECT_EQ(resultToken, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetUIExtensionSourceToken
 */
HWTEST_F(AbilityConnectManagerFourthTest, GetUIExtensionSourceToken_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    sptr<SessionInfo> sessionInfo = new SessionInfo();
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    connectManager->uiExtensionMap_.clear();
    connectManager->uiExtensionMap_.emplace(token, std::make_pair(abilityRecord, sessionInfo));

    sptr<IRemoteObject> resultToken = connectManager->GetUIExtensionSourceToken(token);
    EXPECT_EQ(resultToken, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: StopServiceAbilityLocked
 */
HWTEST_F(AbilityConnectManagerFourthTest, StopServiceAbilityLocked_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "StopServiceAbilityLocked_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.deviceId = "deviceId";
    abilityRequest.abilityInfo.bundleName = "com.ohos.formrenderservice";
    abilityRequest.abilityInfo.name = "testAbility";
    abilityRequest.abilityInfo.moduleName = "testModule";

    int result = connectManager->StopServiceAbilityLocked(abilityRequest);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "StopServiceAbilityLocked_001 end");
}
 
/*
 * Feature: AbilityConnectManager
 * Function: StopServiceAbilityLocked
 */
HWTEST_F(AbilityConnectManagerFourthTest, StopServiceAbilityLocked_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "StopServiceAbilityLocked_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.deviceId = "deviceId";
    abilityRequest.abilityInfo.bundleName ="testBundle";
    abilityRequest.abilityInfo.name = "testAbility";
    abilityRequest.abilityInfo.moduleName = "testModule";
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    abilityRecord->SetAbilityState(AbilityState::TERMINATING);
    connectManager->AddToServiceMap("testServiceKey", abilityRecord);

    int result = connectManager->StopServiceAbilityLocked(abilityRequest);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "StopServiceAbilityLocked_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: StopServiceAbilityLocked
 */
HWTEST_F(AbilityConnectManagerFourthTest, StopServiceAbilityLocked_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "StopServiceAbilityLocked_003 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.deviceId = "deviceId";
    abilityRequest.abilityInfo.bundleName ="testBundle";
    abilityRequest.abilityInfo.name = "testAbility";
    abilityRequest.abilityInfo.moduleName = "testModule";
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> callerToken = abilityRecord->GetToken();
    OHOS::sptr<IAbilityConnection> callback1 = new AbilityConnectCallback();
    std::shared_ptr<ConnectionRecord> connectRecord =
        std::make_shared<ConnectionRecord>(callerToken, abilityRecord, callback1, nullptr);
    abilityRecord->AddConnectRecordToList(connectRecord);
    connectManager->AddToServiceMap("testServiceKey", abilityRecord);

    int result = connectManager->StopServiceAbilityLocked(abilityRequest);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "StopServiceAbilityLocked_003 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: RemoveServiceFromMapSafe
 */
HWTEST_F(AbilityConnectManagerFourthTest, RemoveServiceFromMapSafe_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "RemoveServiceFromMapSafe_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::string existingKey = "existingServiceKey";
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    connectManager->AddToServiceMap(existingKey, abilityRecord);
    EXPECT_EQ(connectManager->GetServiceMap().size(), 1);

    connectManager->RemoveServiceFromMapSafe(existingKey);
    EXPECT_EQ(connectManager->GetServiceMap().size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "RemoveServiceFromMapSafe_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: QueryPreLoadUIExtensionRecordInner
 */
HWTEST_F(AbilityConnectManagerFourthTest, QueryPreLoadUIExtensionRecordInner_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "QueryPreLoadUIExtensionRecordInner_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AppExecFwk::ElementName element("deviceId", "bundleName", "abilityName", "moduleName");
    std::string moduleName = "testModule";
    std::string hostBundleName = "testHostBundle";
    int32_t recordNum = 0;

    int32_t result =
        connectManager->QueryPreLoadUIExtensionRecordInner(element, moduleName, hostBundleName, recordNum);
    EXPECT_EQ(result, ERR_OK);

    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    result =
        connectManager->QueryPreLoadUIExtensionRecordInner(element, moduleName, hostBundleName, recordNum);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    TAG_LOGI(AAFwkTag::TEST, "QueryPreLoadUIExtensionRecordInner_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: QueryPreLoadUIExtensionRecordInner
 */
HWTEST_F(AbilityConnectManagerFourthTest, QueryPreLoadUIExtensionRecordInner_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "QueryPreLoadUIExtensionRecordInner_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AppExecFwk::ElementName element("deviceId", "bundleName", "abilityName", "moduleName");
    std::string moduleName = "testModule";
    std::string hostBundleName = "testHostBundle";
    int32_t recordNum = 0;

    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    int result = connectManager->QueryPreLoadUIExtensionRecordInner(element, moduleName, hostBundleName, recordNum);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    TAG_LOGI(AAFwkTag::TEST, "QueryPreLoadUIExtensionRecordInner_002 end");
}
}  // namespace AAFwk
}  // namespace OHOS
