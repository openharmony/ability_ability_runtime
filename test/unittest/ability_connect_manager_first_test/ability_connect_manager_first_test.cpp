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
class AbilityConnectManagerTest : public testing::Test {
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

AbilityRequest AbilityConnectManagerTest::GenerateAbilityRequest(const std::string& deviceName,
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

sptr<SessionInfo> AbilityConnectManagerTest::MockSessionInfo(int32_t persistentId)
{
    sptr<SessionInfo> sessionInfo = new (std::nothrow) SessionInfo();
    if (!sessionInfo) {
        TAG_LOGE(AAFwkTag::TEST, "sessionInfo is nullptr");
        return nullptr;
    }
    sessionInfo->persistentId = persistentId;
    return sessionInfo;
}

std::shared_ptr<AbilityRecord> AbilityConnectManagerTest::InitAbilityRecord()
{
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    return abilityRecord;
}

void AbilityConnectManagerTest::SetUpTestCase(void)
{}

void AbilityConnectManagerTest::TearDownTestCase(void)
{}

void AbilityConnectManagerTest::SetUp(void)
{
    connectManager_ = std::make_unique<AbilityConnectManager>(0);
    taskHandler_ = MockTaskHandlerWrap::CreateQueueHandler("AbilityConnectManagerTest");
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

void AbilityConnectManagerTest::TearDown(void)
{
    // reset the callback count
    AbilityConnectCallback::onAbilityConnectDoneCount = 0;
    AbilityConnectCallback::onAbilityDisconnectDoneCount = 0;
    serviceRecord_ = nullptr;
}

AbilityConnectManager* AbilityConnectManagerTest::ConnectManager() const
{
    return connectManager_.get();
}

std::shared_ptr<MockTaskHandlerWrap> AbilityConnectManagerTest::TaskHandler() const
{
    return taskHandler_;
}

std::shared_ptr<EventHandlerWrap> AbilityConnectManagerTest::EventHandler() const
{
    return eventHandler_;
}

/*
 * Feature: AbilityConnectManager
 * Function: GetUIExtensionBySessionInfo
 */
HWTEST_F(AbilityConnectManagerTest, GetUIExtensionBySessionInfo_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);
    connectManager->uiExtensionMap_.clear();
    Rosen::SessionInfo info;
    sptr<SessionInfo> sessionInfo(new SessionInfo());
    sessionInfo->sessionToken = new Rosen::Session(info);
    auto service = connectManager->GetUIExtensionBySessionInfo(sessionInfo);
    std::string device = "device";
    std::string abilityName1 = "uiExtensionAbility1";
    std::string appName1 = "uiExtensionProvider1";
    std::string bundleName1 = "com.ix.uiExtensionProvider1";
    std::string moduleName1 = "entry";
    auto request1 = GenerateAbilityRequest(device, abilityName1, appName1, bundleName1, moduleName1);
    auto uiExtension1 = AbilityRecord::CreateAbilityRecord(request1);
    EXPECT_NE(uiExtension1, nullptr);
    uiExtension1->abilityInfo_.extensionAbilityType = ExtensionAbilityType::SYS_COMMON_UI;
    uiExtension1 = nullptr;
    connectManager->uiExtensionMap_.emplace(
        sessionInfo->sessionToken, AbilityConnectManager::UIExtWindowMapValType(uiExtension1, sessionInfo));
    service = connectManager->GetUIExtensionBySessionInfo(sessionInfo);
    EXPECT_EQ(service, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetUIExtensionBySessionInfo
 */
HWTEST_F(AbilityConnectManagerTest, GetUIExtensionBySessionInfo_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);
    connectManager->uiExtensionMap_.clear();
    Rosen::SessionInfo info;
    sptr<SessionInfo> sessionInfo(new SessionInfo());
    sessionInfo->sessionToken = new Rosen::Session(info);
    sessionInfo->callerToken = new Rosen::Session(info);
    std::string device = "device";
    std::string abilityName1 = "uiExtensionAbility1";
    std::string appName1 = "uiExtensionProvider1";
    std::string bundleName1 = "com.ix.uiExtensionProvider1";
    std::string moduleName1 = "entry";
    auto request1 = GenerateAbilityRequest(device, abilityName1, appName1, bundleName1, moduleName1);
    auto uiExtension1 = AbilityRecord::CreateAbilityRecord(request1);
    EXPECT_NE(uiExtension1, nullptr);
    uiExtension1->abilityInfo_.extensionAbilityType = ExtensionAbilityType::SYS_COMMON_UI;
    Rosen::SessionInfo infos;
    sptr<SessionInfo> sessionInfo1(new SessionInfo());
    sessionInfo1 = nullptr;
    connectManager->uiExtensionMap_.emplace(
        sessionInfo->sessionToken, AbilityConnectManager::UIExtWindowMapValType(uiExtension1, sessionInfo1));
    auto service = connectManager->GetUIExtensionBySessionInfo(sessionInfo);
    EXPECT_EQ(service, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetUIExtensionBySessionInfo
 */
HWTEST_F(AbilityConnectManagerTest, GetUIExtensionBySessionInfo_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_003 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);
    connectManager->uiExtensionMap_.clear();
    Rosen::SessionInfo info;
    sptr<SessionInfo> sessionInfo(new SessionInfo());
    sessionInfo->sessionToken = new Rosen::Session(info);
    sessionInfo->callerToken = new Rosen::Session(info);
    std::string device = "device";
    std::string abilityName1 = "uiExtensionAbility1";
    std::string appName1 = "uiExtensionProvider1";
    std::string bundleName1 = "com.ix.uiExtensionProvider1";
    std::string moduleName1 = "entry";
    auto request1 = GenerateAbilityRequest(device, abilityName1, appName1, bundleName1, moduleName1);
    auto uiExtension1 = AbilityRecord::CreateAbilityRecord(request1);
    EXPECT_NE(uiExtension1, nullptr);
    uiExtension1->abilityInfo_.extensionAbilityType = ExtensionAbilityType::SYS_COMMON_UI;

    Rosen::SessionInfo infos;
    sptr<SessionInfo> sessionInfo1(new SessionInfo());
    sessionInfo1->sessionToken = new Rosen::Session(info);
    sessionInfo1->callerToken = uiExtension1->GetToken();
    connectManager->uiExtensionMap_.emplace(
        sessionInfo->sessionToken, AbilityConnectManager::UIExtWindowMapValType(uiExtension1, sessionInfo1));
    auto service = connectManager->GetUIExtensionBySessionInfo(sessionInfo);
    EXPECT_EQ(service, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_003 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetUIExtensionBySessionInfo
 */
HWTEST_F(AbilityConnectManagerTest, GetUIExtensionBySessionInfo_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_004 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);
    connectManager->uiExtensionMap_.clear();
    Rosen::SessionInfo info;
    sptr<SessionInfo> sessionInfo(new SessionInfo());
    sessionInfo->sessionToken = new Rosen::Session(info);
    std::string device = "device";
    std::string abilityName1 = "uiExtensionAbility1";
    std::string appName1 = "uiExtensionProvider1";
    std::string bundleName1 = "com.ix.uiExtensionProvider1";
    std::string moduleName1 = "entry";
    auto request1 = GenerateAbilityRequest(device, abilityName1, appName1, bundleName1, moduleName1);
    auto uiExtension1 = AbilityRecord::CreateAbilityRecord(request1);
    EXPECT_NE(uiExtension1, nullptr);
    uiExtension1->abilityInfo_.extensionAbilityType = ExtensionAbilityType::SYS_COMMON_UI;
    Rosen::SessionInfo infos;
    sptr<SessionInfo> sessionInfo1(new SessionInfo());
    sessionInfo1->sessionToken = uiExtension1->GetToken();
    sessionInfo1->callerToken = new Rosen::Session(info);
    connectManager->uiExtensionMap_.emplace(
        sessionInfo->sessionToken, AbilityConnectManager::UIExtWindowMapValType(uiExtension1, sessionInfo1));
    auto service = connectManager->GetUIExtensionBySessionInfo(sessionInfo);
    EXPECT_EQ(service, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_004 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: HandleActiveAbility
 */
HWTEST_F(AbilityConnectManagerTest, HandleActiveAbility_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleActiveAbility_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    AbilityRequest abilityRequest;
    sptr<IRemoteObject> callerToken = abilityRecord->GetToken();
    OHOS::sptr<IAbilityConnection> callback1 = new AbilityConnectCallback();
    std::shared_ptr<ConnectionRecord> connectRecord =
        std::make_shared<ConnectionRecord>(callerToken, abilityRecord, callback1, nullptr);
    std::shared_ptr<AbilityRecord> targetService = nullptr;
    connectManager->HandleActiveAbility(targetService, connectRecord);
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI_SERVICE;
    Want want;
    want.SetParam(PARAM_RESV_CALLER_APP_ID, std::string("app"));
    abilityRecord->SetWant(want);
    EXPECT_EQ(abilityRecord->GetWant().GetStringParam(PARAM_RESV_CALLER_APP_ID), "app");
    TAG_LOGI(AAFwkTag::TEST, "HandleActiveAbility_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: HandleActiveAbility
 */
HWTEST_F(AbilityConnectManagerTest, HandleActiveAbility_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleActiveAbility_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);
    auto result = connectManager->ConnectAbilityLocked(abilityRequest_, callbackA_, nullptr);
    EXPECT_EQ(0, result);
    auto connectMap = connectManager->connectMap_;
    auto connectRecordList = connectMap.at(callbackA_->AsObject());
    EXPECT_EQ(1, static_cast<int>(connectRecordList.size()));
    auto elementName = abilityRequest_.want.GetElement();
    auto elementNameUri = elementName.GetURI();
    auto serviceMap = connectManager->GetServiceMap();
    std::shared_ptr<AbilityRecord> abilityRecord = serviceMap.at(elementNameUri);
    //AbilityRequest abilityRequest;
    sptr<IRemoteObject> callerToken = abilityRecord->GetToken();
    Want want;
    want.SetParam(PARAM_RESV_CALLER_APP_ID, std::string("app"));
    abilityRecord->SetWant(want);
    OHOS::sptr<IAbilityConnection> callback1 = new AbilityConnectCallback();
    auto connectRecord = std::make_shared<ConnectionRecord>(callerToken, abilityRecord, callback1, nullptr);
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI;
    connectManager->HandleActiveAbility(abilityRecord, connectRecord);
    EXPECT_EQ(abilityRecord->GetWant().GetStringParam(PARAM_RESV_CALLER_APP_ID), "app"); // no remove signatureInfo
    TAG_LOGI(AAFwkTag::TEST, "HandleActiveAbility_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: HandleActiveAbility
 */
HWTEST_F(AbilityConnectManagerTest, HandleActiveAbility_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleActiveAbility_003 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    auto result = connectManager->ConnectAbilityLocked(abilityRequest_, callbackA_, nullptr);
    EXPECT_EQ(0, result);

    result = connectManager->ConnectAbilityLocked(abilityRequest_, callbackB_, nullptr);
    EXPECT_EQ(0, result);

    auto connectMap = connectManager->connectMap_;
    auto connectRecordList = connectMap.at(callbackA_->AsObject());
    EXPECT_EQ(1, static_cast<int>(connectRecordList.size()));

    connectRecordList = connectMap.at(callbackB_->AsObject());
    EXPECT_EQ(1, static_cast<int>(connectRecordList.size()));

    auto elementName = abilityRequest_.want.GetElement();
    std::string elementNameUri = elementName.GetURI();
    auto serviceMap = connectManager->GetServiceMap();
    auto abilityRecord = serviceMap.at(elementNameUri);
    connectRecordList = abilityRecord->GetConnectRecordList();
    EXPECT_EQ(2, static_cast<int>(connectRecordList.size()));
    //AbilityRequest abilityRequest;
    sptr<IRemoteObject> callerToken = abilityRecord->GetToken();
    OHOS::sptr<IAbilityConnection> callback1 = new AbilityConnectCallback();
    auto connectRecord = std::make_shared<ConnectionRecord>(callerToken, abilityRecord, callback1, nullptr);
    auto mockTaskHandler = MockTaskHandlerWrap::CreateQueueHandler("HandleActiveAbility003");
    EXPECT_CALL(*mockTaskHandler, SubmitTaskInner(_, _)).Times(0);
    connectManager->taskHandler_ = mockTaskHandler;
    abilityRecord->connRemoteObject_ = abilityRecord->GetToken();
    connectManager->HandleActiveAbility(abilityRecord, connectRecord);
    TAG_LOGI(AAFwkTag::TEST, "HandleActiveAbility_003 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: HandleRestartResidentTask
 */
HWTEST_F(AbilityConnectManagerTest, HandleRestartResidentTask_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleRestartResidentTask_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::string deviceName = "device";
    std::string abilityName = "TestAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.example.bundle";
    std::string moduleName = "entry";
    abilityRequest_ = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    serviceRecord_ = AbilityRecord::CreateAbilityRecord(abilityRequest_);

    connectManager->HandleRestartResidentTask(abilityRequest_);
    ASSERT_TRUE(connectManager->restartResidentTaskList_.empty());
    TAG_LOGI(AAFwkTag::TEST, "HandleRestartResidentTask_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: HandleRestartResidentTask
 */
HWTEST_F(AbilityConnectManagerTest, HandleRestartResidentTask_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleRestartResidentTask_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    connectManager->restartResidentTaskList_.clear();
    std::string deviceName = "device";
    std::string abilityName = "TestAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.example.bundle";
    std::string moduleName = "entry";
    abilityRequest_ = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    serviceRecord_ = AbilityRecord::CreateAbilityRecord(abilityRequest_);

    connectManager->HandleRestartResidentTask(abilityRequest_);
    ASSERT_EQ(connectManager->restartResidentTaskList_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "HandleRestartResidentTask_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: IsNeedToRestart
 */
HWTEST_F(AbilityConnectManagerTest, IsNeedToRestart_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsNeedToRestart_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    bool result = connectManager->IsNeedToRestart(abilityRecord, "com.example.bundle", "TestAbility");
    ASSERT_TRUE(result);
    TAG_LOGI(AAFwkTag::TEST, "IsNeedToRestart_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: HandleUIExtensionDied
 */
HWTEST_F(AbilityConnectManagerTest, HandleUIExtensionDied_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleUIExtensionDied_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    connectManager->HandleUIExtensionDied(abilityRecord);
    EXPECT_EQ(connectManager->uiExtensionMap_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "HandleUIExtensionDied_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetUIExtensionSessionInfo
 */
HWTEST_F(AbilityConnectManagerTest, GetUIExtensionSessionInfo_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSessionInfo_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    AbilityRequest abilityRequest;
    sptr<IRemoteObject> callerToken = abilityRecord->GetToken();
    UIExtensionSessionInfo info;

    int32_t result = connectManager->GetUIExtensionSessionInfo(callerToken, info);
    ASSERT_EQ(result, OHOS::ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSessionInfo_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetUIExtensionSessionInfo
 */
HWTEST_F(AbilityConnectManagerTest, GetUIExtensionSessionInfo_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSessionInfo_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    ASSERT_NE(connectManager, nullptr);
    
    sptr<IRemoteObject> nullToken = nullptr;
    UIExtensionSessionInfo sessionInfo;
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest_ = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    serviceRecord_ = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    int32_t ret = connectManager->GetUIExtensionSessionInfo(token, sessionInfo);
    EXPECT_NE(ret, OHOS::ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSessionInfo_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: IsStrictMode
 */
HWTEST_F(AbilityConnectManagerTest, IsStrictMode_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsStrictMode_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    bool result = connectManager->IsStrictMode(nullptr);
    ASSERT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "IsStrictMode_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: IsStrictMode
 */
HWTEST_F(AbilityConnectManagerTest, IsStrictMode_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsStrictMode_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::INPUTMETHOD;
    Want want;
    want.SetParam("strictMode", true);
    abilityRecord->SetWant(want);

    bool result = connectManager->IsStrictMode(abilityRecord);
    ASSERT_TRUE(result);
    TAG_LOGI(AAFwkTag::TEST, "IsStrictMode_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: TerminateAbilityInner
 */
HWTEST_F(AbilityConnectManagerTest, TerminateAbilityInner_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "TerminateAbilityInner_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest_);
    auto abilityInfo = abilityRecord->GetAbilityInfo();
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI;
    auto result = ConnectManager()->TerminateAbilityInner(abilityRecord->GetToken());
    EXPECT_EQ(OHOS::ERR_INVALID_VALUE, result);
    TAG_LOGI(AAFwkTag::TEST, "TerminateAbilityInner_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: TerminateAbilityInner
 */
HWTEST_F(AbilityConnectManagerTest, TerminateAbilityInner_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "TerminateAbilityInner_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    auto abilityInfo = abilityRecord->GetAbilityInfo();
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI;
    OHOS::sptr<IAbilityConnection> callback = new AbilityConnectCallback();
    std::shared_ptr<ConnectionRecord> connectionRe =
        std::make_shared<ConnectionRecord>(abilityRecord->GetToken(), abilityRecord, callback, nullptr);
    EXPECT_NE(connectionRe, nullptr);

    abilityRecord->currentState_ = AbilityState::FOREGROUND;
    abilityRecord->connRecordList_.push_back(connectionRe);
    auto result = connectManager->TerminateAbilityInner(abilityRecord->GetToken());
    EXPECT_EQ(OHOS::ERR_INVALID_VALUE, result);
    TAG_LOGI(AAFwkTag::TEST, "TerminateAbilityInner_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: TerminateAbilityInner
 */
HWTEST_F(AbilityConnectManagerTest, TerminateAbilityInner_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "TerminateAbilityInner_003 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    auto abilityInfo = abilityRecord->GetAbilityInfo();
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI;
    abilityRecord->connRecordList_.clear();
    auto result = connectManager->TerminateAbilityInner(abilityRecord->GetToken());
    EXPECT_EQ(OHOS::ERR_INVALID_VALUE, result);
    TAG_LOGI(AAFwkTag::TEST, "TerminateAbilityInner_003 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: IsWindowExtensionFocused
 */
HWTEST_F(AbilityConnectManagerTest, IsWindowExtensionFocused_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsWindowExtensionFocused_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    ASSERT_NE(connectManager, nullptr);

    uint32_t extensionTokenId = 12345;
    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    sptr<IRemoteObject> focusToken = abilityRecord->GetToken();
    ASSERT_NE(focusToken, nullptr);
    
    sptr<SessionInfo> sessionInfo = MockSessionInfo(1);
    sessionInfo->callerToken = focusToken;
    connectManager->windowExtensionMap_.emplace(focusToken, std::make_pair(extensionTokenId, sessionInfo));

    bool result = connectManager->IsWindowExtensionFocused(extensionTokenId, focusToken);
    EXPECT_TRUE(result);

    uint32_t invalidTokenId = 54321;
    result = connectManager->IsWindowExtensionFocused(invalidTokenId, focusToken);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "IsWindowExtensionFocused_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: IsWindowExtensionFocused
 */
HWTEST_F(AbilityConnectManagerTest, IsWindowExtensionFocused_0002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsWindowExtensionFocused_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    ASSERT_NE(connectManager, nullptr);

    uint32_t extensionTokenId = 12345;
    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    sptr<IRemoteObject> focusToken = abilityRecord->GetToken();
    ASSERT_NE(focusToken, nullptr);
    
    sptr<SessionInfo> sessionInfo = MockSessionInfo(1);
    sessionInfo->callerToken = focusToken;
    connectManager->windowExtensionMap_.emplace(focusToken, std::make_pair(extensionTokenId, nullptr));
    
    bool result = connectManager->IsWindowExtensionFocused(extensionTokenId, focusToken);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "IsWindowExtensionFocused_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: NeedExtensionControl
 */
HWTEST_F(AbilityConnectManagerTest, NeedExtensionControl_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "NeedExtensionControl_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);
    
    std::shared_ptr<AbilityRecord> nullRecord = nullptr;
    bool result = connectManager->NeedExtensionControl(nullRecord);
    EXPECT_FALSE(result);

    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SERVICE;
    result = connectManager->NeedExtensionControl(abilityRecord);
    EXPECT_FALSE(result);

    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::DATASHARE;
    result = connectManager->NeedExtensionControl(abilityRecord);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "NeedExtensionControl_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: NeedExtensionControl
 */
HWTEST_F(AbilityConnectManagerTest, NeedExtensionControl_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "NeedExtensionControl_002 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    abilityRecord->abilityInfo_.extensionAbilityType = AppExecFwk::ExtensionAbilityType::FORM;
    abilityRecord->SetCustomProcessFlag("");
    bool result = connectManager->NeedExtensionControl(abilityRecord);
    EXPECT_TRUE(result);

    abilityRecord->SetCustomProcessFlag("Test customProces");
    uint32_t extensionProcessMode = 0;
    abilityRecord->SetExtensionProcessMode(extensionProcessMode);
    result = connectManager->NeedExtensionControl(abilityRecord);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "NeedExtensionControl_002 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: StartAbilityLocked
 */
HWTEST_F(AbilityConnectManagerTest, StartAbilityLocked_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "StartAbilityLocked_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    sptr<IRemoteObject> focusToken = abilityRecord->GetToken();
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.deviceId = "id";
    abilityRequest.abilityInfo.bundleName = "bundle";
    abilityRequest.abilityInfo.name = "name";
    abilityRequest.abilityInfo.moduleName = "module";
    abilityRequest.abilityInfo.extensionAbilityType = ExtensionAbilityType::UI;
    std::string stringUri = "id/bundle/module/name";
    abilityRequest.callerToken = abilityRecord->GetToken();
    AppExecFwk::ElementName element(abilityRequest.abilityInfo.deviceId, abilityRequest.abilityInfo.bundleName,
        abilityRequest.abilityInfo.name, abilityRequest.abilityInfo.moduleName);
    EXPECT_EQ(element.GetURI(), stringUri);
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;

    int result = connectManager->StartAbilityLocked(abilityRequest);
    EXPECT_NE(result, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "StartAbilityLocked_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: DoForegroundUIExtension
 */
HWTEST_F(AbilityConnectManagerTest, DoForegroundUIExtension_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DoForegroundUIExtension_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> nullRecord = nullptr;
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.deviceId = "id";
    abilityRequest.abilityInfo.bundleName = "bundle";
    abilityRequest.abilityInfo.name = "name";
    abilityRequest.abilityInfo.moduleName = "module";
    abilityRequest.abilityInfo.extensionAbilityType = ExtensionAbilityType::UI;
    connectManager->DoForegroundUIExtension(nullRecord, abilityRequest);

    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    abilityRecord->isReady_ = true;
    abilityRecord->currentState_ = AbilityState::FOREGROUND;
    
    connectManager->DoForegroundUIExtension(abilityRecord, abilityRequest);
    std::string expectName = "name";
    EXPECT_EQ(expectName, abilityRequest.abilityInfo.name);
    TAG_LOGI(AAFwkTag::TEST, "DoForegroundUIExtension_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetOrCreateExtensionRecord
 */
HWTEST_F(AbilityConnectManagerTest, GetOrCreateExtensionRecord_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetOrCreateExtensionRecord_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    std::string hostBundName = "bundleName";
    bool isCreate = false;
    bool isLoadedAbility = false;
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    
    int32_t result = connectManager->GetOrCreateExtensionRecord(
        abilityRequest, isCreate, hostBundName, abilityRecord, isLoadedAbility);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    TAG_LOGI(AAFwkTag::TEST, "GetOrCreateExtensionRecord_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetOrCreateExtensionRecord
 */
HWTEST_F(AbilityConnectManagerTest, GetOrCreateServiceRecord_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetOrCreateServiceRecord_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI_SERVICE;
    abilityRequest.abilityInfo.bundleName = "com.example.test";
    abilityRequest.abilityInfo.name = "TestAbility";

    std::shared_ptr<AbilityRecord> resultService = nullptr;
    bool isLoadedAbility = false;
    connectManager->GetOrCreateServiceRecord(abilityRequest, false, resultService, isLoadedAbility);

    ASSERT_NE(resultService, nullptr);
    EXPECT_EQ(resultService->GetAbilityInfo().name, "TestAbility");
    TAG_LOGI(AAFwkTag::TEST, "GetOrCreateServiceRecord_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: GetOrCreateExtensionRecord
 */
HWTEST_F(AbilityConnectManagerTest, UnloadUIExtensionAbility_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "UnloadUIExtensionAbility_001 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::WORK_SCHEDULER;
    abilityRequest.abilityInfo.bundleName = "com.example.test";
    abilityRequest.abilityInfo.name = "TestAbility";
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    OHOS::sptr<IAbilityConnection> callback = new AbilityConnectCallback();
    std::shared_ptr<ConnectionRecord> connection =
        std::make_shared<ConnectionRecord>(abilityRecord->GetToken(), abilityRecord, callback, nullptr);
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    connection->SetConnectState(ConnectionState::DISCONNECTING);
    abilityRecord->abilityInfo_.type = AbilityType::PAGE;
    abilityRecord->SetAbilityState(AbilityState::INACTIVE);
    abilityRecord->connRecordList_.push_back(connection);
    std::string hostBundName = "bundleName";

    int result = connectManager->UnloadUIExtensionAbility(abilityRecord, hostBundName);
    EXPECT_NE(result, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "UnloadUIExtensionAbility_001 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: HandleActiveAbility
 */
HWTEST_F(AbilityConnectManagerTest, HandleActiveAbility_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleActiveAbility_004 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::WORK_SCHEDULER;
    abilityRequest.abilityInfo.bundleName = "com.example.test";
    abilityRequest.abilityInfo.name = "TestAbility";
    std::shared_ptr<AbilityRecord> targetService  = AbilityRecord::CreateAbilityRecord(abilityRequest);
    Want want;
    want.SetParam(PARAM_RESV_CALLER_APP_ID, std::string("app"));
    targetService->SetWant(want);
    targetService->abilityInfo_.extensionAbilityType = ExtensionAbilityType::UI_SERVICE;
    std::shared_ptr<ConnectionRecord> connectRecord = nullptr;

    connectManager->HandleActiveAbility(targetService, connectRecord);
    EXPECT_NE(targetService->GetWant().GetStringParam(PARAM_RESV_CALLER_APP_ID), "app");
    TAG_LOGI(AAFwkTag::TEST, "HandleActiveAbility_004 end");
}

/*
 * Feature: AbilityConnectManager
 * Function: HandleActiveAbility
 */
HWTEST_F(AbilityConnectManagerTest, HandleActiveAbility_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleActiveAbility_005 start");
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI_SERVICE;
    abilityRequest.abilityInfo.bundleName = "com.example.test";
    abilityRequest.abilityInfo.name = "TestAbility";
    std::shared_ptr<AbilityRecord> targetService  = AbilityRecord::CreateAbilityRecord(abilityRequest);
    Want want;
    want.SetParam(PARAM_RESV_CALLER_APP_ID, std::string("app"));
    targetService->SetWant(want);
    sptr<IRemoteObject> callerToken = abilityRecord->GetToken();
    OHOS::sptr<IAbilityConnection> callback1 = new AbilityConnectCallback();
    std::shared_ptr<ConnectionRecord> connectRecord =
        std::make_shared<ConnectionRecord>(callerToken, abilityRecord, callback1, nullptr);

    connectManager->HandleActiveAbility(targetService, connectRecord);
    EXPECT_NE(targetService->GetWant().GetStringParam(PARAM_RESV_CALLER_APP_ID), "app");
    TAG_LOGI(AAFwkTag::TEST, "HandleActiveAbility_005 end");
}
}  // namespace AAFwk
}  // namespace OHOS
