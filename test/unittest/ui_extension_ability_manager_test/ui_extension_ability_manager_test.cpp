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
#include <memory>

#define private public
#define protected public
#include "ui_extension_ability_manager.h"
#undef private
#undef protected

#include "ability_config.h"
#include "ability_manager_errors.h"
#include "ability_scheduler.h"
#include "ability_util.h"
#include "extension_record.h"
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
constexpr uint32_t FAKE_TOKENID = 111;
const std::string UIEXTENSION_ABILITY_ID = "ability.want.params.uiExtensionAbilityId";
}

namespace OHOS {
namespace AAFwk {
class UIExtensionAbilityManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    UIExtensionAbilityManager* GetUIExtensionAbilityManager() const;
    std::shared_ptr<MockTaskHandlerWrap> TaskHandler() const;
    std::shared_ptr<EventHandlerWrap> EventHandler() const;

    AbilityRequest GenerateAbilityRequest(const std::string& deviceName, const std::string& abilityName,
        const std::string& appName, const std::string& bundleName, const std::string& moduleName);

    sptr<SessionInfo> MockSessionInfo(int32_t persistentId);
    std::shared_ptr<BaseExtensionRecord> InitAbilityRecord();
    std::shared_ptr<MockTaskHandlerWrap> taskHandler_;
protected:
    AbilityRequest abilityRequest_{};
    AbilityRequest abilityRequest1_{};
    AbilityRequest abilityRequest2_{};
    std::shared_ptr<BaseExtensionRecord> serviceRecord_{ nullptr };
    std::shared_ptr<BaseExtensionRecord> serviceRecord1_{ nullptr };
    std::shared_ptr<BaseExtensionRecord> serviceRecord2_{ nullptr };
    std::shared_ptr<BaseExtensionRecord> uiExtensionAbilityRecord1_{ nullptr };
    OHOS::sptr<Token> serviceToken_{ nullptr };
    OHOS::sptr<Token> serviceToken1_{ nullptr };
    OHOS::sptr<Token> serviceToken2_{ nullptr };
    OHOS::sptr<IAbilityConnection> callbackA_{ nullptr };
    OHOS::sptr<IAbilityConnection> callbackB_{ nullptr };
    AbilityRequest uiExtensionAbilityRequest1_{};
    OHOS::sptr<Token> uiExtensionAbilityToken1_{ nullptr };

private:
    std::shared_ptr<UIExtensionAbilityManager> connectManager_;
    std::shared_ptr<EventHandlerWrap> eventHandler_;
};

AbilityRequest UIExtensionAbilityManagerTest::GenerateAbilityRequest(const std::string& deviceName,
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

sptr<SessionInfo> UIExtensionAbilityManagerTest::MockSessionInfo(int32_t persistentId)
{
    sptr<SessionInfo> sessionInfo = new (std::nothrow) SessionInfo();
    if (!sessionInfo) {
        TAG_LOGE(AAFwkTag::TEST, "sessionInfo is nullptr");
        return nullptr;
    }
    sessionInfo->persistentId = persistentId;
    return sessionInfo;
}

std::shared_ptr<BaseExtensionRecord> UIExtensionAbilityManagerTest::InitAbilityRecord()
{
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::PAGE;
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest);
    return abilityRecord;
}

void UIExtensionAbilityManagerTest::SetUpTestCase(void)
{}

void UIExtensionAbilityManagerTest::TearDownTestCase(void)
{}

void UIExtensionAbilityManagerTest::SetUp(void)
{
    connectManager_ = std::make_unique<UIExtensionAbilityManager>(0);
    taskHandler_ = MockTaskHandlerWrap::CreateQueueHandler("UIExtensionAbilityManagerTest");
    eventHandler_ = std::make_shared<EventHandlerWrap>(taskHandler_);
    // generate ability request
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest_ = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    serviceRecord_ = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest_);
    serviceToken_ = serviceRecord_->GetToken();
    std::string deviceName1 = "device";
    std::string abilityName1 = "musicServiceAbility";
    std::string appName1 = "musicservcie";
    std::string bundleName1 = "com.ix.musicservcie";
    std::string moduleName1 = "entry";
    abilityRequest1_ = GenerateAbilityRequest(deviceName1, abilityName1, appName1, bundleName1, moduleName1);
    serviceRecord1_ = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest1_);
    std::string deviceName2 = "device";
    std::string abilityName2 = "residentServiceAbility";
    std::string appName2 = "residentservcie";
    std::string bundleName2 = "com.ix.residentservcie";
    std::string moduleName2 = "entry";
    abilityRequest2_ = GenerateAbilityRequest(deviceName2, abilityName2, appName2, bundleName2, moduleName2);
    serviceRecord2_ = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest2_);
    serviceToken2_ = serviceRecord_->GetToken();
    serviceToken1_ = serviceRecord_->GetToken();
    callbackA_ = new AbilityConnectCallback();
    callbackB_ = new AbilityConnectCallback();
}

void UIExtensionAbilityManagerTest::TearDown(void)
{
    // reset the callback count
    AbilityConnectCallback::onAbilityConnectDoneCount = 0;
    AbilityConnectCallback::onAbilityDisconnectDoneCount = 0;
    serviceRecord_ = nullptr;
}

UIExtensionAbilityManager* UIExtensionAbilityManagerTest::GetUIExtensionAbilityManager() const
{
    return connectManager_.get();
}

std::shared_ptr<MockTaskHandlerWrap> UIExtensionAbilityManagerTest::TaskHandler() const
{
    return taskHandler_;
}

std::shared_ptr<EventHandlerWrap> UIExtensionAbilityManagerTest::EventHandler() const
{
    return eventHandler_;
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionBySessionInfo
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionBySessionInfo_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_001 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
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
    auto uiExtension1 = BaseExtensionRecord::CreateBaseExtensionRecord(request1);
    EXPECT_NE(uiExtension1, nullptr);
    uiExtension1->abilityInfo_.extensionAbilityType = ExtensionAbilityType::SYS_COMMON_UI;
    uiExtension1 = nullptr;
    connectManager->uiExtensionMap_.emplace(
        sessionInfo->sessionToken, UIExtensionAbilityManager::UIExtWindowMapValType(uiExtension1, sessionInfo));
    service = connectManager->GetUIExtensionBySessionInfo(sessionInfo);
    EXPECT_EQ(service, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_001 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionBySessionInfo
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionBySessionInfo_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_002 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
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
    auto uiExtension1 = BaseExtensionRecord::CreateBaseExtensionRecord(request1);
    EXPECT_NE(uiExtension1, nullptr);
    uiExtension1->abilityInfo_.extensionAbilityType = ExtensionAbilityType::SYS_COMMON_UI;
    Rosen::SessionInfo infos;
    sptr<SessionInfo> sessionInfo1(new SessionInfo());
    sessionInfo1 = nullptr;
    connectManager->uiExtensionMap_.emplace(
        sessionInfo->sessionToken, UIExtensionAbilityManager::UIExtWindowMapValType(uiExtension1, sessionInfo1));
    auto service = connectManager->GetUIExtensionBySessionInfo(sessionInfo);
    EXPECT_EQ(service, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_002 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionBySessionInfo
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionBySessionInfo_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_003 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
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
    auto uiExtension1 = BaseExtensionRecord::CreateBaseExtensionRecord(request1);
    EXPECT_NE(uiExtension1, nullptr);
    uiExtension1->abilityInfo_.extensionAbilityType = ExtensionAbilityType::SYS_COMMON_UI;

    Rosen::SessionInfo infos;
    sptr<SessionInfo> sessionInfo1(new SessionInfo());
    sessionInfo1->sessionToken = new Rosen::Session(info);
    sessionInfo1->callerToken = uiExtension1->GetToken();
    connectManager->uiExtensionMap_.emplace(
        sessionInfo->sessionToken, UIExtensionAbilityManager::UIExtWindowMapValType(uiExtension1, sessionInfo1));
    auto service = connectManager->GetUIExtensionBySessionInfo(sessionInfo);
    EXPECT_EQ(service, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_003 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionBySessionInfo
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionBySessionInfo_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_004 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
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
    auto uiExtension1 = BaseExtensionRecord::CreateBaseExtensionRecord(request1);
    EXPECT_NE(uiExtension1, nullptr);
    uiExtension1->abilityInfo_.extensionAbilityType = ExtensionAbilityType::SYS_COMMON_UI;
    Rosen::SessionInfo infos;
    sptr<SessionInfo> sessionInfo1(new SessionInfo());
    sessionInfo1->sessionToken = uiExtension1->GetToken();
    sessionInfo1->callerToken = new Rosen::Session(info);
    connectManager->uiExtensionMap_.emplace(
        sessionInfo->sessionToken, UIExtensionAbilityManager::UIExtWindowMapValType(uiExtension1, sessionInfo1));
    auto service = connectManager->GetUIExtensionBySessionInfo(sessionInfo);
    EXPECT_EQ(service, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionBySessionInfo_004 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: HandleUIExtensionDied
 */
HWTEST_F(UIExtensionAbilityManagerTest, HandleUIExtensionDied_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleUIExtensionDied_001 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<BaseExtensionRecord> abilityRecord = serviceRecord_;
    connectManager->HandleUIExtensionDied(abilityRecord);
    EXPECT_EQ(connectManager->uiExtensionMap_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "HandleUIExtensionDied_001 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionSessionInfo
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionSessionInfo_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSessionInfo_001 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<BaseExtensionRecord> abilityRecord = serviceRecord_;
    AbilityRequest abilityRequest;
    sptr<IRemoteObject> callerToken = abilityRecord->GetToken();
    UIExtensionSessionInfo info;

    int32_t result = connectManager->GetUIExtensionSessionInfo(callerToken, info);
    ASSERT_EQ(result, OHOS::ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSessionInfo_001 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionSessionInfo
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionSessionInfo_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSessionInfo_002 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    ASSERT_NE(connectManager, nullptr);
    
    sptr<IRemoteObject> nullToken = nullptr;
    UIExtensionSessionInfo sessionInfo;
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest_ = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    serviceRecord_ = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest_);
    std::shared_ptr<BaseExtensionRecord> abilityRecord = serviceRecord_;
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    int32_t ret = connectManager->GetUIExtensionSessionInfo(token, sessionInfo);
    EXPECT_NE(ret, OHOS::ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSessionInfo_002 end");
}


/*
 * Feature: UIExtensionAbilityManager
 * Function: DoForegroundUIExtension
 */
HWTEST_F(UIExtensionAbilityManagerTest, DoForegroundUIExtension_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DoForegroundUIExtension_001 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<BaseExtensionRecord> nullRecord = nullptr;
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.deviceId = "id";
    abilityRequest.abilityInfo.bundleName = "bundle";
    abilityRequest.abilityInfo.name = "name";
    abilityRequest.abilityInfo.moduleName = "module";
    abilityRequest.abilityInfo.extensionAbilityType = ExtensionAbilityType::UI;
    connectManager->DoForegroundUIExtension(nullRecord, abilityRequest);

    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest);
    abilityRecord->isReady_ = true;
    abilityRecord->currentState_ = AbilityState::FOREGROUND;
    
    connectManager->DoForegroundUIExtension(abilityRecord, abilityRequest);
    std::string expectName = "name";
    EXPECT_EQ(expectName, abilityRequest.abilityInfo.name);
    TAG_LOGI(AAFwkTag::TEST, "DoForegroundUIExtension_001 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetOrCreateExtensionRecord
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetOrCreateExtensionRecord_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetOrCreateExtensionRecord_001 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.unittest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::PAGE;
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest);
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
 * Feature: UIExtensionAbilityManager
 * Function: GetOrCreateExtensionRecord
 */
HWTEST_F(UIExtensionAbilityManagerTest, UnloadUIExtensionAbility_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "UnloadUIExtensionAbility_001 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::WORK_SCHEDULER;
    abilityRequest.abilityInfo.bundleName = "com.example.test";
    abilityRequest.abilityInfo.name = "TestAbility";
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest);
    OHOS::sptr<IAbilityConnection> callback = new AbilityConnectCallback();
    std::shared_ptr<ConnectionRecord> connection =
        std::make_shared<ConnectionRecord>(abilityRecord->GetToken(), abilityRecord, callback, nullptr);
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    connection->SetConnectState(ConnectionState::DISCONNECTING);
    abilityRecord->abilityInfo_.type = AbilityType::PAGE;
    abilityRecord->SetAbilityState(AbilityState::INACTIVE);
    abilityRecord->connRecordList_.push_back(connection);
    int32_t hostPid = 10;

    int result = connectManager->UnloadUIExtensionAbility(abilityRecord, hostPid);
    EXPECT_NE(result, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "UnloadUIExtensionAbility_001 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: IsUIExtensionFocused
 */
HWTEST_F(UIExtensionAbilityManagerTest, IsUIExtensionFocused_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsUIExtensionFocused_001 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    uint32_t uiExtensionTokenId = 1;
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest_);
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
 * Feature: UIExtensionAbilityManager
 * Function: IsUIExtensionFocused
 */
HWTEST_F(UIExtensionAbilityManagerTest, IsUIExtensionFocused_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsUIExtensionFocused_002 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    uint32_t uiExtensionTokenId = 1;
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest_);
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
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionSourceToken
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionSourceToken_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_001 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    sptr<IRemoteObject> nulltoken = nullptr;
    sptr<IRemoteObject> resultToken = connectManager->GetUIExtensionSourceToken(nulltoken);
    EXPECT_EQ(resultToken, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_001 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionSourceToken
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionSourceToken_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_002 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    connectManager->uiExtensionMap_.emplace(token, std::make_pair(abilityRecord, nullptr));

    sptr<IRemoteObject> resultToken = connectManager->GetUIExtensionSourceToken(token);
    EXPECT_EQ(resultToken, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_002 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionSourceToken
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionSourceToken_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_002 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    sptr<SessionInfo> sessionInfo = new SessionInfo();
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    connectManager->uiExtensionMap_.clear();
    connectManager->uiExtensionMap_.emplace(token, std::make_pair(abilityRecord, sessionInfo));

    sptr<IRemoteObject> resultToken = connectManager->GetUIExtensionSourceToken(token);
    EXPECT_EQ(resultToken, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_002 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: QueryPreLoadUIExtensionRecordInner
 */
HWTEST_F(UIExtensionAbilityManagerTest, QueryPreLoadUIExtensionRecordInner_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "QueryPreLoadUIExtensionRecordInner_001 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AppExecFwk::ElementName element("deviceId", "bundleName", "abilityName", "moduleName");
    std::string moduleName = "testModule";
    int32_t hostPid = 0;
    int32_t recordNum = 0;

    int32_t result =
        connectManager->QueryPreLoadUIExtensionRecordInner(element, moduleName, hostPid, recordNum);
    EXPECT_EQ(result, ERR_OK);

    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    result =
        connectManager->QueryPreLoadUIExtensionRecordInner(element, moduleName, hostPid, recordNum);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    TAG_LOGI(AAFwkTag::TEST, "QueryPreLoadUIExtensionRecordInner_001 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: QueryPreLoadUIExtensionRecordInner
 */
HWTEST_F(UIExtensionAbilityManagerTest, QueryPreLoadUIExtensionRecordInner_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "QueryPreLoadUIExtensionRecordInner_002 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    AppExecFwk::ElementName element("deviceId", "bundleName", "abilityName", "moduleName");
    std::string moduleName = "testModule";
    int32_t hostPid = 0;
    int32_t recordNum = 0;

    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    int result = connectManager->QueryPreLoadUIExtensionRecordInner(element, moduleName, hostPid, recordNum);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    TAG_LOGI(AAFwkTag::TEST, "QueryPreLoadUIExtensionRecordInner_002 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: PreloadUIExtensionAbilityInner
 */
HWTEST_F(UIExtensionAbilityManagerTest, PreloadUIExtensionAbilityInner_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "PreloadUIExtensionAbilityInner_001 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);
    std::string hostBundleName = "hostBundleName";
    int32_t hostPid = 1;

    auto res = connectManager->PreloadUIExtensionAbilityInner(abilityRequest_, hostBundleName, hostPid);
    EXPECT_EQ(res, ERR_WRONG_INTERFACE_CALL);

    abilityRequest_.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SHARE;
    res = connectManager->PreloadUIExtensionAbilityInner(abilityRequest_, hostBundleName, hostPid);
    EXPECT_EQ(res, ERR_OK);

    abilityRequest_.want.SetParam(Want::CREATE_APP_INSTANCE_KEY, true);
    res = connectManager->PreloadUIExtensionAbilityInner(abilityRequest_, hostBundleName, hostPid);
    EXPECT_EQ(res, ERR_INVALID_VALUE);

    abilityRequest_.want.SetParam(Want::CREATE_APP_INSTANCE_KEY, false);
    abilityRequest_.extensionType = AppExecFwk::ExtensionAbilityType::EMBEDDED_UI;
    res = connectManager->PreloadUIExtensionAbilityInner(abilityRequest_, hostBundleName, hostPid);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "PreloadUIExtensionAbilityInner_001 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: HandleUIExtWindowDiedTask
 * SubFunction: HandleUIExtWindowDiedTask
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UIExtensionAbilityManager HandleUIExtWindowDiedTask
 * @tc.require: AR000I8B26
 */
HWTEST_F(UIExtensionAbilityManagerTest, HandleUIExtWindowDiedTask_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    ASSERT_NE(connectManager, nullptr);
    connectManager->uiExtRecipientMap_.clear();
    connectManager->uiExtensionMap_.clear();

    connectManager->uiExtensionMap_.emplace(
        callbackA_->AsObject(), UIExtensionAbilityManager::UIExtWindowMapValType(serviceRecord_, MockSessionInfo(0)));
    connectManager->AddUIExtWindowDeathRecipient(callbackA_->AsObject());
    connectManager->HandleUIExtWindowDiedTask(nullptr);
    EXPECT_EQ(static_cast<int>(connectManager->uiExtRecipientMap_.size()), 1);
    EXPECT_EQ(static_cast<int>(connectManager->uiExtensionMap_.size()), 1);

    connectManager->HandleUIExtWindowDiedTask(callbackA_->AsObject());
    EXPECT_TRUE(connectManager->uiExtRecipientMap_.empty());
    EXPECT_TRUE(connectManager->uiExtensionMap_.empty());
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: IsUIExtensionFocused
 * SubFunction: IsUIExtensionFocused
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UIExtensionAbilityManager IsUIExtensionFocused
 */
HWTEST_F(UIExtensionAbilityManagerTest, IsUIExtensionFocused_003, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(3);
    ASSERT_NE(connectManager, nullptr);
    connectManager->uiExtensionMap_.clear();
    bool isFocused = connectManager->IsUIExtensionFocused(
        serviceRecord_->GetApplicationInfo().accessTokenId, serviceRecord1_->GetToken());
    EXPECT_EQ(isFocused, false);
    connectManager.reset();
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: IsUIExtensionFocused
 * SubFunction: IsUIExtensionFocused
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UIExtensionAbilityManager IsUIExtensionFocused
 */
HWTEST_F(UIExtensionAbilityManagerTest, IsUIExtensionFocused_004, TestSize.Level1)
{
    AAFwk::IsMockSaCall::IsMockSaCallWithPermission();
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(3);
    ASSERT_NE(connectManager, nullptr);
    connectManager->uiExtensionMap_.clear();

    std::string device = "device";
    std::string abilityName = "uiExtensionUserAbility";
    std::string appName = "uiExtensionUser";
    std::string bundleName = "com.ix.uiExtensionUser";
    std::string moduleName = "entry";
    auto request = GenerateAbilityRequest(device, abilityName, appName, bundleName, moduleName);
    auto uiExtensionUser = BaseExtensionRecord::CreateBaseExtensionRecord(request);
    EXPECT_NE(uiExtensionUser, nullptr);

    std::string abilityName1 = "uiExtensionAbility1";
    std::string appName1 = "uiExtensionProvider1";
    std::string bundleName1 = "com.ix.uiExtensionProvider1";
    std::string moduleName1 = "entry";
    auto request1 = GenerateAbilityRequest(device, abilityName1, appName1, bundleName1, moduleName1);
    auto uiExtension1 = BaseExtensionRecord::CreateBaseExtensionRecord(request1);
    EXPECT_NE(uiExtension1, nullptr);
    uiExtension1->abilityInfo_.extensionAbilityType = ExtensionAbilityType::SYS_COMMON_UI;
    sptr<SessionInfo> sessionInfo1 = new (std::nothrow) SessionInfo();
    sessionInfo1->callerToken = uiExtensionUser->GetToken();
    uiExtension1->sessionInfo_ = sessionInfo1;
    connectManager->uiExtensionMap_.emplace(
        callbackA_->AsObject(), UIExtensionAbilityManager::UIExtWindowMapValType(uiExtension1, sessionInfo1));
    bool isFocused1 = connectManager->IsUIExtensionFocused(
        uiExtension1->GetApplicationInfo().accessTokenId, uiExtensionUser->GetToken());
    EXPECT_EQ(isFocused1, true);
    std::string abilityName2 = "uiExtensionAbility2";
    std::string appName2 = "uiExtensionProvider2";
    std::string bundleName2 = "com.ix.uiExtensionProvider2";
    std::string moduleName2 = "entry";
    auto request2 = GenerateAbilityRequest(device, abilityName2, appName2, bundleName2, moduleName2);
    auto uiExtension2 = BaseExtensionRecord::CreateBaseExtensionRecord(request2);
    EXPECT_NE(uiExtension2, nullptr);
    uiExtension2->abilityInfo_.extensionAbilityType = ExtensionAbilityType::SYS_COMMON_UI;
    sptr<SessionInfo> sessionInfo2 = new (std::nothrow) SessionInfo();
    sessionInfo2->callerToken = uiExtension1->GetToken();
    uiExtension2->sessionInfo_ = sessionInfo2;
    connectManager->uiExtensionMap_.emplace(
        callbackA_->AsObject(), UIExtensionAbilityManager::UIExtWindowMapValType(uiExtension2, sessionInfo2));
    bool isFocused2 = connectManager->IsUIExtensionFocused(
        uiExtension2->GetApplicationInfo().accessTokenId, uiExtensionUser->GetToken());
    EXPECT_EQ(isFocused2, true);
    connectManager.reset();
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionSourceToken
 * SubFunction: GetUIExtensionSourceToken
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UIExtensionAbilityManager GetUIExtensionSourceToken
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionSourceToken_004, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(3);
    ASSERT_NE(connectManager, nullptr);
    connectManager->uiExtensionMap_.clear();
    auto sourceToken = connectManager->GetUIExtensionSourceToken(nullptr);
    EXPECT_EQ(sourceToken, nullptr);
    connectManager.reset();
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: PauseExtensions
 * SubFunction: PauseExtensions
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UIExtensionAbilityManager PauseExtensions
 */
HWTEST_F(UIExtensionAbilityManagerTest, AAFwk_AbilityMS_PauseExtensions_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    ASSERT_NE(connectManager, nullptr);
    std::shared_ptr<BaseExtensionRecord> abilityRecord1 = serviceRecord_;
    abilityRecord1->abilityInfo_.type = AbilityType::PAGE;
    connectManager->serviceMap_.emplace("first", abilityRecord1);
    std::shared_ptr<BaseExtensionRecord> abilityRecord2 = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest_);
    abilityRecord2->abilityInfo_.type = AbilityType::EXTENSION;
    abilityRecord2->abilityInfo_.name = AbilityConfig::LAUNCHER_ABILITY_NAME;
    abilityRecord2->abilityInfo_.bundleName = AbilityConfig::LAUNCHER_BUNDLE_NAME;
    connectManager->serviceMap_.emplace("second", abilityRecord2);
    connectManager->PauseExtensions();
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: SignRestartAppFlag
 * CaseDescription: Verify UIExtensionAbilityManager SignRestartAppFlag
 */
HWTEST_F(UIExtensionAbilityManagerTest, AAFwk_AbilityMS_SignRestartAppFlag_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    ASSERT_NE(connectManager, nullptr);

    std::string bundleName = "testBundleName";
    std::shared_ptr<BaseExtensionRecord> abilityRecord1 = serviceRecord_;
    abilityRecord1->abilityInfo_.bundleName = bundleName;
    connectManager->serviceMap_.emplace("first", abilityRecord1);
    std::shared_ptr<BaseExtensionRecord> abilityRecord2 = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest_);
    abilityRecord2->abilityInfo_.bundleName = "errTestBundleName";
    connectManager->serviceMap_.emplace("second", abilityRecord2);
    int32_t uid = 100;
    connectManager->SignRestartAppFlag(uid, "");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: BuildEventInfo
 * CaseDescription: Verify UIExtensionAbilityManager BuildEventInfo
 */
HWTEST_F(UIExtensionAbilityManagerTest, AAFwk_AbilityMS_BuildEventInfo_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    ASSERT_NE(connectManager, nullptr);

    connectManager->BuildEventInfo(nullptr);
    std::shared_ptr<BaseExtensionRecord> abilityRecord = InitAbilityRecord();
    connectManager->BuildEventInfo(abilityRecord);
    abilityRecord->SetCreateByConnectMode(true);
    connectManager->BuildEventInfo(abilityRecord);
}

/**
 * @tc.name: UpdateUIExtensionInfo_0100
 * @tc.desc: Update want params of ui extension.
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionAbilityManagerTest, UpdateUIExtensionInfo_0100, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    ASSERT_NE(connectManager, nullptr);

    Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.extensionAbilityType = ExtensionAbilityType::SYS_COMMON_UI;
    AppExecFwk::ApplicationInfo applicationInfo;
    auto abilityRecord = std::make_shared<BaseExtensionRecord>(want, abilityInfo, applicationInfo);
    abilityRecord->SetUIExtensionAbilityId(1000);
    connectManager->UpdateUIExtensionInfo(abilityRecord);
    EXPECT_EQ(abilityRecord->GetWant().HasParameter("ability.want.params.uiExtensionAbilityId"), true);
    EXPECT_EQ(abilityRecord->GetWant().GetIntParam("ability.want.params.uiExtensionAbilityId", -1), 1000);
}

/**
 * @tc.name: PreloadUIExtensionAbilityLocked_0100
 * @tc.desc: preload uiextension ability
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionAbilityManagerTest, PreloadUIExtensionAbilityLocked_0100, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    ASSERT_NE(connectManager, nullptr);

    AbilityRequest abilityRequest;
    AppExecFwk::ElementName providerElement("0", "com.ohos.uiextensionprovider", "UIExtensionProvider", "entry");
    abilityRequest.want.SetElement(providerElement);
    abilityRequest.abilityInfo.type = AbilityType::EXTENSION;
    std::string hostBundleName = "com.ohos.uiextensionuser";

    int32_t preloadId = AbilityRuntime::INVALID_EXTENSION_RECORD_ID;
    int32_t hostPid = DEFAULT_INVAL_VALUE;
    auto ret = connectManager->PreloadUIExtensionAbilityLocked(
        abilityRequest, hostBundleName, ERR_PRELOAD_APP_DATA_ABILITIES_FAILED);
    EXPECT_NE(ret, ERR_OK);
}

/**
 * @tc.name: UnloadUIExtensionAbility_0100
 * @tc.desc: UnloadUIExtensionAbility
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionAbilityManagerTest, UnloadUIExtensionAbility_0100, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    ASSERT_NE(connectManager, nullptr);

    AbilityRequest abilityRequest;
    AppExecFwk::ElementName providerElement("0", "com.ohos.uiextensionprovider", "UIExtensionProvider", "entry");
    abilityRequest.want.SetElement(providerElement);
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest);
    int32_t hostPid = 0;
    auto ret = connectManager->UnloadUIExtensionAbility(abilityRecord, hostPid);
    EXPECT_EQ(ret, ERR_CONNECT_MANAGER_NULL_ABILITY_RECORD);
}


/**
 * @tc.name: UnPreloadUIExtensionAbilityLocked_0100
 * @tc.desc: unpreload uiextension ability with invalid id
 * @tc.type: FUNC
 */
HWTEST_F(UIExtensionAbilityManagerTest, UnPreloadUIExtensionAbilityLocked_0100, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    ASSERT_NE(connectManager, nullptr);
    int32_t extensionAbilityId = AbilityRuntime::INVALID_EXTENSION_RECORD_ID;
    auto ret = connectManager->UnPreloadUIExtensionAbilityLocked(extensionAbilityId);
    EXPECT_EQ(ret, ERR_CODE_INVALID_ID);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: ClearAllPreloadUIExtensionAbilityLocked
 * SubFunction: ClearAllPreloadUIExtensionAbilityInner
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify ClearAllPreloadUIExtensionAbilityLocked when uiExtensionAbilityRecordMgr_ is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, AAFwk_AbilityMS_ClearAllPreloadUIExtensionAbilityLocked_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    
    int res = connectManager->ClearAllPreloadUIExtensionAbilityLocked();
    EXPECT_EQ(res, ERR_NULL_OBJECT);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: ClearAllPreloadUIExtensionAbilityLocked
 * SubFunction: ClearAllPreloadUIExtensionAbilityInner
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify ClearAllPreloadUIExtensionAbilityLocked with valid uiExtensionAbilityRecordMgr_
 */
HWTEST_F(UIExtensionAbilityManagerTest, AAFwk_AbilityMS_ClearAllPreloadUIExtensionAbilityLocked_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    
    int res = connectManager->ClearAllPreloadUIExtensionAbilityLocked();
    EXPECT_EQ(res, ERR_OK);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: RegisterPreloadUIExtensionHostClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify RegisterPreloadUIExtensionHostClient when callerToken is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, AAFwk_AbilityMS_RegisterPreloadUIExtensionHostClient_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    sptr<IRemoteObject> callerToken = nullptr;
    
    int32_t res = connectManager->RegisterPreloadUIExtensionHostClient(callerToken);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: RegisterPreloadUIExtensionHostClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify RegisterPreloadUIExtensionHostClient when uiExtensionAbilityRecordMgr_ is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, AAFwk_AbilityMS_RegisterPreloadUIExtensionHostClient_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> callerToken = abilityRecord->GetToken();
    ASSERT_NE(callerToken, nullptr);
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    
    int32_t res = connectManager->RegisterPreloadUIExtensionHostClient(callerToken);
    EXPECT_EQ(res, ERR_NULL_OBJECT);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: RegisterPreloadUIExtensionHostClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify RegisterPreloadUIExtensionHostClient with valid parameters
 */
HWTEST_F(UIExtensionAbilityManagerTest, AAFwk_AbilityMS_RegisterPreloadUIExtensionHostClient_003, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> callerToken = abilityRecord->GetToken();
    ASSERT_NE(callerToken, nullptr);
    
    int32_t res = connectManager->RegisterPreloadUIExtensionHostClient(callerToken);
    EXPECT_EQ(res, ERR_OK);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: UnRegisterPreloadUIExtensionHostClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UnRegisterPreloadUIExtensionHostClient when uiExtensionAbilityRecordMgr_ is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, AAFwk_AbilityMS_UnRegisterPreloadUIExtensionHostClient_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    int32_t callerPid = 1234;
    
    int32_t res = connectManager->UnRegisterPreloadUIExtensionHostClient(callerPid);
    EXPECT_EQ(res, ERR_NULL_OBJECT);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: UnRegisterPreloadUIExtensionHostClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UnRegisterPreloadUIExtensionHostClient with DEFAULT_INVALID_VALUE
 */
HWTEST_F(UIExtensionAbilityManagerTest, AAFwk_AbilityMS_UnRegisterPreloadUIExtensionHostClient_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    int32_t callerPid = DEFAULT_INVAL_VALUE;
    
    int32_t res = connectManager->UnRegisterPreloadUIExtensionHostClient(callerPid);
    EXPECT_EQ(res, ERR_OK);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: UnRegisterPreloadUIExtensionHostClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UnRegisterPreloadUIExtensionHostClient with valid callerPid
 */
HWTEST_F(UIExtensionAbilityManagerTest, AAFwk_AbilityMS_UnRegisterPreloadUIExtensionHostClient_003, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    int32_t callerPid = 5678;
    
    int32_t res = connectManager->UnRegisterPreloadUIExtensionHostClient(callerPid);
    EXPECT_EQ(res, ERR_OK);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: UnRegisterPreloadUIExtensionHostClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UnRegisterPreloadUIExtensionHostClient
 */
HWTEST_F(UIExtensionAbilityManagerTest, AAFwk_AbilityMS_UnRegisterPreloadUIExtensionHostClient_004, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> callerToken = abilityRecord->GetToken();
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    connectManager->RegisterPreloadUIExtensionHostClient(callerToken);
    EXPECT_EQ(connectManager->uiExtensionAbilityRecordMgr_->preloadUIExtensionHostClientCallerTokens_.size(), 1);
    
    connectManager->UnRegisterPreloadUIExtensionHostClient(1);
    EXPECT_EQ(connectManager->uiExtensionAbilityRecordMgr_->preloadUIExtensionHostClientCallerTokens_.size(), 1);

    connectManager->UnRegisterPreloadUIExtensionHostClient(callerPid);
    EXPECT_EQ(connectManager->uiExtensionAbilityRecordMgr_->preloadUIExtensionHostClientCallerTokens_.size(), 0);
}

/*
* Feature: UIExtensionAbilityManager
* Function: HandleUIExtensionDied
*/
HWTEST_F(UIExtensionAbilityManagerTest, HandleUIExtensionDied_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "HandleUIExtensionDied_002 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    sptr<Token> token = serviceToken_;
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> sessionToken = abilityRecord->GetToken();
    connectManager->AddUIExtWindowDeathRecipient(sessionToken);
    connectManager->uiExtensionMap_[sessionToken] = {std::weak_ptr<BaseExtensionRecord>(), nullptr};
    EXPECT_EQ(connectManager->uiExtensionMap_.size(), 1);

    connectManager->HandleUIExtensionDied(abilityRecord);
    EXPECT_EQ(connectManager->uiExtensionMap_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "HandleUIExtensionDied_002 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: IsUIExtensionFocused
 */
HWTEST_F(UIExtensionAbilityManagerTest, IsUIExtensionFocused_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsUIExtensionFocused_001 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    uint32_t uiExtensionTokenId = 1;
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest_);
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
 * Feature: UIExtensionAbilityManager
 * Function: IsUIExtensionFocused
 */
HWTEST_F(UIExtensionAbilityManagerTest, IsUIExtensionFocused_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "IsUIExtensionFocused_002 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    uint32_t uiExtensionTokenId = 1;
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest_);
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
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionSourceToken
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionSourceToken_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_001 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    sptr<IRemoteObject> nulltoken = nullptr;
    sptr<IRemoteObject> resultToken = connectManager->GetUIExtensionSourceToken(nulltoken);
    EXPECT_EQ(resultToken, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_001 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionSourceToken
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionSourceToken_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_002 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    connectManager->uiExtensionMap_.emplace(token, std::make_pair(abilityRecord, nullptr));

    sptr<IRemoteObject> resultToken = connectManager->GetUIExtensionSourceToken(token);
    EXPECT_EQ(resultToken, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_002 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionSourceToken
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionSourceToken_007, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_002 start");
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    EXPECT_NE(connectManager, nullptr);

    sptr<SessionInfo> sessionInfo = new SessionInfo();
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(
        abilityRequest_);
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    connectManager->uiExtensionMap_.clear();
    connectManager->uiExtensionMap_.emplace(token, std::make_pair(abilityRecord, sessionInfo));

    sptr<IRemoteObject> resultToken = connectManager->GetUIExtensionSourceToken(token);
    EXPECT_EQ(resultToken, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "GetUIExtensionSourceToken_002 end");
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetActiveUIExtensionList
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions:NA
 * CaseDescription: verify the GetActiveUIExtensionList function.
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetActiveUIExtensionList_01, TestSize.Level1)
{
    int32_t pid = 1;
    std::vector<std::string> extensionList;
    auto result = GetUIExtensionAbilityManager()->GetActiveUIExtensionList(pid, extensionList);
    EXPECT_EQ(result, ERR_OK);

    std::string bundleName = "com.test.demo";
    result = GetUIExtensionAbilityManager()->GetActiveUIExtensionList(bundleName, extensionList);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: ClearAllPreloadUIExtensionAbilityLocked
 * SubFunction: ClearAllPreloadUIExtensionAbilityInner
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify ClearAllPreloadUIExtensionAbilityLocked when uiExtensionAbilityRecordMgr_ is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, ClearAllPreloadUIExtensionAbilityLocked_003, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    
    int res = connectManager->ClearAllPreloadUIExtensionAbilityLocked();
    EXPECT_EQ(res, ERR_NULL_OBJECT);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: ClearAllPreloadUIExtensionAbilityLocked
 * SubFunction: ClearAllPreloadUIExtensionAbilityInner
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify ClearAllPreloadUIExtensionAbilityLocked with valid uiExtensionAbilityRecordMgr_
 */
HWTEST_F(UIExtensionAbilityManagerTest, ClearAllPreloadUIExtensionAbilityLocked_004, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    
    int res = connectManager->ClearAllPreloadUIExtensionAbilityLocked();
    EXPECT_EQ(res, ERR_OK);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: RegisterPreloadUIExtensionHostClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify RegisterPreloadUIExtensionHostClient when callerToken is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, RegisterPreloadUIExtensionHostClient_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    sptr<IRemoteObject> callerToken = nullptr;
    
    int32_t res = connectManager->RegisterPreloadUIExtensionHostClient(callerToken);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: RegisterPreloadUIExtensionHostClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify RegisterPreloadUIExtensionHostClient when uiExtensionAbilityRecordMgr_ is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, RegisterPreloadUIExtensionHostClient_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> callerToken = abilityRecord->GetToken();
    ASSERT_NE(callerToken, nullptr);
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    
    int32_t res = connectManager->RegisterPreloadUIExtensionHostClient(callerToken);
    EXPECT_EQ(res, ERR_NULL_OBJECT);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: RegisterPreloadUIExtensionHostClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify RegisterPreloadUIExtensionHostClient with valid parameters
 */
HWTEST_F(UIExtensionAbilityManagerTest, RegisterPreloadUIExtensionHostClient_003, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> callerToken = abilityRecord->GetToken();
    ASSERT_NE(callerToken, nullptr);
    
    int32_t res = connectManager->RegisterPreloadUIExtensionHostClient(callerToken);
    EXPECT_EQ(res, ERR_OK);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: UnRegisterPreloadUIExtensionHostClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UnRegisterPreloadUIExtensionHostClient when uiExtensionAbilityRecordMgr_ is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, UnRegisterPreloadUIExtensionHostClient_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    int32_t callerPid = 1234;
    
    int32_t res = connectManager->UnRegisterPreloadUIExtensionHostClient(callerPid);
    EXPECT_EQ(res, ERR_NULL_OBJECT);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: UnRegisterPreloadUIExtensionHostClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UnRegisterPreloadUIExtensionHostClient with DEFAULT_INVALID_VALUE
 */
HWTEST_F(UIExtensionAbilityManagerTest, UnRegisterPreloadUIExtensionHostClient_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    int32_t callerPid = DEFAULT_INVAL_VALUE;
    
    int32_t res = connectManager->UnRegisterPreloadUIExtensionHostClient(callerPid);
    EXPECT_EQ(res, ERR_OK);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: UnRegisterPreloadUIExtensionHostClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UnRegisterPreloadUIExtensionHostClient with valid callerPid
 */
HWTEST_F(UIExtensionAbilityManagerTest, UnRegisterPreloadUIExtensionHostClient_003, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    int32_t callerPid = 5678;
    
    int32_t res = connectManager->UnRegisterPreloadUIExtensionHostClient(callerPid);
    EXPECT_EQ(res, ERR_OK);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: UnRegisterPreloadUIExtensionHostClient
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UnRegisterPreloadUIExtensionHostClient
 */
HWTEST_F(UIExtensionAbilityManagerTest, UnRegisterPreloadUIExtensionHostClient_004, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    std::shared_ptr<AbilityRecord> abilityRecord = serviceRecord_;
    ASSERT_NE(abilityRecord, nullptr);
    sptr<IRemoteObject> callerToken = abilityRecord->GetToken();
    int32_t callerPid = IPCSkeleton::GetCallingPid();
    connectManager->RegisterPreloadUIExtensionHostClient(callerToken);
    EXPECT_EQ(connectManager->uiExtensionAbilityRecordMgr_->preloadUIExtensionHostClientCallerTokens_.size(), 1);
    
    connectManager->UnRegisterPreloadUIExtensionHostClient(1);
    EXPECT_EQ(connectManager->uiExtensionAbilityRecordMgr_->preloadUIExtensionHostClientCallerTokens_.size(), 1);

    connectManager->UnRegisterPreloadUIExtensionHostClient(callerPid);
    EXPECT_EQ(connectManager->uiExtensionAbilityRecordMgr_->preloadUIExtensionHostClientCallerTokens_.size(), 0);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: UpdateUIExtensionBindInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UpdateUIExtensionBindInfo with null abilityRecord
 */
HWTEST_F(UIExtensionAbilityManagerTest, UpdateUIExtensionBindInfo_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    connectManager->UpdateUIExtensionBindInfo(nullptr, "testBundle", 1);
    // Should not crash
    SUCCEED();
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: UpdateUIExtensionBindInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UpdateUIExtensionBindInfo with non-UIExtension ability
 */
HWTEST_F(UIExtensionAbilityManagerTest, UpdateUIExtensionBindInfo_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    std::shared_ptr<BaseExtensionRecord> abilityRecord =
        BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest_);
    abilityRecord->abilityInfo_.extensionAbilityType = ExtensionAbilityType::SERVICE;
    
    connectManager->UpdateUIExtensionBindInfo(abilityRecord, "testBundle", 1);
    // Should not crash
    SUCCEED();
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: UpdateUIExtensionBindInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UpdateUIExtensionBindInfo with SCENEBOARD_BUNDLE_NAME
 */
HWTEST_F(UIExtensionAbilityManagerTest, UpdateUIExtensionBindInfo_003, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest_);
    abilityRecord->abilityInfo_.extensionAbilityType = ExtensionAbilityType::SYS_COMMON_UI;
    
    connectManager->UpdateUIExtensionBindInfo(abilityRecord, AbilityConfig::SCENEBOARD_BUNDLE_NAME, 1);
    // Should not allow bind process
    SUCCEED();
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetActiveUIExtensionList
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify GetActiveUIExtensionList with valid parameters
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetActiveUIExtensionList_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    
    int32_t pid = 1234;
    std::vector<std::string> extensionList;
    int32_t result = connectManager->GetActiveUIExtensionList(pid, extensionList);
    EXPECT_EQ(result, ERR_OK);
    
    std::string bundleName = "com.test.demo";
    result = connectManager->GetActiveUIExtensionList(bundleName, extensionList);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetActiveUIExtensionList
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify GetActiveUIExtensionList when uiExtensionAbilityRecordMgr_ is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetActiveUIExtensionList_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    
    int32_t pid = 1234;
    std::vector<std::string> extensionList;
    int32_t result = connectManager->GetActiveUIExtensionList(pid, extensionList);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    
    std::string bundleName = "com.test.demo";
    result = connectManager->GetActiveUIExtensionList(bundleName, extensionList);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionRootHostInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify GetUIExtensionRootHostInfo with null token
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionRootHostInfo_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    
    std::shared_ptr<AAFwk::AbilityRecord> result = connectManager->GetUIExtensionRootHostInfo(nullptr);
    EXPECT_EQ(result, nullptr);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionRootHostInfo
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify GetUIExtensionRootHostInfo when uiExtensionAbilityRecordMgr_ is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionRootHostInfo_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest_);
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    
    std::shared_ptr<AAFwk::AbilityRecord> result = connectManager->GetUIExtensionRootHostInfo(token);
    EXPECT_EQ(result, nullptr);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: AddPreloadUIExtensionRecord
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AddPreloadUIExtensionRecord with null abilityRecord
 */
HWTEST_F(UIExtensionAbilityManagerTest, AddPreloadUIExtensionRecord_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    
    int32_t result = connectManager->AddPreloadUIExtensionRecord(nullptr);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: AddPreloadUIExtensionRecord
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify AddPreloadUIExtensionRecord when uiExtensionAbilityRecordMgr_ is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, AddPreloadUIExtensionRecord_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest_);
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    
    int32_t result = connectManager->AddPreloadUIExtensionRecord(abilityRecord);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: RemoveUIExtensionBySessionInfoToken
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify RemoveUIExtensionBySessionInfoToken with null token
 */
HWTEST_F(UIExtensionAbilityManagerTest, RemoveUIExtensionBySessionInfoToken_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    
    int result = connectManager->RemoveUIExtensionBySessionInfoToken(nullptr);
    // Should not crash, just return 0
    SUCCEED();
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: RemoveUIExtensionBySessionInfoToken
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify RemoveUIExtensionBySessionInfoToken with existing token
 */
HWTEST_F(UIExtensionAbilityManagerTest, RemoveUIExtensionBySessionInfoToken_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest_);
    sptr<IRemoteObject> token = abilityRecord->GetToken();
    
    connectManager->uiExtensionMap_[token] = {std::weak_ptr<BaseExtensionRecord>(), nullptr};
    int result = connectManager->RemoveUIExtensionBySessionInfoToken(token);
    EXPECT_EQ(result, 1);
    EXPECT_TRUE(connectManager->uiExtensionMap_.empty());
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionCallerTokenList
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify GetUIExtensionCallerTokenList with null abilityRecord
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionCallerTokenList_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    
    std::list<sptr<IRemoteObject>> callerList;
    connectManager->GetUIExtensionCallerTokenList(nullptr, callerList);
    // Should not crash
    SUCCEED();
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: GetUIExtensionCallerTokenList
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify GetUIExtensionCallerTokenList when uiExtensionAbilityRecordMgr_ is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, GetUIExtensionCallerTokenList_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    std::shared_ptr<BaseExtensionRecord> abilityRecord = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest_);
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    
    std::list<sptr<IRemoteObject>> callerList;
    connectManager->GetUIExtensionCallerTokenList(abilityRecord, callerList);
    // Should not crash
    SUCCEED();
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: HandlePreloadUIExtensionSuccess
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify HandlePreloadUIExtensionSuccess when uiExtensionAbilityRecordMgr_ is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, HandlePreloadUIExtensionSuccess_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    
    connectManager->HandlePreloadUIExtensionSuccess(1234, true);
    // Should not crash
    SUCCEED();
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: IsCallerValid
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify IsCallerValid with null abilityRecord
 */
HWTEST_F(UIExtensionAbilityManagerTest, IsCallerValid_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    
    bool result = connectManager->IsCallerValid(nullptr);
    EXPECT_FALSE(result);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: IsCallerValid
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify IsCallerValid with null sessionInfo
 */
HWTEST_F(UIExtensionAbilityManagerTest, IsCallerValid_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    std::shared_ptr<BaseExtensionRecord> abilityRecord =
        BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest_);
    abilityRecord->sessionInfo_ = nullptr;
    
    bool result = connectManager->IsCallerValid(abilityRecord);
    EXPECT_FALSE(result);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: SetLastExitReason
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify SetLastExitReason with null abilityRecord
 */
HWTEST_F(UIExtensionAbilityManagerTest, SetLastExitReason_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    AbilityRequest abilityRequest;
    std::shared_ptr<BaseExtensionRecord> targetRecord = nullptr;
    
    connectManager->SetLastExitReason(abilityRequest, targetRecord);
    // Should not crash
    SUCCEED();
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: SetLastExitReason
 * SubFunction: NA
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify SetLastExitReason with non-UIExtension ability
 */
HWTEST_F(UIExtensionAbilityManagerTest, SetLastExitReason_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.extensionAbilityType = ExtensionAbilityType::SERVICE;
    std::shared_ptr<BaseExtensionRecord> targetRecord = BaseExtensionRecord::CreateBaseExtensionRecord(abilityRequest);
    
    connectManager->SetLastExitReason(abilityRequest, targetRecord);
    // Should not set exit reason for non-UIExtension
    SUCCEED();
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: UnPreloadUIExtensionAbilityLocked
 * SubFunction: UnPreloadUIExtensionAbilityInner
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UnPreloadUIExtensionAbilityLocked with invalid extensionAbilityId
 */
HWTEST_F(UIExtensionAbilityManagerTest, UnPreloadUIExtensionAbilityLocked_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    int32_t extensionAbilityId = AbilityRuntime::INVALID_EXTENSION_RECORD_ID;
    
    int res = connectManager->UnPreloadUIExtensionAbilityLocked(extensionAbilityId);
    EXPECT_EQ(res, ERR_CODE_INVALID_ID);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: UnPreloadUIExtensionAbilityLocked
 * SubFunction: UnPreloadUIExtensionAbilityInner
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify UnPreloadUIExtensionAbilityLocked when uiExtensionAbilityRecordMgr_ is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, UnPreloadUIExtensionAbilityLocked_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    int32_t extensionAbilityId = 1234;
    
    int res = connectManager->UnPreloadUIExtensionAbilityLocked(extensionAbilityId);
    EXPECT_EQ(res, ERR_NULL_OBJECT);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: PreloadUIExtensionAbilityLocked
 * SubFunction: PreloadUIExtensionAbilityInner
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify PreloadUIExtensionAbilityLocked with non-UIExtension type
 */
HWTEST_F(UIExtensionAbilityManagerTest, PreloadUIExtensionAbilityLocked_001, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.extensionAbilityType = ExtensionAbilityType::SERVICE;
    std::string hostBundleName = "testBundle";
    int32_t hostPid = 1234;
    
    int res = connectManager->PreloadUIExtensionAbilityLocked(abilityRequest, hostBundleName, hostPid);
    EXPECT_EQ(res, ERR_WRONG_INTERFACE_CALL);
}

/*
 * Feature: UIExtensionAbilityManager
 * Function: PreloadUIExtensionAbilityLocked
 * SubFunction: PreloadUIExtensionAbilityInner
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Verify PreloadUIExtensionAbilityLocked when uiExtensionAbilityRecordMgr_ is nullptr
 */
HWTEST_F(UIExtensionAbilityManagerTest, PreloadUIExtensionAbilityLocked_002, TestSize.Level1)
{
    std::shared_ptr<UIExtensionAbilityManager> connectManager = std::make_shared<UIExtensionAbilityManager>(0);
    connectManager->uiExtensionAbilityRecordMgr_ = nullptr;
    AbilityRequest abilityRequest;
    abilityRequest.abilityInfo.extensionAbilityType = ExtensionAbilityType::SYS_COMMON_UI;
    std::string hostBundleName = "testBundle";
    int32_t hostPid = 1234;
    
    int res = connectManager->PreloadUIExtensionAbilityLocked(abilityRequest, hostBundleName, hostPid);
    EXPECT_EQ(res, ERR_NULL_OBJECT);
}
}  // namespace AAFwk
}  // namespace OHOS
