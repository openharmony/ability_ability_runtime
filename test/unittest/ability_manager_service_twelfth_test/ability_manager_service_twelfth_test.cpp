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

#include "mock_ipc_skeleton.h"
#include "mock_permission_verification.h"
#include "mock_my_flag.h"
#include "mock_ability_connect_callback.h"
#include "ability_manager_service.h"
#include "modal_system_dialog/modal_system_dialog_ui_extension.h"
#include "utils/modal_system_dialog_util.h"
#include "remote_on_listener_stub_mock.h"
#include "ability_connect_manager.h"
#include "hilog_tag_wrapper.h"
#include "ability_bundle_event_callback.h"
#include "session/host/include/session.h"
#include "system_ability_definition.h"
#include "ability_util.h"
#include "connection_data.h"
#include "mock_scene_board_judgement.h"
#include "mock_test_object.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::AppExecFwk::AbilityType;
using OHOS::AppExecFwk::ExtensionAbilityType;

constexpr char DEVELOPER_MODE_STATE[] = "const.security.developermode.state";
constexpr const char* DEBUG_APP = "debugApp";
constexpr const char* START_ABILITY_TYPE = "ABILITY_INNER_START_WITH_ACCOUNT";
constexpr int32_t ONE = 1;
constexpr int32_t TWO = 2;
constexpr int32_t FOUNDATION_UID = 5523;
constexpr int32_t RESOURCE_SCHEDULE_UID = 1096;
constexpr int32_t UPDATE_CONFIG_FLAG_COVER = 1;
constexpr int32_t UPDATE_CONFIG_FLAG_APPEND = 2;

namespace OHOS {
namespace AAFwk {
class AbilityManagerServiceTwelfthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    std::shared_ptr<AbilityRecord> MockAbilityRecord(AbilityType);
    sptr<Token> MockToken(AbilityType);
    AbilityRequest GenerateAbilityRequest(const std::string& deviceName, const std::string& abilityName,
        const std::string& appName, const std::string& bundleName, const std::string& moduleName);

    std::shared_ptr<AbilityRecord> abilityRecord;
    sptr<SessionInfo> MockSessionInfo(int32_t persistentId);
};

void AbilityManagerServiceTwelfthTest::SetUpTestCase() {}

void AbilityManagerServiceTwelfthTest::TearDownTestCase() {}

void AbilityManagerServiceTwelfthTest::SetUp() {}

void AbilityManagerServiceTwelfthTest::TearDown() {}

std::shared_ptr<AbilityRecord> AbilityManagerServiceTwelfthTest::MockAbilityRecord(AbilityType abilityType)
{
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.test.demo";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = abilityType;
    return AbilityRecord::CreateAbilityRecord(abilityRequest);
}

sptr<Token> AbilityManagerServiceTwelfthTest::MockToken(AbilityType abilityType)
{
    abilityRecord = MockAbilityRecord(abilityType);
    if (!abilityRecord) {
        return nullptr;
    }
    return abilityRecord->GetToken();
}

sptr<SessionInfo> AbilityManagerServiceTwelfthTest::MockSessionInfo(int32_t persistentId)
{
    sptr<SessionInfo> sessionInfo = new (std::nothrow) SessionInfo();
    if (!sessionInfo) {
        TAG_LOGE(AAFwkTag::TEST, "sessionInfo is nullptr");
        return nullptr;
    }
    sessionInfo->persistentId = persistentId;
    return sessionInfo;
}

AbilityRequest AbilityManagerServiceTwelfthTest::GenerateAbilityRequest(const std::string& deviceName,
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

/*
 * Feature: AbilityManagerService
 * Function: CloseUIExtensionAbilityBySCB
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CloseUIExtensionAbilityBySCB
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, CloseUIExtensionAbilityBySCB_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CloseUIExtensionAbilityBySCB_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled())
        .WillRepeatedly(Return(true));
    EXPECT_EQ(abilityMs_->CloseUIExtensionAbilityBySCB(callerToken), ERR_INVALID_VALUE);

    callerToken = MockToken(AbilityType::PAGE);
    EXPECT_EQ(abilityMs_->CloseUIExtensionAbilityBySCB(callerToken), ERR_PERMISSION_DENIED);

    abilityMs_->subManagersHelper_ = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    IPCSkeleton::SetCallingUid(BASE_USER_RANGE);
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(ONE);
    connectManager->sceneBoardTokenId_ = ONE;
    abilityMs_->subManagersHelper_->connectManagers_.insert(std::make_pair(ONE, connectManager));
    IPCSkeleton::SetCallingTokenID(ONE);
    EXPECT_EQ(abilityMs_->CloseUIExtensionAbilityBySCB(callerToken), ERR_INVALID_VALUE);

    AbilityRequest abilityRequest{};
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    callerToken = abilityRecord->GetToken();
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    uiAbilityLifecycleManager->sessionAbilityMap_.emplace(TWO, abilityRecord);
    abilityMs_->subManagersHelper_->uiAbilityManagers_.emplace(TWO, uiAbilityLifecycleManager);
    EXPECT_EQ(abilityMs_->CloseUIExtensionAbilityBySCB(callerToken), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CloseUIExtensionAbilityBySCB_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: CloseUIExtensionAbilityBySCB
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CloseUIExtensionAbilityBySCB
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, CloseUIExtensionAbilityBySCB_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CloseUIExtensionAbilityBySCB_002 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled())
        .WillRepeatedly(Return(true));
    abilityMs_->subManagersHelper_ = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    IPCSkeleton::SetCallingUid(BASE_USER_RANGE);
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(ONE);
    connectManager->sceneBoardTokenId_ = ONE;
    abilityMs_->subManagersHelper_->connectManagers_.insert(std::make_pair(ONE, connectManager));
    IPCSkeleton::SetCallingTokenID(ONE);

    AbilityRequest abilityRequest{};
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SHARE;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    callerToken = abilityRecord->GetToken();
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    uiAbilityLifecycleManager->sessionAbilityMap_.emplace(TWO, abilityRecord);
    abilityMs_->subManagersHelper_->uiAbilityManagers_.emplace(TWO, uiAbilityLifecycleManager);
    EXPECT_EQ(abilityMs_->CloseUIExtensionAbilityBySCB(callerToken), ERR_INVALID_VALUE);

    auto sessionInfo = new SessionInfo();
    abilityRecord->SetSessionInfo(sessionInfo);
    EXPECT_EQ(abilityMs_->CloseUIExtensionAbilityBySCB(callerToken), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CloseUIExtensionAbilityBySCB_002 end");
}

/*
 * Feature: AbilityManagerService
 * Function: CloseUIAbilityBySCB
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CloseUIAbilityBySCB
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, CloseUIAbilityBySCB_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CloseUIAbilityBySCB_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    Rosen::SessionInfo info;
    sptr<SessionInfo> sessionInfo = nullptr;
    bool isUserRequestedExit = true;
    uint32_t sceneFlag = ONE;

    EXPECT_EQ(abilityMs_->CloseUIAbilityBySCB(sessionInfo, isUserRequestedExit, sceneFlag), ERR_INVALID_VALUE);

    sessionInfo = new SessionInfo();
    sessionInfo->callerToken = MockToken(AbilityType::PAGE);
    EXPECT_EQ(abilityMs_->CloseUIAbilityBySCB(sessionInfo, isUserRequestedExit, sceneFlag), ERR_INVALID_VALUE);

    sessionInfo->sessionToken = MockToken(AbilityType::PAGE);
    EXPECT_EQ(abilityMs_->CloseUIAbilityBySCB(sessionInfo, isUserRequestedExit, sceneFlag), ERR_WRONG_INTERFACE_CALL);

    abilityMs_->subManagersHelper_ = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    IPCSkeleton::SetCallingUid(BASE_USER_RANGE);
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(ONE);
    connectManager->sceneBoardTokenId_ = ONE;
    abilityMs_->subManagersHelper_->connectManagers_.insert(std::make_pair(ONE, connectManager));
    IPCSkeleton::SetCallingTokenID(ONE);
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    abilityMs_->subManagersHelper_->uiAbilityManagers_.emplace(ONE, uiAbilityLifecycleManager);

    EXPECT_EQ(abilityMs_->CloseUIAbilityBySCB(sessionInfo, isUserRequestedExit, sceneFlag), ERR_INVALID_VALUE);

    sessionInfo->isClearSession = true;
    AbilityRequest abilityRequest{};
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    abilityRecord->Init();
    sessionInfo->persistentId = TWO;
    uiAbilityLifecycleManager->sessionAbilityMap_.emplace(TWO, abilityRecord);
    EXPECT_EQ(abilityMs_->CloseUIAbilityBySCB(sessionInfo, isUserRequestedExit, sceneFlag), ERR_INVALID_VALUE);

    isUserRequestedExit = false;
    EXPECT_EQ(abilityMs_->CloseUIAbilityBySCB(sessionInfo, isUserRequestedExit, sceneFlag), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CloseUIAbilityBySCB_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: MinimizeUIExtensionAbility
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService MinimizeUIExtensionAbility
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, MinimizeUIExtensionAbility_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest MinimizeUIExtensionAbility_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    sptr<SessionInfo> extensionSessionInfo = nullptr;
    bool fromUser = false;

    EXPECT_EQ(abilityMs_->MinimizeUIExtensionAbility(extensionSessionInfo, fromUser), ERR_INVALID_VALUE);

    extensionSessionInfo = new SessionInfo();
    Rosen::SessionInfo info;
    extensionSessionInfo->sessionToken = new Rosen::Session(info);
    extensionSessionInfo->callerToken = MockToken(AbilityType::PAGE);
    EXPECT_EQ(abilityMs_->MinimizeUIExtensionAbility(extensionSessionInfo, fromUser), CHECK_PERMISSION_FAILED);

    AbilityRequest abilityRequest{};
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.accessTokenId = ONE;
    abilityRequest.appInfo = appInfo;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    extensionSessionInfo->callerToken = abilityRecord->GetToken();
    IPCSkeleton::SetCallingTokenID(ONE);
    abilityMs_->subManagersHelper_ = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    IPCSkeleton::SetCallingUid(BASE_USER_RANGE);
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(ONE);
    connectManager->sceneBoardTokenId_ = ONE;
    connectManager->uiExtensionMap_[extensionSessionInfo->sessionToken] =
        std::make_pair(abilityRecord, extensionSessionInfo);
    abilityMs_->subManagersHelper_->connectManagers_.insert(std::make_pair(ONE, connectManager));
    EXPECT_EQ(abilityMs_->MinimizeUIExtensionAbility(extensionSessionInfo, fromUser), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest MinimizeUIExtensionAbility_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: MinimizeUIExtensionAbility
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService MinimizeUIExtensionAbility
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, MinimizeUIExtensionAbility_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest MinimizeUIExtensionAbility_002 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    sptr<SessionInfo> extensionSessionInfo = nullptr;
    bool fromUser = false;
    extensionSessionInfo = new SessionInfo();
    Rosen::SessionInfo info;
    extensionSessionInfo->sessionToken = new Rosen::Session(info);
    extensionSessionInfo->callerToken = MockToken(AbilityType::PAGE);

    AbilityRequest abilityRequest{};
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::SHARE;
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.accessTokenId = ONE;
    abilityRequest.appInfo = appInfo;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    extensionSessionInfo->callerToken = abilityRecord->GetToken();
    IPCSkeleton::SetCallingTokenID(ONE);
    abilityMs_->subManagersHelper_ = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    IPCSkeleton::SetCallingUid(BASE_USER_RANGE);
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(ONE);
    connectManager->sceneBoardTokenId_ = ONE;
    connectManager->uiExtensionMap_[extensionSessionInfo->sessionToken] =
        std::make_pair(abilityRecord, extensionSessionInfo);
    abilityMs_->subManagersHelper_->connectManagers_.insert(std::make_pair(ONE, connectManager));

    EXPECT_EQ(abilityMs_->MinimizeUIExtensionAbility(extensionSessionInfo, fromUser), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest MinimizeUIExtensionAbility_002 end");
}

/*
 * Feature: AbilityManagerService
 * Function: DisconnectAbility
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DisconnectAbility
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, DisconnectAbility_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest DisconnectAbility_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    sptr<IAbilityConnection> connect = nullptr;

    EXPECT_EQ(abilityMs_->DisconnectAbility(connect), ERR_INVALID_VALUE);

    connect = new AbilityConnectCallback();
    EXPECT_EQ(abilityMs_->DisconnectAbility(connect), ERR_NO_INIT);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest DisconnectAbility_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: DisconnectLocalAbility
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DisconnectLocalAbility
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, DisconnectLocalAbility_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTestDisconnectLocalAbility_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    sptr<IAbilityConnection> connect = nullptr;

    EXPECT_EQ(abilityMs_->DisconnectLocalAbility(connect), ERR_NO_INIT);

    abilityMs_->subManagersHelper_ = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    IPCSkeleton::SetCallingUid(BASE_USER_RANGE);
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(ONE);
    connectManager->sceneBoardTokenId_ = ONE;
    abilityMs_->subManagersHelper_->currentConnectManager_ = connectManager;
    IPCSkeleton::SetCallingTokenID(ONE);
    connect = new AbilityConnectCallback();
    std::shared_ptr<AbilityConnectManager> connectManager2 = std::make_shared<AbilityConnectManager>(TWO);
    connectManager2->sceneBoardTokenId_ = TWO;
    abilityMs_->subManagersHelper_->connectManagers_.insert(std::make_pair(0, connectManager2));
    EXPECT_EQ(abilityMs_->DisconnectLocalAbility(connect), ERR_NO_INIT);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest DisconnectLocalAbility_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: GetConnectionData
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetConnectionData
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, GetConnectionData_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfth GetConnectionData_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    std::vector<AbilityRuntime::ConnectionData> connectionData;

    EXPECT_EQ(abilityMs_->GetConnectionData(connectionData), ERR_OK);

    MyFlag::flag_ = false;
    EXPECT_EQ(abilityMs_->GetConnectionData(connectionData), CHECK_PERMISSION_FAILED);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest GetConnectionData_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: RegisterOffListener
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService RegisterOffListener
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, RegisterOffListener_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfth RegisterOffListener_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    std::string type = "";
    sptr<IRemoteOnListener> listener = nullptr;
    EXPECT_EQ(abilityMs_->RegisterOffListener(type, listener), ERR_INVALID_VALUE);

    listener = new RemoteOnListenerStubMock();
    MyFlag::flag_ = true;
    EXPECT_EQ(abilityMs_->RegisterOffListener(type, listener), INVALID_PARAMETERS_ERR);

    MyFlag::flag_ = false;
    EXPECT_EQ(abilityMs_->RegisterOffListener(type, listener), CHECK_PERMISSION_FAILED);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest RegisterOffListener_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: GetUserScreenUnlockCallback
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetUserScreenUnlockCallback
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, GetUserScreenUnlockCallback_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest GetUserScreenUnlockCallback_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    abilityMs_->UnSubscribeScreenUnlockedEvent();
    abilityMs_->interceptorExecuter_ = std::make_shared<AbilityInterceptorExecuter>();
    abilityMs_->RemoveScreenUnlockInterceptor();
    int32_t retryCount = 1;
    abilityMs_->RetrySubscribeScreenUnlockedEvent(retryCount);
    Want want;
    AbilityRequest abilityRequest;
    abilityMs_->RemoveUnauthorizedLaunchReasonMessage(want, abilityRequest, nullptr);
    std::string testText = "AbilityManagerServiceTwelfthTest";
    want.SetParam(Want::PARM_LAUNCH_REASON_MESSAGE, testText);
    abilityMs_->RemoveUnauthorizedLaunchReasonMessage(want, abilityRequest, nullptr);
    auto ret = abilityMs_->GetUserScreenUnlockCallback();
    if (ret) {
        ret();
        abilityMs_.reset();
        ret();
    }
    EXPECT_EQ(static_cast<bool>(ret), true);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest GetUserScreenUnlockCallback_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: StartAbilityJust
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService StartAbilityJust
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, StartAbilityJust_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest StartAbilityJust_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    AbilityRequest abilityRequest;
    int32_t validUserId = 0;
    auto retCode = abilityMs_->StartAbilityJust(abilityRequest, validUserId);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest StartAbilityJust_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: StartUser
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService StartUser
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, StartUser_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest StartUser_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    int userId = 0;
    sptr<IUserCallback> callback = new MockIUserCallback();
    bool isAppRecovery = false;
    auto retCode = abilityMs_->StartUser(userId, callback, isAppRecovery);
    EXPECT_EQ(retCode, CHECK_PERMISSION_FAILED);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest StartUser_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: StartAbilityByCallWithErrMsg
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService StartAbilityByCallWithErrMsg
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, StartAbilityByCallWithErrMsg_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest StartAbilityByCallWithErrMsg_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    Want want;
    int32_t accountId = -1;
    std::string errMsg;
    auto retCode = abilityMs_->StartAbilityByCallWithErrMsg(want, nullptr, nullptr, accountId, errMsg);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    sptr<IAbilityConnection> connect = new MockIAbilityConnection();
    retCode = abilityMs_->StartAbilityByCallWithErrMsg(want, connect, nullptr, accountId, errMsg);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest StartAbilityByCallWithErrMsg_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: TerminateUIExtensionAbility
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService TerminateUIExtensionAbility
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, TerminateUIExtensionAbility_001, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    sptr<SessionInfo> extensionSessionInfo = new SessionInfo();
    Rosen::SessionInfo info;
    extensionSessionInfo->sessionToken = new Rosen::Session(info);
    extensionSessionInfo->persistentId = TWO;
    AbilityRequest abilityRequest{};
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.accessTokenId = ONE;
    abilityRequest.appInfo = appInfo;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    extensionSessionInfo->callerToken = abilityRecord->GetToken();
    IPCSkeleton::SetCallingTokenID(ONE);
    abilityMs_->subManagersHelper_ = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    IPCSkeleton::SetCallingUid(BASE_USER_RANGE);
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(ONE);
    connectManager->sceneBoardTokenId_ = ONE;
    connectManager->uiExtensionMap_[extensionSessionInfo->sessionToken] =
        std::make_pair(abilityRecord, extensionSessionInfo);
    abilityRecord->SetSessionInfo(extensionSessionInfo);
    connectManager->serviceMap_.insert(std::make_pair("test", abilityRecord));
    abilityMs_->subManagersHelper_->connectManagers_.insert(std::make_pair(ONE, connectManager));
    EXPECT_EQ(abilityMs_->TerminateUIExtensionAbility(extensionSessionInfo), ERR_INVALID_VALUE);
}

/*
 * Feature: AbilityManagerService
 * Name: IsSceneBoardReady_001
 * Function: IsSceneBoardReady
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsSceneBoardReady
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, IsSceneBoardReady_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest IsSceneBoardReady_001 start");
    int32_t userId = -1;
    auto abilityMs = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs, nullptr);
    abilityMs->userController_ = std::make_shared<UserController>();
    EXPECT_NE(abilityMs->userController_, nullptr);
    abilityMs->subManagersHelper_ = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(abilityMs->subManagersHelper_, nullptr);
    bool result = abilityMs->IsSceneBoardReady(userId);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest IsSceneBoardReady_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: IsSceneBoardReady_002
 * Function: IsSceneBoardReady
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsSceneBoardReady
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, IsSceneBoardReady_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest IsSceneBoardReady_002 start");
    int32_t userId = 100;
    auto abilityMs = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs, nullptr);
    abilityMs->userController_ = nullptr;
    abilityMs->subManagersHelper_ = nullptr;
    bool result = abilityMs->IsSceneBoardReady(userId);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest IsSceneBoardReady_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: PrepareTerminateAbilityBySCB_001
 * Function: PrepareTerminateAbilityBySCB
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService PrepareTerminateAbilityBySCB
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, PrepareTerminateAbilityBySCB_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest PrepareTerminateAbilityBySCB_001 start");
    bool isTerminate = false;
    auto abilityMs = std::make_shared<AbilityManagerService>();
    sptr<SessionInfo> sessionInfo = MockSessionInfo(1);
    sessionInfo->sessionToken = MockToken(AbilityType::PAGE);
    int result = abilityMs->PrepareTerminateAbilityBySCB(sessionInfo, isTerminate);
    EXPECT_EQ(result, ERR_WRONG_INTERFACE_CALL);
    EXPECT_FALSE(isTerminate);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest PrepareTerminateAbilityBySCB_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: PrepareTerminateAbilityBySCB_002
 * Function: PrepareTerminateAbilityBySCB
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService PrepareTerminateAbilityBySCB
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, PrepareTerminateAbilityBySCB_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest PrepareTerminateAbilityBySCB_002 start");
    bool isTerminate = false;
    auto abilityMs = std::make_shared<AbilityManagerService>();
    sptr<SessionInfo> sessionInfo = nullptr;
    int result = abilityMs->PrepareTerminateAbilityBySCB(sessionInfo, isTerminate);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    EXPECT_FALSE(isTerminate);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest PrepareTerminateAbilityBySCB_002 end");
}

/*
 * Feature: AbilityManagerService
 * Function: OnStartSpecifiedAbilityTimeoutResponse
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService OnStartSpecifiedAbilityTimeoutResponse
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, OnStartSpecifiedAbilityTimeoutResponse_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest OnStartSpecifiedAbilityTimeoutResponse_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    int32_t requestId = 101;
    abilityMs->subManagersHelper_ = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(abilityMs->subManagersHelper_, nullptr);
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled())
        .Times(AnyNumber())
        .WillRepeatedly(Return(true));
    abilityMs->OnStartSpecifiedAbilityTimeoutResponse(requestId);
    auto manager = abilityMs->GetCurrentUIAbilityManager();
    EXPECT_EQ(manager, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest OnStartSpecifiedAbilityTimeoutResponse_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: OnStartSpecifiedAbilityTimeoutResponse
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService OnStartSpecifiedAbilityTimeoutResponse
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, OnStartSpecifiedAbilityTimeoutResponse_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest OnStartSpecifiedAbilityTimeoutResponse_002 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    int32_t requestId = 101;
    abilityMs->OnStartSpecifiedAbilityTimeoutResponse(requestId);
    auto manager = abilityMs->GetCurrentUIAbilityManager();
    EXPECT_EQ(manager, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest OnStartSpecifiedAbilityTimeoutResponse_002 end");
}

/*
 * Feature: AbilityManagerService
 * Function: UpdateAssociateConfigList
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService UpdateAssociateConfigList
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, UpdateAssociateConfigList_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest UpdateAssociateConfigList_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    IPCSkeleton::SetCallingUid(BASE_USER_RANGE);
    std::map<std::string, std::list<std::string>> configs;
    std::list<std::string> exportConfigs;
    int32_t flag = 0;
    int32_t result = abilityMs->UpdateAssociateConfigList(configs, exportConfigs, flag);
    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest UpdateAssociateConfigList_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: UpdateAssociateConfigList
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService UpdateAssociateConfigList
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, UpdateAssociateConfigList_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest UpdateAssociateConfigList_002 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    IPCSkeleton::SetCallingUid(RESOURCE_SCHEDULE_UID);
    std::map<std::string, std::list<std::string>> configs1 = {
        {"caller1", {"callee1/ability1", "callee2/ability2"}},
        {"caller2", {"callee3/ability3"}}
    };
    std::list<std::string> exportConfigs1 = {"callee4/ability4", "callee5/ability5"};
    int32_t flag1 = UPDATE_CONFIG_FLAG_COVER;
    int32_t result1 = abilityMs->UpdateAssociateConfigList(configs1, exportConfigs1, flag1);
    EXPECT_EQ(result1, ERR_OK);
    EXPECT_TRUE(abilityMs->IsInWhiteList("caller1", "callee1", "ability1"));
    EXPECT_TRUE(abilityMs->IsInWhiteList("caller2", "callee3", "ability3"));
    EXPECT_TRUE(abilityMs->IsInWhiteList("caller1", "callee2", "ability2"));
    EXPECT_TRUE(abilityMs->IsInWhiteList("caller2", "callee3", "ability3"));
    EXPECT_TRUE(abilityMs->IsInWhiteList("callerX", "callee4", "ability4"));

    std::map<std::string, std::list<std::string>> configs2 = {
        {"caller1", {"callee6/ability6"}},
        {"caller3", {"callee7/ability7"}}
    };
    std::list<std::string> exportConfigs2 = {"callee8/ability8"};
    int32_t flag2 = UPDATE_CONFIG_FLAG_APPEND;
    int32_t result2 = abilityMs->UpdateAssociateConfigList(configs2, exportConfigs2, flag2);
    EXPECT_EQ(result2, ERR_OK);
    EXPECT_TRUE(abilityMs->IsInWhiteList("caller1", "callee6", "ability6"));
    EXPECT_TRUE(abilityMs->IsInWhiteList("caller3", "callee7", "ability7"));
    EXPECT_TRUE(abilityMs->IsInWhiteList("callerX", "callee8", "ability8"));

    std::map<std::string, std::list<std::string>> configs3;
    std::list<std::string> exportConfigs3;
    int32_t flag3 = UPDATE_CONFIG_FLAG_APPEND;
    int32_t result3 = abilityMs->UpdateAssociateConfigList(configs3, exportConfigs3, flag3);
    EXPECT_EQ(result3, ERR_OK);
    EXPECT_TRUE(abilityMs->IsInWhiteList("caller1", "callee6", "ability6"));
    EXPECT_TRUE(abilityMs->IsInWhiteList("caller3", "callee7", "ability7"));
    EXPECT_TRUE(abilityMs->IsInWhiteList("callerX", "callee8", "ability8"));
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest UpdateAssociateConfigList_002 end");
}

/*
 * Feature: AbilityManagerService
 * Function: UpdateAssociateConfigList
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService UpdateAssociateConfigList
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, UpdateAssociateConfigList_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest UpdateAssociateConfigList_003 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    IPCSkeleton::SetCallingUid(RESOURCE_SCHEDULE_UID);
    std::map<std::string, std::list<std::string>> configs = {
        {"caller1", {"callee1/ability1"}}
    };
    std::list<std::string> exportConfigs = {"callee2/ability2"};
    int32_t invalidFlag = 999;
    int32_t result = abilityMs->UpdateAssociateConfigList(configs, exportConfigs, invalidFlag);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_FALSE(abilityMs->IsInWhiteList("caller1", "callee1", "ability1"));
    EXPECT_FALSE(abilityMs->IsInWhiteList("callerX", "callee2", "ability2"));
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest UpdateAssociateConfigList_003 end");
}

/*
 * Feature: AbilityManagerService
 * Function: IsAppSelfCalled
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsAppSelfCalled
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, IsAppSelfCalled_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest IsAppSelfCalled_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    AbilityRequest abilityRequest{};
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    AppExecFwk::ApplicationInfo appInfo;
    appInfo.accessTokenId = ONE;
    abilityRequest.appInfo = appInfo;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    bool result = abilityMs->IsAppSelfCalled(abilityRecord);
    EXPECT_TRUE(result);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest IsAppSelfCalled_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: IsAppSelfCalled
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsAppSelfCalled
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, IsAppSelfCalled_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest IsAppSelfCalled_002 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    std::shared_ptr<AbilityRecord> abilityRecord = nullptr;
    bool result = abilityMs->IsAppSelfCalled(abilityRecord);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest IsAppSelfCalled_002 end");
}

/*
 * Feature: AbilityManagerService
 * Function: CheckProcessIsBackground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckProcessIsBackground
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, CheckProcessIsBackground_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CheckProcessIsBackground_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    int32_t pid = 1234;
    AbilityState currentState = AbilityState::BACKGROUND;
    abilityMs->windowVisibleList_.insert(pid);
    bool result = abilityMs->CheckProcessIsBackground(pid, currentState);
    ASSERT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CheckProcessIsBackground_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: CheckProcessIsBackground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckProcessIsBackground
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, CheckProcessIsBackground_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CheckProcessIsBackground_002 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    int32_t pid = 1234;
    AbilityState currentState = AbilityState::BACKGROUND;
    abilityMs->windowVisibleList_.clear();
    bool result = abilityMs->CheckProcessIsBackground(pid, currentState);
    ASSERT_TRUE(result);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CheckProcessIsBackground_002 end");
}

/*
 * Feature: AbilityManagerService
 * Function: CheckProcessIsBackground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckProcessIsBackground
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, CheckProcessIsBackground_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CheckProcessIsBackground_003 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    int32_t pid = 1234;
    AbilityState currentState = AbilityState::FOREGROUND;
    abilityMs->windowVisibleList_.insert(pid);
    bool result = abilityMs->CheckProcessIsBackground(pid, currentState);
    ASSERT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CheckProcessIsBackground_003 end");
}

/*
 * Feature: AbilityManagerService
 * Function: CheckProcessIsBackground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckProcessIsBackground
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, CheckProcessIsBackground_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CheckProcessIsBackground_004 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    int32_t pid = 1234;
    AbilityState currentState = AbilityState::FOREGROUND;
    abilityMs->windowVisibleList_.erase(pid);
    bool result = abilityMs->CheckProcessIsBackground(pid, currentState);
    ASSERT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CheckProcessIsBackground_004 end");
}

/*
 * Feature: AbilityManagerService
 * Function: CleanUIAbilityBySCB
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CleanUIAbilityBySCB
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, CleanUIAbilityBySCB_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CleanUIAbilityBySCB_001 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    sptr<SessionInfo> sessionInfo = nullptr;
    uint32_t sceneFlag = 0;
    bool isUserRequestedExit = false;
    int32_t result = abilityMs->CleanUIAbilityBySCB(sessionInfo, isUserRequestedExit, sceneFlag);
    ASSERT_EQ(result, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CleanUIAbilityBySCB_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: CleanUIAbilityBySCB
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CleanUIAbilityBySCB
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, CleanUIAbilityBySCB_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CleanUIAbilityBySCB_002 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    sptr<SessionInfo> sessionInfo = new SessionInfo();
    sessionInfo->sessionToken = nullptr;
    uint32_t sceneFlag = 0;
    bool isUserRequestedExit = false;
    int32_t result = abilityMs->CleanUIAbilityBySCB(sessionInfo, isUserRequestedExit, sceneFlag);
    ASSERT_EQ(result, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CleanUIAbilityBySCB_002 end");
}

/*
 * Feature: AbilityManagerService
 * Function: CleanUIAbilityBySCB
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CleanUIAbilityBySCB
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, CleanUIAbilityBySCB_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CleanUIAbilityBySCB_003 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    Rosen::SessionInfo info;
    sptr<SessionInfo> sessionInfo = new SessionInfo();
    sessionInfo->sessionToken = new Rosen::Session(info);
    uint32_t sceneFlag = 0;
    bool isUserRequestedExit = false;
    int32_t result = abilityMs->CleanUIAbilityBySCB(sessionInfo, isUserRequestedExit, sceneFlag);
    ASSERT_EQ(result, ERR_WRONG_INTERFACE_CALL);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CleanUIAbilityBySCB_003 end");
}

/*
 * Feature: AbilityManagerService
 * Function: CleanUIAbilityBySCB
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CleanUIAbilityBySCB
 */
HWTEST_F(AbilityManagerServiceTwelfthTest, CleanUIAbilityBySCB_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CleanUIAbilityBySCB_004 start");
    auto abilityMs = std::make_shared<AbilityManagerService>();
    sptr<SessionInfo> sessionInfo = new SessionInfo();
    Rosen::SessionInfo info;
    sessionInfo->sessionToken = new Rosen::Session(info);
    sessionInfo->persistentId = 99999;
    uint32_t sceneFlag = 1;
    bool isUserRequestedExit = false;
    auto uiAbilityManager = abilityMs->GetCurrentUIAbilityManager();
    int32_t result = abilityMs->CleanUIAbilityBySCB(sessionInfo, isUserRequestedExit, sceneFlag);
    ASSERT_EQ(result, ERR_WRONG_INTERFACE_CALL);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceTwelfthTest CleanUIAbilityBySCB_004 end");
}
} // namespace AAFwk
} // namespace OHOS
