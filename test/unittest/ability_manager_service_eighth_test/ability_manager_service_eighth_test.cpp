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
#include <sstream>

#include "ability_manager_errors.h"
#include "ability_manager_service.h"
#include "hilog_tag_wrapper.h"
#include "process_options.h"
#include "ipc_skeleton.h"
#include "mock_parameters.h"
#include "mock_scene_board_judgement.h"
#include "start_ability_handler.h"
#include "session/host/include/session.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::AppExecFwk::AbilityType;
using OHOS::AppExecFwk::ExtensionAbilityType;
namespace OHOS {
namespace AAFwk {
namespace {
constexpr int32_t ACCOUNT_MGR_SERVICE_UID = 3058;
constexpr int32_t TEST_UID = 1000;
constexpr char PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED[] = "const.product.enterprisefeature.setting.enabled";
constexpr char PRODUCT_APPBOOT_SETTING_ENABLED[] = "const.product.appboot.setting.enabled";
constexpr int32_t FOUNDATION_UID = 5523;
constexpr uint32_t TEST_FLAG_ABILITY_CONTINUATION = 0x00000008;
constexpr int32_t TEST_U0_USER_ID = 0;
constexpr int32_t ONE = 1;
constexpr int32_t TWO = 2;
constexpr uint32_t TEST_VALUE_ONE = 1;
const std::string TEST_STRING_VALUE_1 = "1";
const std::string TEST_CREATE_FILE = "ohos.want.action.CREATE_FILE";
const std::string TEST_BUNDLE_NAME = "com.example.test";
const std::string TEST_ABILITY_NAME = "com.example.test.MainAbility";
const std::string TEST_MODULE_NAME = "entry";
const std::string TEST_DEVICEID = "deviceId";
const std::string TEST_SESSION_ID_KEY = "1000";
const std::string TEST_SESSION_ID_VALUE = "10000";
} // namespace

class MockIUserCallback : public IUserCallback {
public:
    MockIUserCallback() = default;
    virtual ~MockIUserCallback() = default;

    void OnStopUserDone(int userId, int errcode) override
    {}
    void OnStartUserDone(int userId, int errcode) override
    {}

    void OnLogoutUserDone(int userId, int errcode)  override
    {}

    sptr<IRemoteObject> AsObject() override
    {
        return {};
    }
};

class AbilityManagerServiceEighthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<AbilityRecord> GetAbilityRecord();
    AbilityRequest GenerateAbilityRequest(const std::string& deviceName, const std::string& abilityName,
        const std::string& appName, const std::string& bundleName, const std::string& moduleName);
    std::shared_ptr<AbilityManagerService> abilityMs_;
};

void AbilityManagerServiceEighthTest::SetUpTestCase()
{}

void AbilityManagerServiceEighthTest::TearDownTestCase()
{}

void AbilityManagerServiceEighthTest::SetUp()
{
    abilityMs_ = std::make_shared<AbilityManagerService>();
    ASSERT_NE(abilityMs_, nullptr);
}

void AbilityManagerServiceEighthTest::TearDown()
{
    abilityMs_.reset();
}

std::shared_ptr<AbilityRecord> AbilityManagerServiceEighthTest::GetAbilityRecord()
{
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    return std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
}

AbilityRequest AbilityManagerServiceEighthTest::GenerateAbilityRequest(const std::string& deviceName,
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
 * Function: StopUser
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService StopUser
 */
HWTEST_F(AbilityManagerServiceEighthTest, StopUser_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest StopUser_001 start");
    std::shared_ptr<AbilityManagerService> abilityMs = std::make_shared<AbilityManagerService>();
    int userId = 10;
    sptr<IUserCallback> callback = new MockIUserCallback();
    EXPECT_EQ(abilityMs->StopUser(userId, callback), CHECK_PERMISSION_FAILED);
    IPCSkeleton::SetCallingUid(ACCOUNT_MGR_SERVICE_UID);
    sptr<IUserCallback> callback1 = nullptr;
    EXPECT_EQ(abilityMs->StopUser(userId, callback1), 0);
    abilityMs->userController_ = std::make_shared<UserController>();
    EXPECT_EQ(abilityMs->StopUser(userId, callback), 0);
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, true);
    EXPECT_EQ(abilityMs->StopUser(userId, callback), 0);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest StopUser_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: LogoutUser
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService LogoutUser
 */
HWTEST_F(AbilityManagerServiceEighthTest, LogoutUser_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest LogoutUser_001 start");
    std::shared_ptr<AbilityManagerService> abilityMs = std::make_shared<AbilityManagerService>();
    int userId = 10;
    IPCSkeleton::SetCallingUid(TEST_UID);
    sptr<IUserCallback> callback = nullptr;
    EXPECT_EQ(abilityMs->LogoutUser(userId, callback), CHECK_PERMISSION_FAILED);
    sptr<IUserCallback> callback1 = new MockIUserCallback();
    EXPECT_EQ(abilityMs->LogoutUser(userId, callback1), CHECK_PERMISSION_FAILED);
    IPCSkeleton::SetCallingUid(ACCOUNT_MGR_SERVICE_UID);
    EXPECT_EQ(abilityMs->LogoutUser(userId, callback1), ERR_OK);
    abilityMs->userController_ = std::make_shared<UserController>();
    system::SetBoolParameter(PRODUCT_APPBOOT_SETTING_ENABLED, true);
    EXPECT_NE(abilityMs->LogoutUser(userId, callback1), ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest LogoutUser_001 end");
}

/*
  * Feature: AbilityManagerService
  * Function: GetAbilityRunningInfos
  * SubFunction: NA
  * FunctionPoints: AbilityManagerService GetAbilityRunningInfos
  */
HWTEST_F(AbilityManagerServiceEighthTest, GetAbilityRunningInfos_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest GetAbilityRunningInfos_001 start");
    std::shared_ptr<AbilityManagerService> abilityMs = std::make_shared<AbilityManagerService>();
    AbilityRunningInfo abilityRunningInfo;
    std::vector<AbilityRunningInfo> info {abilityRunningInfo};
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled()).Times(1).WillOnce(Return(true));
    EXPECT_EQ(abilityMs->GetAbilityRunningInfos(info), ERR_INVALID_VALUE);
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled()).Times(1).WillOnce(Return(false));
    EXPECT_EQ(abilityMs->GetAbilityRunningInfos(info), ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest GetAbilityRunningInfos_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: SwitchToUser
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService SwitchToUser
 */
HWTEST_F(AbilityManagerServiceEighthTest, SwitchToUser_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest SwitchToUser_001 start");
    std::shared_ptr<AbilityManagerService> abilityMs = std::make_shared<AbilityManagerService>();
    int32_t oldUserId = 10;
    int32_t userId = 11;
    sptr<IUserCallback> callback;
    sptr<IUserCallback> callback1 = new MockIUserCallback();
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled())
        .WillRepeatedly(Return(false));
    EXPECT_NE(abilityMs->SwitchToUser(oldUserId, userId, callback), ERR_OK);
    abilityMs->taskHandler_ = TaskHandlerWrap::CreateQueueHandler("SetTaskHandler");
    EXPECT_NE(abilityMs->SwitchToUser(oldUserId, userId, callback1), ERR_OK);
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled())
        .WillRepeatedly(Return(true));
    EXPECT_NE(abilityMs->SwitchToUser(oldUserId, userId, callback1), ERR_OK);
    AmsConfigurationParameter::GetInstance().multiUserType_ = 1; // multiUserType_ = 1
    EXPECT_NE(abilityMs->SwitchToUser(oldUserId, userId, callback1), ERR_OK);
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled())
        .WillRepeatedly(Return(false));
    EXPECT_NE(abilityMs->SwitchToUser(oldUserId, userId, callback1), ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest SwitchToUser_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: CheckStaticCfgPermissionForSkill
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckStaticCfgPermissionForSkill
 */
HWTEST_F(AbilityManagerServiceEighthTest, CheckStaticCfgPermissionForSkill_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest CheckStaticCfgPermissionForSkill_001 start");
    std::shared_ptr<AbilityManagerService> abilityMs = std::make_shared<AbilityManagerService>();
    AppExecFwk::AbilityRequest abilityRequest;
    uint32_t tokenId = 10;
    Skill skills;
    abilityRequest.abilityInfo.skills.emplace_back(skills);
    auto res = abilityMs->CheckStaticCfgPermissionForSkill(abilityRequest, tokenId);
    EXPECT_EQ(res,  AppExecFwk::Constants::PERMISSION_GRANTED);

    abilityRequest.abilityInfo.permissions.emplace_back(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED);
    res = abilityMs->CheckStaticCfgPermissionForSkill(abilityRequest, tokenId);
    EXPECT_EQ(res,  AppExecFwk::Constants::PERMISSION_NOT_GRANTED);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest CheckStaticCfgPermissionForSkill_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: StartAbilityOnlyUIAbility_001
 * Function: StartAbilityOnlyUIAbility
 * SubFunction: NA
 */
HWTEST_F(AbilityManagerServiceEighthTest, StartAbilityOnlyUIAbility_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest StartAbilityOnlyUIAbility_001 start");
    Want want;
    sptr<IRemoteObject> callerToken;
    uint32_t specifyTokenId = 0;
    IPCSkeleton::SetCallingUid(ACCOUNT_MGR_SERVICE_UID);
    int result = abilityMs_->StartAbilityOnlyUIAbility(want, callerToken, specifyTokenId);
    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
    IPCSkeleton::SetCallingUid(FOUNDATION_UID);
    result = abilityMs_->StartAbilityOnlyUIAbility(want, callerToken, specifyTokenId);
    EXPECT_NE(result, ERR_OK);
    want.SetFlags(TEST_FLAG_ABILITY_CONTINUATION);
    result = abilityMs_->StartAbilityOnlyUIAbility(want, callerToken, specifyTokenId);
    EXPECT_EQ(result, ERR_INVALID_CONTINUATION_FLAG);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest StartAbilityOnlyUIAbility_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: StartAbilityInChainTest_001
 * Function: StartAbilityInChain
 * SubFunction: NA
 */
HWTEST_F(AbilityManagerServiceEighthTest, StartAbilityInChainTest_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest StartAbilityInChainTest_001 start");
    Want want;
    int result = ERR_OK;
    bool ret = false;
    sptr<IRemoteObject> callerToken = nullptr;
    StartAbilityParams params(want);
    params.callerToken = callerToken;
    abilityMs_->InitStartAbilityChain();
    ret = abilityMs_->StartAbilityInChain(params, result);
    EXPECT_FALSE(ret);
    want.SetAction(TEST_CREATE_FILE);
    std::string key = "startMode";
    std::string value = "save";
    want.SetParam(key, value);
    StartAbilityParams params2(want);
    params2.callerToken = callerToken;
    params2.callerAppIndex = ONE;
    ret = abilityMs_->StartAbilityInChain(params2, result);
    EXPECT_TRUE(ret);
    const int32_t userId = -1;
    std::shared_ptr<AbilityRecord> callerAbilityRecord = GetAbilityRecord();
    callerAbilityRecord->Init();
    sptr<IRemoteObject> callerToken1 = callerAbilityRecord->GetToken();
    params2.callerToken = callerToken1;
    params2.userId = userId;
    ret = abilityMs_->StartAbilityInChain(params2, result);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest StartAbilityInChainTest_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: StartUIAbilityBySCB_001
 * Function: StartAbilityOnlyUIAbility
 * SubFunction: NA
 */
HWTEST_F(AbilityManagerServiceEighthTest, StartUIAbilityBySCB_001, TestSize.Level1)
{
    int ret = 0;
    bool isColdStart = false;
    uint32_t sceneFlag = 0;
    sptr<SessionInfo> sessionInfo = nullptr;
    ret = abilityMs_->StartUIAbilityBySCB(sessionInfo, isColdStart, sceneFlag);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    sessionInfo = new (std::nothrow) SessionInfo();
    EXPECT_NE(sessionInfo, nullptr);
    sessionInfo->sessionToken == nullptr;
    ret = abilityMs_->StartUIAbilityBySCB(sessionInfo, isColdStart, sceneFlag);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    Rosen::SessionInfo info;
    sessionInfo->sessionToken = new Rosen::Session(info);
    ret = abilityMs_->StartUIAbilityBySCB(sessionInfo, isColdStart, sceneFlag);
    EXPECT_EQ(ret, ERR_WRONG_INTERFACE_CALL);
    abilityMs_->subManagersHelper_ = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    IPCSkeleton::SetCallingUid(BASE_USER_RANGE);
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(ONE);
    connectManager->sceneBoardTokenId_ = TEST_VALUE_ONE;
    abilityMs_->subManagersHelper_->connectManagers_.insert(std::make_pair(ONE, connectManager));
    IPCSkeleton::SetCallingTokenID(ONE);
    ret = abilityMs_->StartUIAbilityBySCB(sessionInfo, isColdStart, sceneFlag);
    EXPECT_NE(ret, ERR_OK);
    std::string value;
    sessionInfo->want.SetParam(KEY_SESSION_ID, value);
    ret = abilityMs_->StartUIAbilityBySCB(sessionInfo, isColdStart, sceneFlag);
    EXPECT_NE(ret, ERR_OK);
    sessionInfo->want.SetParam(KEY_SESSION_ID, TEST_STRING_VALUE_1);
    ret = abilityMs_->StartUIAbilityBySCB(sessionInfo, isColdStart, sceneFlag);
    EXPECT_NE(ret, ERR_OK);
    abilityMs_->freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    ret = abilityMs_->StartUIAbilityBySCB(sessionInfo, isColdStart, sceneFlag);
    EXPECT_NE(ret, ERR_OK);
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    abilityMs_->subManagersHelper_->uiAbilityManagers_.emplace(ONE, uiAbilityLifecycleManager);
    sessionInfo->want.SetElementName(TEST_DEVICEID, TEST_BUNDLE_NAME, TEST_ABILITY_NAME, TEST_MODULE_NAME);
    ret = abilityMs_->StartUIAbilityBySCB(sessionInfo, isColdStart, sceneFlag);
    EXPECT_NE(ret, ERR_OK);
    Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo applicationInfo;
    auto abilityRecord = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    abilityRecord->Init();
    sessionInfo->persistentId = TWO;
    uiAbilityLifecycleManager->sessionAbilityMap_.emplace(TWO, abilityRecord);
    abilityMs_->subManagersHelper_->uiAbilityManagers_.emplace(TWO, uiAbilityLifecycleManager);
    ret = abilityMs_->StartUIAbilityBySCB(sessionInfo, isColdStart, sceneFlag);
    EXPECT_NE(ret, ERR_OK);
}

/*
* Feature: AbilityManagerService
* Name: StartUIAbilityBySCB_002
* Function: StartAbilityOnlyUIAbility
* SubFunction: NA
*/
HWTEST_F(AbilityManagerServiceEighthTest, StartUIAbilityBySCB_001_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest StartUIAbilityBySCB_001_002 start");
    int ret = 0;
    bool isColdStart = false;
    uint32_t sceneFlag = 0;
    sptr<SessionInfo> sessionInfo = nullptr;
    sessionInfo = new (std::nothrow) SessionInfo();
    EXPECT_NE(sessionInfo, nullptr);
    Rosen::SessionInfo info;
    sessionInfo->sessionToken = new Rosen::Session(info);
    abilityMs_->subManagersHelper_ = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    IPCSkeleton::SetCallingUid(BASE_USER_RANGE);
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(ONE);
    connectManager->sceneBoardTokenId_ = TEST_VALUE_ONE;
    abilityMs_->subManagersHelper_->connectManagers_.insert(std::make_pair(ONE, connectManager));
    IPCSkeleton::SetCallingTokenID(TEST_VALUE_ONE);
    sessionInfo->want.SetParam(KEY_SESSION_ID, TEST_STRING_VALUE_1);
    FreeInstallInfo freeInstallInfo;
    freeInstallInfo.want.SetParam(KEY_SESSION_ID, TEST_STRING_VALUE_1);
    abilityMs_->freeInstallManager_ = std::make_shared<FreeInstallManager>(abilityMs_);
    abilityMs_->freeInstallManager_->freeInstallList_.push_back(freeInstallInfo);
    ret = abilityMs_->StartUIAbilityBySCB(sessionInfo, isColdStart, sceneFlag);
    EXPECT_EQ(ret, ERR_OK);
    abilityMs_->freeInstallManager_->freeInstallList_.clear();
    freeInstallInfo.isFreeInstallFinished = true;
    abilityMs_->freeInstallManager_->freeInstallList_.push_back(freeInstallInfo);
    ret = abilityMs_->StartUIAbilityBySCB(sessionInfo, isColdStart, sceneFlag);
    EXPECT_EQ(ret, ERR_OK);
    abilityMs_->freeInstallManager_->freeInstallList_.clear();
    freeInstallInfo.isInstalled = true;
    abilityMs_->freeInstallManager_->freeInstallList_.push_back(freeInstallInfo);
    ret = abilityMs_->StartUIAbilityBySCB(sessionInfo, isColdStart, sceneFlag);
    EXPECT_NE(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest StartUIAbilityBySCB_001_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckWorkSchedulerPermission_001
 * Function: CheckWorkSchedulerPermission
 * SubFunction: NA
 */
HWTEST_F(AbilityManagerServiceEighthTest, CheckWorkSchedulerPermission_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest CheckWorkSchedulerPermission_001 start");
    sptr<IRemoteObject> callerToken;
    uint32_t uid = 0;
    bool result = abilityMs_->CheckWorkSchedulerPermission(callerToken, uid);
    EXPECT_TRUE(result);
    abilityMs_->bgtaskObserver_ = std::make_shared<BackgroundTaskObserver>();
    result = abilityMs_->CheckWorkSchedulerPermission(callerToken, uid);
    EXPECT_TRUE(result);
    AbilityRequest abilityRequest{};
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    std::shared_ptr<AbilityRecord> abilityRecord{ nullptr };
    abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    callerToken = abilityRecord->GetToken();
    result = abilityMs_->CheckWorkSchedulerPermission(callerToken, uid);
    EXPECT_TRUE(result);
    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::WORK_SCHEDULER;
    abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    callerToken = abilityRecord->GetToken();
    result = abilityMs_->CheckWorkSchedulerPermission(callerToken, uid);
    EXPECT_FALSE(result);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest CheckWorkSchedulerPermission_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: Dump_001
 * Function: Dump
 * SubFunction: NA
 */
HWTEST_F(AbilityManagerServiceEighthTest, Dump_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest Dump_001 start");
    std::vector<std::u16string> args;
    std::stringstream buffer;
    int fd = fileno(tmpfile());
    int result = abilityMs_->Dump(fd, args);
    EXPECT_EQ(result, 0);
    fclose(fdopen(fd, "r"));
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest Dump_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: OnAppStateChanged_001
 * Function: OnAppStateChanged
 * SubFunction: NA
 */
HWTEST_F(AbilityManagerServiceEighthTest, OnAppStateChanged_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest OnAppStateChanged_001 start");
    abilityMs_->Init();
    EXPECT_TRUE(abilityMs_->subManagersHelper_ != nullptr);
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = std::make_shared<UIAbilityLifecycleManager>();
    abilityMs_->subManagersHelper_->currentConnectManager_ = std::make_shared<AbilityConnectManager>(ONE);
    abilityMs_->subManagersHelper_->currentDataAbilityManager_ = std::make_shared<DataAbilityManager>();
    AppInfo info;
    abilityMs_->OnAppStateChanged(info);
    EXPECT_TRUE(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false));

    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled())
        .WillRepeatedly(Return(true));
    system::SetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false);
    abilityMs_->OnAppStateChanged(info);
    EXPECT_FALSE(system::GetBoolParameter(PRODUCT_ENTERPRISE_FEATURE_SETTING_ENABLED, false));
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest OnAppStateChanged_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: TerminateUIServiceExtensionAbility_001
 * Function: TerminateUIServiceExtensionAbility
 * SubFunction: NA
 */
HWTEST_F(AbilityManagerServiceEighthTest, TerminateUIServiceExtensionAbility_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest TerminateUIServiceExtensionAbility_001 start");
    sptr<IRemoteObject> token;
    abilityMs_->subManagersHelper_ = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled())
        .WillRepeatedly(Return(false));
    int32_t result = abilityMs_->TerminateUIServiceExtensionAbility(token);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    AbilityRequest abilityRequest{};
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    std::shared_ptr<AbilityRecord> abilityRecord{ nullptr };
    abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    token = abilityRecord->GetToken();
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    uiAbilityLifecycleManager->sessionAbilityMap_.emplace(TWO, abilityRecord);
    abilityMs_->subManagersHelper_->uiAbilityManagers_.emplace(TWO, uiAbilityLifecycleManager);
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled())
        .WillRepeatedly(Return(true));
    result = abilityMs_->TerminateUIServiceExtensionAbility(token);
    EXPECT_EQ(result, ERR_WRONG_INTERFACE_CALL);

    IPCSkeleton::SetCallingUid(BASE_USER_RANGE);
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(1);
    connectManager->sceneBoardTokenId_ = 1;
    abilityMs_->subManagersHelper_->connectManagers_.insert(std::make_pair(1, connectManager));
    IPCSkeleton::SetCallingTokenID(1);
    result = abilityMs_->TerminateUIServiceExtensionAbility(token);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest TerminateUIServiceExtensionAbility_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: TerminateUIServiceExtensionAbility_002
 * Function: TerminateUIServiceExtensionAbility
 * SubFunction: NA
 */
HWTEST_F(AbilityManagerServiceEighthTest, TerminateUIServiceExtensionAbility_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest TerminateUIServiceExtensionAbility_002 start");
    sptr<IRemoteObject> token;
    abilityMs_->subManagersHelper_ = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    AbilityRequest abilityRequest{};
    std::string deviceName = "device";
    std::string abilityName = "ServiceAbility";
    std::string appName = "hiservcie";
    std::string bundleName = "com.ix.hiservcie";
    std::string moduleName = "entry";
    IPCSkeleton::SetCallingUid(BASE_USER_RANGE);
    IPCSkeleton::SetCallingTokenID(1);
    std::shared_ptr<AbilityRecord> abilityRecord{ nullptr };
    auto uiAbilityLifecycleManager = std::make_shared<UIAbilityLifecycleManager>();
    EXPECT_CALL(Rosen::SceneBoardJudgement::GetInstance(), MockIsSceneBoardEnabled())
        .WillRepeatedly(Return(true));
    abilityRequest = GenerateAbilityRequest(deviceName, abilityName, appName, bundleName, moduleName);
    abilityRequest.abilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    token = abilityRecord->GetToken();
    uiAbilityLifecycleManager->sessionAbilityMap_.emplace(TWO, abilityRecord);
    abilityMs_->subManagersHelper_->uiAbilityManagers_.emplace(TWO, uiAbilityLifecycleManager);
    std::shared_ptr<AbilityConnectManager> connectManager = std::make_shared<AbilityConnectManager>(1);
    connectManager->sceneBoardTokenId_ = 1;
    abilityMs_->subManagersHelper_->connectManagers_.insert(std::make_pair(1, connectManager));
    int32_t result = abilityMs_->TerminateUIServiceExtensionAbility(token);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    abilityRequest.abilityInfo.extensionAbilityType = AppExecFwk::ExtensionAbilityType::UI_SERVICE;
    abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    token = abilityRecord->GetToken();
    uiAbilityLifecycleManager->sessionAbilityMap_.clear();
    abilityMs_->subManagersHelper_->uiAbilityManagers_.clear();
    uiAbilityLifecycleManager->sessionAbilityMap_.emplace(TWO, abilityRecord);
    abilityMs_->subManagersHelper_->uiAbilityManagers_.emplace(TWO, uiAbilityLifecycleManager);
    result = abilityMs_->TerminateUIServiceExtensionAbility(token);
    EXPECT_NE(result, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceEighthTest TerminateUIServiceExtensionAbility_002 end");
}
} // namespace AAFwk
} // namespace OHOS
