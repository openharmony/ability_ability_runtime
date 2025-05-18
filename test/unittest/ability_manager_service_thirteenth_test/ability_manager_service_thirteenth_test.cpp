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
#include "mock_my_status.h"

#include "ability_manager_service.h"
#include "hilog_tag_wrapper.h"
#include "sub_managers_helper.h"
#include "mission_list_manager.h"

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
constexpr int32_t DMS_UID = 5522;

namespace OHOS {
namespace AAFwk {
class AbilityManagerServiceThirteenthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<AbilityRecord> MockAbilityRecord(AbilityType);
    sptr<Token> MockToken(AbilityType);
};

void AbilityManagerServiceThirteenthTest::SetUpTestCase() {}

void AbilityManagerServiceThirteenthTest::TearDownTestCase() {}

void AbilityManagerServiceThirteenthTest::SetUp() {}

void AbilityManagerServiceThirteenthTest::TearDown() {}
std::shared_ptr<AbilityRecord> AbilityManagerServiceThirteenthTest::MockAbilityRecord(AbilityType abilityType)
{
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.test.demo";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = abilityType;
    return AbilityRecord::CreateAbilityRecord(abilityRequest);
}

sptr<Token> AbilityManagerServiceThirteenthTest::MockToken(AbilityType abilityType)
{
    std::shared_ptr<AbilityRecord> abilityRecord = MockAbilityRecord(abilityType);
    if (!abilityRecord) {
        return nullptr;
    }
    return abilityRecord->GetToken();
}

/*
 * Feature: AbilityManagerService
 * Name: FreeInstallAbilityFromRemote_001
 * Function: FreeInstallAbilityFromRemote
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService FreeInstallAbilityFromRemote
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, FreeInstallAbilityFromRemote_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest FreeInstallAbilityFromRemote_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    MyStatus::GetInstance().ipcGetCallingUid_ = FOUNDATION_UID;
    Want want;
    sptr<IRemoteObject> callback = nullptr;
    int retCode = abilityMs_->FreeInstallAbilityFromRemote(want, callback, 0, 0);
    EXPECT_EQ(retCode, CHECK_PERMISSION_FAILED);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest FreeInstallAbilityFromRemote_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: FreeInstallAbilityFromRemote_002
 * Function: FreeInstallAbilityFromRemote
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService FreeInstallAbilityFromRemote
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, FreeInstallAbilityFromRemote_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest FreeInstallAbilityFromRemote_002 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    MyStatus::GetInstance().ipcGetCallingUid_ = DMS_UID;
    abilityMs_->freeInstallManager_ = nullptr;
    Want want;
    sptr<IRemoteObject> callback = nullptr;
    int retCode = abilityMs_->FreeInstallAbilityFromRemote(want, callback, 0, 0);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest FreeInstallAbilityFromRemote_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: FreeInstallAbilityFromRemote_003
 * Function: FreeInstallAbilityFromRemote
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService FreeInstallAbilityFromRemote
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, FreeInstallAbilityFromRemote_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest FreeInstallAbilityFromRemote_003 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    MyStatus::GetInstance().ipcGetCallingUid_ = DMS_UID;
    Want want;
    sptr<IRemoteObject> callback = nullptr;
    int retCode = abilityMs_->FreeInstallAbilityFromRemote(want, callback, 0, 0);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest FreeInstallAbilityFromRemote_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: SetMissionContinueState_001
 * Function: SetMissionContinueState
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService SetMissionContinueState
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, SetMissionContinueState_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest SetMissionContinueState_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    sptr<IRemoteObject> token = nullptr;
    AAFwk::ContinueState state = AAFwk::ContinueState::CONTINUESTATE_UNKNOWN;
    int result = abilityMs_->SetMissionContinueState(token, state);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest SetMissionContinueState_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: SetMissionContinueState_002
 * Function: SetMissionContinueState
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService SetMissionContinueState
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, SetMissionContinueState_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest SetMissionContinueState_002 start");
    
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    
    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    AAFwk::ContinueState state = AAFwk::ContinueState::CONTINUESTATE_UNKNOWN;
    int result = abilityMs_->SetMissionContinueState(token, state);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest SetMissionContinueState_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckFileAccessExtensionPermission_001
 * Function: CheckFileAccessExtensionPermission
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckFileAccessExtensionPermission
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, CheckFileAccessExtensionPermission_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckFileAccessExtensionPermission_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    MyStatus::GetInstance().permPermission_ = 0;
    AbilityRequest abilityRequest;
    int result = abilityMs_->CheckFileAccessExtensionPermission(abilityRequest);
    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckFileAccessExtensionPermission_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckFileAccessExtensionPermission_002
 * Function: CheckFileAccessExtensionPermission
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckFileAccessExtensionPermission
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, CheckFileAccessExtensionPermission_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckFileAccessExtensionPermission_002 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    MyStatus::GetInstance().permPermission_ = CHECK_PERMISSION_FAILED;
    AbilityRequest abilityRequest;
    int result = abilityMs_->CheckFileAccessExtensionPermission(abilityRequest);
    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckFileAccessExtensionPermission_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckCallerInfoQueryExtensionPermission_001
 * Function: CheckCallerInfoQueryExtensionPermission
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckCallerInfoQueryExtensionPermission
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, CheckCallerInfoQueryExtensionPermission_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckCallerInfoQueryExtensionPermission_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    MyStatus::GetInstance().permPermission_ = 0;
    AbilityRequest abilityRequest;
    int result = abilityMs_->CheckCallerInfoQueryExtensionPermission(abilityRequest);
    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckCallerInfoQueryExtensionPermission_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckCallerInfoQueryExtensionPermission_002
 * Function: CheckCallerInfoQueryExtensionPermission
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckCallerInfoQueryExtensionPermission
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, CheckCallerInfoQueryExtensionPermission_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckCallerInfoQueryExtensionPermission_002 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    MyStatus::GetInstance().permPermission_ = 1;
    AbilityRequest abilityRequest;
    int result = abilityMs_->CheckCallerInfoQueryExtensionPermission(abilityRequest);
    EXPECT_EQ(result, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckCallerInfoQueryExtensionPermission_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckUIExtensionCallerIsForeground_001
 * Function: CheckUIExtensionCallerIsForeground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckUIExtensionCallerIsForeground
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, CheckUIExtensionCallerIsForeground_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckUIExtensionCallerIsForeground_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    AbilityRequest abilityRequest;
    int result = abilityMs_->CheckUIExtensionCallerIsForeground(abilityRequest);
    EXPECT_TRUE(result);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckUIExtensionCallerIsForeground_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckUIExtensionCallerIsForeground_002
 * Function: CheckUIExtensionCallerIsForeground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckUIExtensionCallerIsForeground
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, CheckUIExtensionCallerIsForeground_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckUIExtensionCallerIsForeground_002 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.test.demo";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::PAGE;
    MyStatus::GetInstance().permPermission_ = 0;
    int result = abilityMs_->CheckUIExtensionCallerIsForeground(abilityRequest);
    EXPECT_TRUE(result);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckUIExtensionCallerIsForeground_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckUIExtensionCallerIsForeground_003
 * Function: CheckUIExtensionCallerIsForeground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckUIExtensionCallerIsForeground
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, CheckUIExtensionCallerIsForeground_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckUIExtensionCallerIsForeground_003 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.test.demo";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::PAGE;
    MyStatus::GetInstance().permPermission_ = 1;
    int result = abilityMs_->CheckUIExtensionCallerIsForeground(abilityRequest);
    EXPECT_TRUE(result);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckUIExtensionCallerIsForeground_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckDebugAssertPermission_001
 * Function: CheckDebugAssertPermission
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckDebugAssertPermission
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, CheckDebugAssertPermission_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckDebugAssertPermission_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    MyStatus::GetInstance().paramGetBoolParameter_ = false;
    int32_t result = abilityMs_->CheckDebugAssertPermission();
    EXPECT_EQ(result, ERR_NOT_SUPPORTED_PRODUCT_TYPE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckDebugAssertPermission_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckDebugAssertPermission_002
 * Function: CheckDebugAssertPermission
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckDebugAssertPermission
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, CheckDebugAssertPermission_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckDebugAssertPermission_002 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    MyStatus::GetInstance().paramGetBoolParameter_ = true;
    int32_t result = abilityMs_->CheckDebugAssertPermission();
    EXPECT_EQ(result, ERR_NOT_SUPPORTED_PRODUCT_TYPE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest CheckDebugAssertPermission_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: IsEmbeddedOpenAllowed_001
 * Function: IsEmbeddedOpenAllowed
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsEmbeddedOpenAllowed
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, IsEmbeddedOpenAllowed_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_001 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = false;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    EXPECT_FALSE(abilityMs_->IsEmbeddedOpenAllowed(callerToken, appId));
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: IsEmbeddedOpenAllowed_002
 * Function: IsEmbeddedOpenAllowed
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsEmbeddedOpenAllowed
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, IsEmbeddedOpenAllowed_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_002 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = -1;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    EXPECT_FALSE(abilityMs_->IsEmbeddedOpenAllowed(callerToken, appId));
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: IsEmbeddedOpenAllowed_003
 * Function: IsEmbeddedOpenAllowed
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsEmbeddedOpenAllowed
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, IsEmbeddedOpenAllowed_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_003 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().fimStartFreeInstall_ = ERR_OK;
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = 1;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->currentState_ = AbilityState::FOREGROUND;
    record->isAbilityForegrounding_ = true;
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    auto mockFreeInstallManager = std::make_shared<FreeInstallManager>(abilityMs_);
    EXPECT_NE(mockFreeInstallManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;
    abilityMs_->freeInstallManager_ = mockFreeInstallManager;

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    EXPECT_TRUE(abilityMs_->IsEmbeddedOpenAllowed(callerToken, appId));
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: IsEmbeddedOpenAllowed_004
 * Function: IsEmbeddedOpenAllowed
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsEmbeddedOpenAllowed
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, IsEmbeddedOpenAllowed_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_004 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = nullptr;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    EXPECT_FALSE(abilityMs_->IsEmbeddedOpenAllowed(callerToken, appId));
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_004 end");
}

/*
 * Feature: AbilityManagerService
 * Name: IsEmbeddedOpenAllowed_005
 * Function: IsEmbeddedOpenAllowed
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsEmbeddedOpenAllowed
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, IsEmbeddedOpenAllowed_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_005 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = -1;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    EXPECT_FALSE(abilityMs_->IsEmbeddedOpenAllowed(callerToken, appId));
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_005 end");
}

/*
 * Feature: AbilityManagerService
 * Name: IsEmbeddedOpenAllowed_006
 * Function: IsEmbeddedOpenAllowed
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsEmbeddedOpenAllowed
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, IsEmbeddedOpenAllowed_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_006 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = 1;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->currentState_ = AbilityState::BACKGROUND;
    record->isAbilityForegrounding_ = false;
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    EXPECT_FALSE(abilityMs_->IsEmbeddedOpenAllowed(callerToken, appId));
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_006 end");
}

/*
 * Feature: AbilityManagerService
 * Name: IsEmbeddedOpenAllowed_007
 * Function: IsEmbeddedOpenAllowed
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsEmbeddedOpenAllowed
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, IsEmbeddedOpenAllowed_007, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_007 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = 1;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->currentState_ = AbilityState::FOREGROUND;
    record->isAbilityForegrounding_ = false;
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    EXPECT_FALSE(abilityMs_->IsEmbeddedOpenAllowed(callerToken, appId));
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_007 end");
}

/*
 * Feature: AbilityManagerService
 * Name: IsEmbeddedOpenAllowed_008
 * Function: IsEmbeddedOpenAllowed
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsEmbeddedOpenAllowed
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, IsEmbeddedOpenAllowed_008, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_008 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = 1;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->currentState_ = AbilityState::FOREGROUND;
    record->isAbilityForegrounding_ = true;
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;
    abilityMs_->freeInstallManager_ = nullptr;
    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    EXPECT_FALSE(abilityMs_->IsEmbeddedOpenAllowed(callerToken, appId));
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_008 end");
}

/*
 * Feature: AbilityManagerService
 * Name: IsEmbeddedOpenAllowed_009
 * Function: IsEmbeddedOpenAllowed
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsEmbeddedOpenAllowed
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, IsEmbeddedOpenAllowed_009, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_009 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().fimStartFreeInstall_ = ERR_INVALID_VALUE;
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = 1;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->currentState_ = AbilityState::FOREGROUND;
    record->isAbilityForegrounding_ = true;
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    auto mockFreeInstallManager = std::make_shared<FreeInstallManager>(abilityMs_);
    EXPECT_NE(mockFreeInstallManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;
    abilityMs_->freeInstallManager_ = mockFreeInstallManager;

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    EXPECT_FALSE(abilityMs_->IsEmbeddedOpenAllowed(callerToken, appId));
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest IsEmbeddedOpenAllowed_009 end");
}

/*
 * Feature: AbilityManagerService
 * Name: QueryAtomicServiceStartupRule_001
 * Function: QueryAtomicServiceStartupRule
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService QueryAtomicServiceStartupRule
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, QueryAtomicServiceStartupRule_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_001 start");

    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = false;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    const std::string startTime = "";
    AtomicServiceStartupRule rule;
    EXPECT_EQ(abilityMs_->QueryAtomicServiceStartupRule(callerToken, appId, startTime, rule),
              ERR_CAPABILITY_NOT_SUPPORT);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: QueryAtomicServiceStartupRule_002
 * Function: QueryAtomicServiceStartupRule
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService QueryAtomicServiceStartupRule
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, QueryAtomicServiceStartupRule_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_002 start");

    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = -1; // 0: TOKEN_HAP

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    const std::string startTime = "";
    AtomicServiceStartupRule rule;
    EXPECT_EQ(abilityMs_->QueryAtomicServiceStartupRule(callerToken, appId, startTime, rule), INNER_ERR);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: QueryAtomicServiceStartupRule_003
 * Function: QueryAtomicServiceStartupRule
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService QueryAtomicServiceStartupRule
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, QueryAtomicServiceStartupRule_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_003 start");

    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0; // 0: TOKEN_HAP
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = false;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    const std::string startTime = "";
    AtomicServiceStartupRule rule;
    EXPECT_EQ(abilityMs_->QueryAtomicServiceStartupRule(callerToken, appId, startTime, rule), INNER_ERR);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: QueryAtomicServiceStartupRule_004
 * Function: QueryAtomicServiceStartupRule
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService QueryAtomicServiceStartupRule
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, QueryAtomicServiceStartupRule_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_004 start");

    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0; // 0: TOKEN_HAP
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = nullptr;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    const std::string startTime = "";
    AtomicServiceStartupRule rule;
    EXPECT_EQ(abilityMs_->QueryAtomicServiceStartupRule(callerToken, appId, startTime, rule), INNER_ERR);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_004 end");
}

/*
 * Feature: AbilityManagerService
 * Name: QueryAtomicServiceStartupRule_005
 * Function: QueryAtomicServiceStartupRule
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService QueryAtomicServiceStartupRule
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, QueryAtomicServiceStartupRule_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_005 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0; // 0: TOKEN_HAP
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().ipcGetCallingTokenID_ = 1;
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = -1;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    const std::string startTime = "";
    AtomicServiceStartupRule rule;
    EXPECT_EQ(abilityMs_->QueryAtomicServiceStartupRule(callerToken, appId, startTime, rule), INNER_ERR);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_005 end");
}

/*
 * Feature: AbilityManagerService
 * Name: QueryAtomicServiceStartupRule_006
 * Function: QueryAtomicServiceStartupRule
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService QueryAtomicServiceStartupRule
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, QueryAtomicServiceStartupRule_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_006 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().ipcGetCallingTokenID_ = 1;
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = 1;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->currentState_ = AbilityState::BACKGROUND;
    record->isAbilityForegrounding_ = false;
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    const std::string startTime = "";
    AtomicServiceStartupRule rule;
    EXPECT_EQ(abilityMs_->QueryAtomicServiceStartupRule(callerToken, appId, startTime, rule), INNER_ERR);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_006 end");
}

/*
 * Feature: AbilityManagerService
 * Name: QueryAtomicServiceStartupRule_007
 * Function: QueryAtomicServiceStartupRule
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService QueryAtomicServiceStartupRule
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, QueryAtomicServiceStartupRule_007, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_007 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().ipcGetCallingTokenID_ = 1;
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = 1;
    MyStatus::GetInstance().fimStartFreeInstall_ = ERR_INVALID_VALUE;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->currentState_ = AbilityState::FOREGROUND;
    record->isAbilityForegrounding_ = false;
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    auto mockFreeInstallManager = std::make_shared<FreeInstallManager>(abilityMs_);
    EXPECT_NE(mockFreeInstallManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;
    abilityMs_->freeInstallManager_ = mockFreeInstallManager;

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    const std::string startTime = "";
    AtomicServiceStartupRule rule;
    EXPECT_EQ(abilityMs_->QueryAtomicServiceStartupRule(callerToken, appId, startTime, rule), ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_007 end");
}

/*
 * Feature: AbilityManagerService
 * Name: QueryAtomicServiceStartupRule_008
 * Function: QueryAtomicServiceStartupRule
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService QueryAtomicServiceStartupRule
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, QueryAtomicServiceStartupRule_008, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_008 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().ipcGetCallingTokenID_ = 1;
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = 1;
    MyStatus::GetInstance().fimStartFreeInstall_ = ERR_OK;
    MyStatus::GetInstance().eriQueryAtomicServiceStartupRule_ = ERR_OK;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->currentState_ = AbilityState::FOREGROUND;
    record->isAbilityForegrounding_ = true;
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    auto mockFreeInstallManager = std::make_shared<FreeInstallManager>(abilityMs_);
    EXPECT_NE(mockFreeInstallManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;
    abilityMs_->freeInstallManager_ = mockFreeInstallManager;

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    const std::string startTime = "";
    AtomicServiceStartupRule rule;
    EXPECT_EQ(abilityMs_->QueryAtomicServiceStartupRule(callerToken, appId, startTime, rule), ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_008 end");
}

/*
 * Feature: AbilityManagerService
 * Name: QueryAtomicServiceStartupRule_009
 * Function: QueryAtomicServiceStartupRule
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService QueryAtomicServiceStartupRule
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, QueryAtomicServiceStartupRule_009, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_009 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().ipcGetCallingTokenID_ = 1;
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = 1;
    MyStatus::GetInstance().fimStartFreeInstall_ = ERR_OK;
    MyStatus::GetInstance().eriQueryAtomicServiceStartupRule_ = ERR_CAPABILITY_NOT_SUPPORT;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->currentState_ = AbilityState::FOREGROUND;
    record->isAbilityForegrounding_ = true;
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    auto mockFreeInstallManager = std::make_shared<FreeInstallManager>(abilityMs_);
    EXPECT_NE(mockFreeInstallManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;
    abilityMs_->freeInstallManager_ = mockFreeInstallManager;

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    const std::string startTime = "";
    AtomicServiceStartupRule rule;
    EXPECT_EQ(abilityMs_->QueryAtomicServiceStartupRule(callerToken, appId, startTime, rule),
              ERR_CAPABILITY_NOT_SUPPORT);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_009 end");
}

/*
 * Feature: AbilityManagerService
 * Name: QueryAtomicServiceStartupRule_010
 * Function: QueryAtomicServiceStartupRule
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService QueryAtomicServiceStartupRule
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, QueryAtomicServiceStartupRule_010, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_010 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().ipcGetCallingTokenID_ = 1;
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = 1;
    MyStatus::GetInstance().fimStartFreeInstall_ = ERR_OK;
    MyStatus::GetInstance().eriQueryAtomicServiceStartupRule_ = ERR_INVALID_VALUE;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->currentState_ = AbilityState::FOREGROUND;
    record->isAbilityForegrounding_ = true;
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    auto mockFreeInstallManager = std::make_shared<FreeInstallManager>(abilityMs_);
    EXPECT_NE(mockFreeInstallManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;
    abilityMs_->freeInstallManager_ = mockFreeInstallManager;

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    const std::string startTime = "";
    AtomicServiceStartupRule rule;
    EXPECT_EQ(abilityMs_->QueryAtomicServiceStartupRule(callerToken, appId, startTime, rule), INNER_ERR);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_010 end");
}

/*
 * Feature: AbilityManagerService
 * Name: QueryAtomicServiceStartupRule_011
 * Function: QueryAtomicServiceStartupRule
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService QueryAtomicServiceStartupRule
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, QueryAtomicServiceStartupRule_011, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_011 start");
    MyStatus::GetInstance().auIsLaunchEmbededUIAbility_ = true;
    MyStatus::GetInstance().atkGetTokenTypeFlag_ = 0;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUid_ = true;
    MyStatus::GetInstance().ipcGetCallingTokenID_ = 1;
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = 1;
    MyStatus::GetInstance().fimStartFreeInstall_ = ERR_OK;
    MyStatus::GetInstance().eriQueryAtomicServiceStartupRule_ = ERR_ECOLOGICAL_CONTROL_STATUS;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->currentState_ = AbilityState::FOREGROUND;
    record->isAbilityForegrounding_ = true;
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    auto mockFreeInstallManager = std::make_shared<FreeInstallManager>(abilityMs_);
    EXPECT_NE(mockFreeInstallManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;
    abilityMs_->freeInstallManager_ = mockFreeInstallManager;

    sptr<IRemoteObject> callerToken;
    std::string appId = "";
    const std::string startTime = "";
    AtomicServiceStartupRule rule;
    EXPECT_EQ(abilityMs_->QueryAtomicServiceStartupRule(callerToken, appId, startTime, rule), INNER_ERR);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest QueryAtomicServiceStartupRule_011 end");
}

/*
 * Feature: AbilityManagerService
 * Name: GetMissionIdByAbilityTokenInner_001
 * Function: GetMissionIdByAbilityTokenInner
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetMissionIdByAbilityTokenInner
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, GetMissionIdByAbilityTokenInner_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest GetMissionIdByAbilityTokenInner_001 start");
    MyStatus::GetInstance().arGetAbilityRecord_ = nullptr;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    EXPECT_EQ(abilityMs_->GetMissionIdByAbilityTokenInner(token), -1);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest GetMissionIdByAbilityTokenInner_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: GetMissionIdByAbilityTokenInner_002
 * Function: GetMissionIdByAbilityTokenInner
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetMissionIdByAbilityTokenInner
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, GetMissionIdByAbilityTokenInner_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest GetMissionIdByAbilityTokenInner_002 start");
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->ownerMissionUserId_ = 1;
    MyStatus::GetInstance().arGetAbilityRecord_ = record;
    MyStatus::GetInstance().sbjIsSceneBoardEnabled_ = true;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUserId_ = false;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    EXPECT_EQ(abilityMs_->GetMissionIdByAbilityTokenInner(token), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest GetMissionIdByAbilityTokenInner_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: GetMissionIdByAbilityTokenInner_003
 * Function: GetMissionIdByAbilityTokenInner
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetMissionIdByAbilityTokenInner
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, GetMissionIdByAbilityTokenInner_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest GetMissionIdByAbilityTokenInner_003 start");
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->ownerMissionUserId_ = 1;
    MyStatus::GetInstance().arGetAbilityRecord_ = record;
    MyStatus::GetInstance().sbjIsSceneBoardEnabled_ = true;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUserId_ = true;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;

    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    EXPECT_EQ(abilityMs_->GetMissionIdByAbilityTokenInner(token), ERR_OK);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest GetMissionIdByAbilityTokenInner_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: GetMissionIdByAbilityTokenInner_004
 * Function: GetMissionIdByAbilityTokenInner
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetMissionIdByAbilityTokenInner
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, GetMissionIdByAbilityTokenInner_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest GetMissionIdByAbilityTokenInner_004 start");
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->ownerMissionUserId_ = 1;
    MyStatus::GetInstance().arGetAbilityRecord_ = record;
    MyStatus::GetInstance().sbjIsSceneBoardEnabled_ = false;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUserId_ = true;
    MyStatus::GetInstance().smhGetMissionListManagerByUserId_ = false;
    
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;

    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    EXPECT_EQ(abilityMs_->GetMissionIdByAbilityTokenInner(token), -1);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest GetMissionIdByAbilityTokenInner_004 end");
}

/*
 * Feature: AbilityManagerService
 * Name: DelegatorDoAbilityForeground_001
 * Function: DelegatorDoAbilityForeground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DelegatorDoAbilityForeground
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, DelegatorDoAbilityForeground_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DelegatorDoAbilityForeground_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    sptr<IRemoteObject> token = nullptr;
    EXPECT_EQ(abilityMs_->DelegatorDoAbilityForeground(token), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DelegatorDoAbilityForeground_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: DelegatorDoAbilityForeground_002
 * Function: DelegatorDoAbilityForeground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DelegatorDoAbilityForeground
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, DelegatorDoAbilityForeground_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DelegatorDoAbilityForeground_002 start");
    MyStatus::GetInstance().arGetAbilityRecord_ = nullptr;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    EXPECT_EQ(abilityMs_->DelegatorDoAbilityForeground(token), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DelegatorDoAbilityForeground_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: DelegatorDoAbilityForeground_003
 * Function: DelegatorDoAbilityForeground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DelegatorDoAbilityForeground
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, DelegatorDoAbilityForeground_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DelegatorDoAbilityForeground_003 start");

    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->pid_ = 0;
    MyStatus::GetInstance().arGetAbilityRecord_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    EXPECT_EQ(abilityMs_->DelegatorDoAbilityForeground(token), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DelegatorDoAbilityForeground_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: DelegatorDoAbilityForeground_004
 * Function: DelegatorDoAbilityForeground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DelegatorDoAbilityForeground
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, DelegatorDoAbilityForeground_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DelegatorDoAbilityForeground_004 start");
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->pid_ = 1;
    MyStatus::GetInstance().arGetAbilityRecord_ = record;
    MyStatus::GetInstance().sbjIsSceneBoardEnabled_ = true;
    MyStatus::GetInstance().ualmGetSessionIdByAbilityToken_ = 0;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    EXPECT_EQ(abilityMs_->DelegatorDoAbilityForeground(token), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DelegatorDoAbilityForeground_004 end");
}

/*
 * Feature: AbilityManagerService
 * Name: DelegatorDoAbilityForeground_005
 * Function: DelegatorDoAbilityForeground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DelegatorDoAbilityForeground
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, DelegatorDoAbilityForeground_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DelegatorDoAbilityForeground_005 start");
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    record->ownerMissionUserId_ = 1;
    EXPECT_NE(record, nullptr);
    record->pid_ = 1;
    MyStatus::GetInstance().arGetAbilityRecord_ = record;
    MyStatus::GetInstance().sbjIsSceneBoardEnabled_ = true;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUserId_ = true;
    MyStatus::GetInstance().ualmGetSessionIdByAbilityToken_ = 1;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    EXPECT_EQ(abilityMs_->DelegatorDoAbilityForeground(token), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DelegatorDoAbilityForeground_005 end");
}

/*
 * Feature: AbilityManagerService
 * Name: DelegatorDoAbilityForeground_006
 * Function: DelegatorDoAbilityForeground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DelegatorDoAbilityForeground
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, DelegatorDoAbilityForeground_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DelegatorDoAbilityForeground_006 start");
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    record->ownerMissionUserId_ = 1;
    EXPECT_NE(record, nullptr);
    record->pid_ = 1;
    MyStatus::GetInstance().arGetAbilityRecord_ = record;
    MyStatus::GetInstance().sbjIsSceneBoardEnabled_ = false;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUserId_ = true;
    MyStatus::GetInstance().ualmGetSessionIdByAbilityToken_ = 1;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    EXPECT_EQ(abilityMs_->DelegatorDoAbilityForeground(token), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DelegatorDoAbilityForeground_006 end");
}

/*
 * Feature: AbilityManagerService
 * Name: DoAbilityForeground_001
 * Function: DoAbilityForeground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DoAbilityForeground
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, DoAbilityForeground_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DoAbilityForeground_001 start");

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    sptr<IRemoteObject> token = nullptr;
    uint32_t flag = 0;
    EXPECT_EQ(abilityMs_->DoAbilityForeground(token, flag), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DoAbilityForeground_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: DoAbilityForeground_002
 * Function: DoAbilityForeground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DoAbilityForeground
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, DoAbilityForeground_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DoAbilityForeground_002 start");
    MyStatus::GetInstance().arGetAbilityInfo_.type = AbilityType::UNKNOWN;
    MyStatus::GetInstance().smhVerificationAllToken_ = false;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;

    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    uint32_t flag = 0;
    EXPECT_EQ(abilityMs_->DoAbilityForeground(token, flag), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DoAbilityForeground_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: DoAbilityForeground_003
 * Function: DoAbilityForeground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DoAbilityForeground
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, DoAbilityForeground_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DoAbilityForeground_003 start");
    MyStatus::GetInstance().arGetAbilityInfo_.type = AbilityType::UNKNOWN;
    MyStatus::GetInstance().smhVerificationAllToken_ = true;
    MyStatus::GetInstance().arGetAbilityRecord_ = nullptr;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;

    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    uint32_t flag = 0;
    EXPECT_EQ(abilityMs_->DoAbilityForeground(token, flag), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DoAbilityForeground_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: DoAbilityForeground_004
 * Function: DoAbilityForeground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DoAbilityForeground
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, DoAbilityForeground_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DoAbilityForeground_004 start");
    MyStatus::GetInstance().arGetAbilityInfo_.type = AbilityType::UNKNOWN;
    MyStatus::GetInstance().smhVerificationAllToken_ = true;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    record->ownerMissionUserId_ = 1;
    MyStatus::GetInstance().arGetAbilityRecord_ = record;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);

    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;

    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    uint32_t flag = 0;
    EXPECT_EQ(abilityMs_->DoAbilityForeground(token, flag), ERR_WRONG_INTERFACE_CALL);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DoAbilityForeground_004 end");
}

/*
 * Feature: AbilityManagerService
 * Name: DoAbilityForeground_005
 * Function: DoAbilityForeground
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService DoAbilityForeground
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, DoAbilityForeground_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DoAbilityForeground_005 start");
    MyStatus::GetInstance().arGetAbilityInfo_.type = AbilityType::PAGE;
    MyStatus::GetInstance().smhVerificationAllToken_ = true;
    Want want;
    OHOS::AppExecFwk::AbilityInfo abilityInfo;
    OHOS::AppExecFwk::ApplicationInfo applicationInfo;
    std::shared_ptr<AbilityRecord> record = std::make_shared<AbilityRecord>(want, abilityInfo, applicationInfo);
    EXPECT_NE(record, nullptr);
    MyStatus::GetInstance().ualmGetAbilityRecordByToken_ = record;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUserId_ = true;
    MyStatus::GetInstance().smhGetMissionListManagerByUserId_ = true;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentUIAbilityManager = std::make_shared<UIAbilityLifecycleManager>(0);
    EXPECT_NE(mockCurrentUIAbilityManager, nullptr);
    auto currentMissionListManager = std::make_shared<MissionListManager>(0);
    EXPECT_NE(currentMissionListManager, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = mockCurrentUIAbilityManager;
    abilityMs_->subManagersHelper_->currentMissionListManager_ = currentMissionListManager;
    
    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    uint32_t flag = 0;
    EXPECT_EQ(abilityMs_->DoAbilityForeground(token, flag), ERR_OK);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest DoAbilityForeground_005 end");
}

/*
 * Feature: AbilityManagerService
 * Name: RequestDialogServiceInner_001
 * Function: RequestDialogServiceInner
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService RequestDialogServiceInner
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, RequestDialogServiceInner_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest RequestDialogServiceInner_001 start");

    Want want;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    sptr<IRemoteObject> token = nullptr;
    uint32_t flag = 0;
    EXPECT_EQ(abilityMs_->RequestDialogServiceInner(want, token, 0, 0), ERR_INVALID_CALLER);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest RequestDialogServiceInner_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: RequestDialogServiceInner_002
 * Function: RequestDialogServiceInner
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService RequestDialogServiceInner
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, RequestDialogServiceInner_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest RequestDialogServiceInner_002 start");

    MyStatus::GetInstance().smhVerificationAllToken_ = false;
    Want want;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    uint32_t flag = 0;
    EXPECT_EQ(abilityMs_->RequestDialogServiceInner(want, token, 0, 0), ERR_INVALID_CALLER);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest RequestDialogServiceInner_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: RequestDialogServiceInner_003
 * Function: RequestDialogServiceInner
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService RequestDialogServiceInner
 */
HWTEST_F(AbilityManagerServiceThirteenthTest, RequestDialogServiceInner_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest RequestDialogServiceInner_003 start");

    MyStatus::GetInstance().smhVerificationAllToken_ = true;
    Want want;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    sptr<IRemoteObject> token = MockToken(AbilityType::PAGE);
    uint32_t flag = 0;
    EXPECT_EQ(abilityMs_->RequestDialogServiceInner(want, token, 0, 0), ERR_INVALID_VALUE);

    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceThirteenthTest RequestDialogServiceInner_003 end");
}
} // namespace AAFwk
} // namespace OHOS
