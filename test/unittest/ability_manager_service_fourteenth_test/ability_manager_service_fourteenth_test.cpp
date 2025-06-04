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

namespace OHOS {
namespace AAFwk {
class AbilityManagerServiceFourteenthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<AbilityRecord> MockAbilityRecord(AbilityType);
    sptr<Token> MockToken(AbilityType);
};

void AbilityManagerServiceFourteenthTest::SetUpTestCase() {}

void AbilityManagerServiceFourteenthTest::TearDownTestCase() {}

void AbilityManagerServiceFourteenthTest::SetUp() {}

void AbilityManagerServiceFourteenthTest::TearDown() {}

std::shared_ptr<AbilityRecord> AbilityManagerServiceFourteenthTest::MockAbilityRecord(AbilityType abilityType)
{
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.test.demo";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = abilityType;
    return AbilityRecord::CreateAbilityRecord(abilityRequest);
}

sptr<Token> AbilityManagerServiceFourteenthTest::MockToken(AbilityType abilityType)
{
    std::shared_ptr<AbilityRecord> abilityRecord = MockAbilityRecord(abilityType);
    if (!abilityRecord) {
        return nullptr;
    }
    return abilityRecord->GetToken();
}

/*
 * Feature: AbilityManagerService
 * Name: NotifyDebugAssertResult_001
 * Function: NotifyDebugAssertResult
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService NotifyDebugAssertResult
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, NotifyDebugAssertResult_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest NotifyDebugAssertResult_001 start");
    MyStatus::GetInstance().paramGetBoolParameter_ = false;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    int retCode = abilityMs_->NotifyDebugAssertResult(0, AAFwk::UserStatus::ASSERT_TERMINATE);
    EXPECT_EQ(retCode, ERR_NOT_SUPPORTED_PRODUCT_TYPE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest NotifyDebugAssertResult_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: NotifyDebugAssertResult_002
 * Function: NotifyDebugAssertResult
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService NotifyDebugAssertResult
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, NotifyDebugAssertResult_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest NotifyDebugAssertResult_002 start");
    MyStatus::GetInstance().paramGetBoolParameter_ = true;
    MyStatus::GetInstance().permPermission_ = 0;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    int retCode = abilityMs_->NotifyDebugAssertResult(0, AAFwk::UserStatus::ASSERT_TERMINATE);
    EXPECT_EQ(retCode, ERR_PERMISSION_DENIED);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest NotifyDebugAssertResult_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: NotifyDebugAssertResult_003
 * Function: NotifyDebugAssertResult
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService NotifyDebugAssertResult
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, NotifyDebugAssertResult_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest NotifyDebugAssertResult_003 start");
    MyStatus::GetInstance().paramGetBoolParameter_ = true;
    MyStatus::GetInstance().permPermission_ = 1;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    int retCode = abilityMs_->NotifyDebugAssertResult(0, AAFwk::UserStatus::ASSERT_TERMINATE);
    EXPECT_EQ(retCode, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest NotifyDebugAssertResult_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: NotifyDebugAssertResult_004
 * Function: NotifyDebugAssertResult
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService NotifyDebugAssertResult
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, NotifyDebugAssertResult_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest NotifyDebugAssertResult_004 start");
    MyStatus::GetInstance().paramGetBoolParameter_ = true;
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = false;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    int retCode = abilityMs_->NotifyDebugAssertResult(0, AAFwk::UserStatus::ASSERT_TERMINATE);
    EXPECT_EQ(retCode, ERR_NOT_SYSTEM_APP);
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest NotifyDebugAssertResult_004 end");
}

/*
 * Feature: AbilityManagerService
 * Name: GetForegroundUIAbilities_001
 * Function: GetForegroundUIAbilities
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetForegroundUIAbilities
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, GetForegroundUIAbilities_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetForegroundUIAbilities_001 start");
    MyStatus::GetInstance().permPermission_ = false;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    std::vector<AppExecFwk::AbilityStateData> list;
    int retCode = abilityMs_->GetForegroundUIAbilities(list);
    EXPECT_EQ(retCode, CHECK_PERMISSION_FAILED);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetForegroundUIAbilities_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: GetForegroundUIAbilities_002
 * Function:GetForegroundUIAbilities
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetForegroundUIAbilities
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, GetForegroundUIAbilities_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetForegroundUIAbilities_002 start");
    MyStatus::GetInstance().permPermission_ = true;
    MyStatus::GetInstance().sbjIsSceneBoardEnabled_ = true;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUserId_ = false;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = nullptr;

    std::vector<AppExecFwk::AbilityStateData> list;
    int retCode = abilityMs_->GetForegroundUIAbilities(list);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetForegroundUIAbilities_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: GetForegroundUIAbilities_003
 * Function:GetForegroundUIAbilities
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetForegroundUIAbilities
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, GetForegroundUIAbilities_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetForegroundUIAbilities_003 start");
    MyStatus::GetInstance().permPermission_ = true;
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

    std::vector<AppExecFwk::AbilityStateData> list;
    int retCode = abilityMs_->GetForegroundUIAbilities(list);
    EXPECT_EQ(retCode, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetForegroundUIAbilities_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: GetForegroundUIAbilities_004
 * Function:GetForegroundUIAbilities
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetForegroundUIAbilities
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, GetForegroundUIAbilities_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetForegroundUIAbilities_004 start");
    MyStatus::GetInstance().permPermission_ = true;
    MyStatus::GetInstance().sbjIsSceneBoardEnabled_ = false;
    MyStatus::GetInstance().smhGetMissionListManagerByUserId_ = false;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentMissionListManager_ = nullptr;

    std::vector<AppExecFwk::AbilityStateData> list;
    int retCode = abilityMs_->GetForegroundUIAbilities(list);
    EXPECT_EQ(retCode, ERR_NULL_OBJECT);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetForegroundUIAbilities_004 end");
}

/*
 * Feature: AbilityManagerService
 * Name: GetForegroundUIAbilities_005
 * Function:GetForegroundUIAbilities
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetForegroundUIAbilities
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, GetForegroundUIAbilities_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetForegroundUIAbilities_005 start");
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = false;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    std::vector<AppExecFwk::AbilityStateData> list;
    int retCode = abilityMs_->GetForegroundUIAbilities(list);
    EXPECT_EQ(retCode, ERR_NOT_SYSTEM_APP);
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetForegroundUIAbilities_005 end");
}

/*
 * Feature: AbilityManagerService
 * Name: IsCallerSceneBoard_001
 * Function: IsCallerSceneBoard
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsCallerSceneBoard
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, IsCallerSceneBoard_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest IsCallerSceneBoard_001 start");
    MyStatus::GetInstance().smhGetConnectManagerByToken_ = false;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    int retCode = abilityMs_->IsCallerSceneBoard();
    EXPECT_FALSE(retCode);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest IsCallerSceneBoard_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: IsCallerSceneBoard_002
 * Function: IsCallerSceneBoard
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsCallerSceneBoard
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, IsCallerSceneBoard_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest IsCallerSceneBoard_002 start");
    MyStatus::GetInstance().smhGetConnectManagerByToken_ = true;
    
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentConnectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(mockCurrentConnectManager, nullptr);
    mockCurrentConnectManager->sceneBoardTokenId_ = 0;
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentConnectManager_ = mockCurrentConnectManager;

    int retCode = abilityMs_->IsCallerSceneBoard();
    EXPECT_FALSE(retCode);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest IsCallerSceneBoard_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: IsCallerSceneBoard_003
 * Function: IsCallerSceneBoard
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsCallerSceneBoard
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, IsCallerSceneBoard_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest IsCallerSceneBoard_003 start");
    MyStatus::GetInstance().smhGetConnectManagerByToken_ = true;
    MyStatus::GetInstance().ipcGetCallingTokenID_ = 0;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentConnectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(mockCurrentConnectManager, nullptr);
    mockCurrentConnectManager->sceneBoardTokenId_ = 1;
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentConnectManager_ = mockCurrentConnectManager;

    int retCode = abilityMs_->IsCallerSceneBoard();
    EXPECT_FALSE(retCode);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest IsCallerSceneBoard_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: IsCallerSceneBoard_004
 * Function: IsCallerSceneBoard
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsCallerSceneBoard
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, IsCallerSceneBoard_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest IsCallerSceneBoard_004 start");
    MyStatus::GetInstance().smhGetConnectManagerByToken_ = true;
    MyStatus::GetInstance().ipcGetCallingTokenID_ = 1;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    auto mockCurrentConnectManager = std::make_shared<AbilityConnectManager>(0);
    EXPECT_NE(mockCurrentConnectManager, nullptr);
    mockCurrentConnectManager->sceneBoardTokenId_ = 1;
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentConnectManager_ = mockCurrentConnectManager;

    int retCode = abilityMs_->IsCallerSceneBoard();
    EXPECT_TRUE(retCode);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest IsCallerSceneBoard_004 end");
}

/*
 * Feature: AbilityManagerService
 * Name: AcquireShareData_001
 * Function: AcquireShareData
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService AcquireShareData
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, AcquireShareData_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest AcquireShareData_001 start");
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = false;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    int retCode = abilityMs_->AcquireShareData(0, nullptr);
    EXPECT_EQ(retCode, ERR_NOT_SYSTEM_APP);
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest AcquireShareData_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: AcquireShareData_002
 * Function: AcquireShareData
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService AcquireShareData
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, AcquireShareData_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest AcquireShareData_002 start");
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    MyStatus::GetInstance().sbjIsSceneBoardEnabled_ = true;
    MyStatus::GetInstance().smhGetUIAbilityManagerByUserId_ = false;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = nullptr;

    int retCode = abilityMs_->AcquireShareData(0, nullptr);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest AcquireShareData_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: AcquireShareData_003
 * Function: AcquireShareData
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService AcquireShareData
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, AcquireShareData_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest AcquireShareData_003 start");
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
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

    int retCode = abilityMs_->AcquireShareData(0, nullptr);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest AcquireShareData_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: AcquireShareData_004
 * Function: AcquireShareData
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService AcquireShareData
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, AcquireShareData_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest AcquireShareData_004 start");
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    MyStatus::GetInstance().sbjIsSceneBoardEnabled_ = false;
    MyStatus::GetInstance().smhGetMissionListManagerByUserId_ = false;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    auto mockSubManagersHelper = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    EXPECT_NE(mockSubManagersHelper, nullptr);
    abilityMs_->subManagersHelper_ = mockSubManagersHelper;
    abilityMs_->subManagersHelper_->currentMissionListManager_ = nullptr;

    int retCode = abilityMs_->AcquireShareData(0, nullptr);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest AcquireShareData_004 end");
}

/*
 * Feature: AbilityManagerService
 * Name: SetMissionIcon_001
 * Function: SetMissionIcon
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService SetMissionIcon
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, SetMissionIcon_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest SetMissionIcon_001 start");
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = false;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    int retCode = abilityMs_->SetMissionIcon(nullptr, nullptr);
    EXPECT_EQ(retCode, ERR_NOT_SYSTEM_APP);
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest SetMissionIcon_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: SetMissionIcon_002
 * Function: SetMissionIcon
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService SetMissionIcon
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, SetMissionIcon_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest SetMissionIcon_002 start");
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    MyStatus::GetInstance().arGetAbilityRecord_ = nullptr;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    int retCode = abilityMs_->SetMissionIcon(nullptr, nullptr);
    EXPECT_EQ(retCode, -1);
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest SetMissionIcon_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: SetMissionIcon_003
 * Function: SetMissionIcon
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService SetMissionIcon
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, SetMissionIcon_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest SetMissionIcon_003 start");
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    MyStatus::GetInstance().arGetAbilityRecord_ = MockAbilityRecord(AbilityType::PAGE);
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = 1;
    MyStatus::GetInstance().ipcGetCallingTokenID_ = 0;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    int retCode = abilityMs_->SetMissionIcon(nullptr, nullptr);
    EXPECT_EQ(retCode, -1);
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest SetMissionIcon_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: SetMissionIcon_004
 * Function: SetMissionIcon
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService SetMissionIcon
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, SetMissionIcon_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest SetMissionIcon_004 start");
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    MyStatus::GetInstance().arGetAbilityRecord_ = MockAbilityRecord(AbilityType::PAGE);
    MyStatus::GetInstance().arGetAbilityInfo_.applicationInfo.accessTokenId = 1;
    MyStatus::GetInstance().ipcGetCallingTokenID_ = 1;

    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    int retCode = abilityMs_->SetMissionIcon(nullptr, nullptr);
    EXPECT_EQ(retCode, -1);
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest SetMissionIcon_004 end");
}

/*
 * Feature: AbilityManagerService
 * Name: GetTopAbility_001
 * Function: GetTopAbility
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetTopAbility
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, GetTopAbility_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetTopAbility_001 start");
    MyStatus::GetInstance().permPermission_ = 0;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    sptr<IRemoteObject> token = nullptr; // MockToken(AbilityType::PAGE);
    int retCode = abilityMs_->GetTopAbility(token);
    EXPECT_EQ(retCode, CHECK_PERMISSION_FAILED);
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetTopAbility_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: GetTopAbility_002
 * Function: GetTopAbility
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetTopAbility
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, GetTopAbility_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetTopAbility_002 start");
    MyStatus::GetInstance().permPermission_ = 1;
    MyStatus::GetInstance().sbjIsSceneBoardEnabled_ = true;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    sptr<IRemoteObject> token = nullptr; // MockToken(AbilityType::PAGE);
    int retCode = abilityMs_->GetTopAbility(token);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetTopAbility_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: GetTopAbility_003
 * Function: GetTopAbility
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetTopAbility
 */
HWTEST_F(AbilityManagerServiceFourteenthTest, GetTopAbility_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetTopAbility_003 start");
    MyStatus::GetInstance().permPermission_ = 1;
    MyStatus::GetInstance().sbjIsSceneBoardEnabled_ = false;
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    abilityMs_->wmsHandler_ = nullptr;
    sptr<IRemoteObject> token = nullptr;
    int retCode = abilityMs_->GetTopAbility(token);
    EXPECT_EQ(retCode, ERR_INVALID_VALUE);
    MyStatus::GetInstance().perJudgeCallerIsAllowedToUseSystemAPI_ = true;
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceFourteenthTest GetTopAbility_003 end");
}
} // namespace AAFwk
} // namespace OHOS
