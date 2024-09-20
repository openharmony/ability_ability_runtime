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

#include "mock_ability_manager_service.h"
#include "ability_manager_errors.h"
#include "app_utils.h"
#include "hilog_tag_wrapper.h"
#include "permission_verification.h"
#include "process_options.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace AAFwk {
namespace {
const char* START_OPTIONS_WITH_ANIMATION = "persist.sys.abilityms.start_options_with_animation";
}  // namespace
class AbilityManagerServiceSeventhTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AbilityManagerServiceSeventhTest::SetUpTestCase() {}

void AbilityManagerServiceSeventhTest::TearDownTestCase() {}

void AbilityManagerServiceSeventhTest::SetUp() {}

void AbilityManagerServiceSeventhTest::TearDown() {}

/*
 * Feature: AbilityManagerService
 * Name: BlockAllAppStart_001
 * Function: BlockAllAppStart
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService BlockAllAppStart
 */
HWTEST_F(AbilityManagerServiceSeventhTest, BlockAllAppStart_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest BlockAllAppStart_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    PermissionVerification::flag = PermissionVerification::FLAG::IS_SA_CALL;
    PermissionVerification::hasBlockAllAppStartPermission = true;
    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);
    EXPECT_EQ(PermissionVerification::GetInstance()->VerifyBlockAllAppStartPermission(), true);
    auto retCode = abilityMs_->BlockAllAppStart(true);
    EXPECT_EQ(retCode, ERR_OK);
    EXPECT_EQ(abilityMs_->shouldBlockAllAppStart_, true);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest BlockAllAppStart_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: BlockAllAppStart_002
 * Function: BlockAllAppStart
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService BlockAllAppStart
 */
HWTEST_F(AbilityManagerServiceSeventhTest, BlockAllAppStart_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest BlockAllAppStart_002 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    AppUtils::isStartOptionsWithAnimation_ = false;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), false);
    auto retCode = abilityMs_->BlockAllAppStart(true);
    EXPECT_EQ(retCode, ERR_PERMISSION_DENIED);
    EXPECT_EQ(abilityMs_->shouldBlockAllAppStart_, false);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest BlockAllAppStart_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: BlockAllAppStart_003
 * Function: BlockAllAppStart
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService BlockAllAppStart
 */
HWTEST_F(AbilityManagerServiceSeventhTest, BlockAllAppStart_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest BlockAllAppStart_003 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);
    PermissionVerification::flag = PermissionVerification::FLAG::IS_SA_CALL;
    PermissionVerification::hasBlockAllAppStartPermission = false;
    EXPECT_EQ(PermissionVerification::GetInstance()->VerifyBlockAllAppStartPermission(), false);
    auto retCode = abilityMs_->BlockAllAppStart(true);
    EXPECT_EQ(retCode, ERR_PERMISSION_DENIED);
    EXPECT_EQ(abilityMs_->shouldBlockAllAppStart_, false);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest BlockAllAppStart_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: BlockAllAppStart_004
 * Function: BlockAllAppStart
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService BlockAllAppStart
 */
HWTEST_F(AbilityManagerServiceSeventhTest, BlockAllAppStart_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest BlockAllAppStart_004 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    PermissionVerification::flag = PermissionVerification::FLAG::IS_SA_CALL;
    PermissionVerification::hasBlockAllAppStartPermission = true;
    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);
    EXPECT_EQ(PermissionVerification::GetInstance()->VerifyBlockAllAppStartPermission(), true);
    auto retCode = abilityMs_->BlockAllAppStart(false);
    EXPECT_EQ(retCode, ERR_OK);
    EXPECT_EQ(abilityMs_->shouldBlockAllAppStart_, false);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest BlockAllAppStart_004 end");
}

/*
 * Feature: AbilityManagerService
 * Name: ShouldBlockAllAppStart_001
 * Function: ShouldBlockAllAppStart
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService ShouldBlockAllAppStart
 */
HWTEST_F(AbilityManagerServiceSeventhTest, ShouldBlockAllAppStart_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest ShouldBlockAllAppStart_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);
    abilityMs_->shouldBlockAllAppStart_ = true;
    EXPECT_EQ(abilityMs_->shouldBlockAllAppStart_, true);
    EXPECT_EQ(abilityMs_->ShouldBlockAllAppStart(), true);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest ShouldBlockAllAppStart_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: ShouldBlockAllAppStart_002
 * Function: ShouldBlockAllAppStart
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService ShouldBlockAllAppStart
 */
HWTEST_F(AbilityManagerServiceSeventhTest, ShouldBlockAllAppStart_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest ShouldBlockAllAppStart_002 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    AppUtils::isStartOptionsWithAnimation_ = false;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), false);
    EXPECT_EQ(abilityMs_->ShouldBlockAllAppStart(), false);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest ShouldBlockAllAppStart_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: ShouldBlockAllAppStart_003
 * Function: ShouldBlockAllAppStart
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService ShouldBlockAllAppStart
 */
HWTEST_F(AbilityManagerServiceSeventhTest, ShouldBlockAllAppStart_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest ShouldBlockAllAppStart_003 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    AppUtils::isStartOptionsWithAnimation_ = true;
    EXPECT_EQ(AppUtils::GetInstance().IsStartOptionsWithAnimation(), true);
    abilityMs_->shouldBlockAllAppStart_ = false;
    EXPECT_EQ(abilityMs_->shouldBlockAllAppStart_, false);
    EXPECT_EQ(abilityMs_->ShouldBlockAllAppStart(), false);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest ShouldBlockAllAppStart_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckProcessOptions_001
 * Function: CheckProcessOptions
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckProcessOptions
 */
HWTEST_F(AbilityManagerServiceSeventhTest, CheckProcessOptions_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest CheckProcessOptions_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    PermissionVerification::flag = PermissionVerification::FLAG::IS_SA_CALL;
    PermissionVerification::hasStartUIAbilityToHiddenPermission = true;
    EXPECT_EQ(PermissionVerification::GetInstance()->VerifyStartUIAbilityToHiddenPermission(), true);
    Want want;
    want.SetElementName("bundle", "ability");
    StartOptions startOptions;
    startOptions.processOptions = std::make_shared<ProcessOptions>();
    startOptions.processOptions->processMode = ProcessMode::NO_ATTACHMENT;
    startOptions.processOptions->startupVisibility = StartupVisibility::STARTUP_HIDE;
    auto retCode = abilityMs_->CheckProcessOptions(want, startOptions, -1);
    EXPECT_EQ(retCode, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest CheckProcessOptions_001 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckProcessOptions_002
 * Function: CheckProcessOptions
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckProcessOptions
 */
HWTEST_F(AbilityManagerServiceSeventhTest, CheckProcessOptions_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest CheckProcessOptions_002 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    Want want;
    want.SetElementName("bundle", "ability");
    StartOptions startOptions;
    auto retCode = abilityMs_->CheckProcessOptions(want, startOptions, -1);
    EXPECT_EQ(retCode, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest CheckProcessOptions_002 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckProcessOptions_003
 * Function: CheckProcessOptions
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckProcessOptions
 */
HWTEST_F(AbilityManagerServiceSeventhTest, CheckProcessOptions_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest CheckProcessOptions_003 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    Want want;
    want.SetElementName("bundle", "ability");
    StartOptions startOptions;
    startOptions.processOptions = std::make_shared<ProcessOptions>();
    auto retCode = abilityMs_->CheckProcessOptions(want, startOptions, -1);
    EXPECT_EQ(retCode, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest CheckProcessOptions_003 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckProcessOptions_004
 * Function: CheckProcessOptions
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckProcessOptions
 */
HWTEST_F(AbilityManagerServiceSeventhTest, CheckProcessOptions_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest CheckProcessOptions_004 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    PermissionVerification::flag = PermissionVerification::FLAG::IS_SA_CALL;
    PermissionVerification::hasStartUIAbilityToHiddenPermission = true;
    EXPECT_EQ(PermissionVerification::GetInstance()->VerifyStartUIAbilityToHiddenPermission(), true);
    Want want;
    want.SetElementName("bundle", "ability");
    StartOptions startOptions;
    startOptions.processOptions = std::make_shared<ProcessOptions>();
    startOptions.processOptions->processMode = ProcessMode::NO_ATTACHMENT;
    auto retCode = abilityMs_->CheckProcessOptions(want, startOptions, -1);
    EXPECT_EQ(retCode, ERR_NOT_SELF_APPLICATION);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest CheckProcessOptions_004 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckProcessOptions_005
 * Function: CheckProcessOptions
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckProcessOptions
 */
HWTEST_F(AbilityManagerServiceSeventhTest, CheckProcessOptions_005, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest CheckProcessOptions_005 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    PermissionVerification::flag = 0;
    Want want;
    want.SetElementName("bundle", "ability");
    StartOptions startOptions;
    startOptions.processOptions = std::make_shared<ProcessOptions>();
    startOptions.processOptions->processMode = ProcessMode::NO_ATTACHMENT;
    startOptions.processOptions->startupVisibility = StartupVisibility::STARTUP_HIDE;
    auto retCode = abilityMs_->CheckProcessOptions(want, startOptions, -1);
    EXPECT_EQ(retCode, ERR_NOT_SELF_APPLICATION);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest CheckProcessOptions_005 end");
}

/*
 * Feature: AbilityManagerService
 * Name: CheckProcessOptions_006
 * Function: CheckProcessOptions
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService CheckProcessOptions
 */
HWTEST_F(AbilityManagerServiceSeventhTest, CheckProcessOptions_006, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest CheckProcessOptions_006 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_NE(abilityMs_, nullptr);
    PermissionVerification::flag = PermissionVerification::FLAG::IS_SA_CALL;
    PermissionVerification::hasStartUIAbilityToHiddenPermission = false;
    EXPECT_EQ(PermissionVerification::GetInstance()->VerifyStartUIAbilityToHiddenPermission(), false);
    Want want;
    want.SetElementName("bundle", "ability");
    StartOptions startOptions;
    startOptions.processOptions = std::make_shared<ProcessOptions>();
    startOptions.processOptions->processMode = ProcessMode::NO_ATTACHMENT;
    startOptions.processOptions->startupVisibility = StartupVisibility::STARTUP_HIDE;
    auto retCode = abilityMs_->CheckProcessOptions(want, startOptions, -1);
    EXPECT_EQ(retCode, ERR_NOT_SELF_APPLICATION);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSeventhTest CheckProcessOptions_006 end");
}
}  // namespace AAFwk
}  // namespace OHOS
