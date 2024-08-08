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

#define private public
#define protected public
#include "ability_manager_service.h"
#include "ability_connect_manager.h"
#include "ability_connection.h"
#include "ability_start_setting.h"
#include "recovery_param.h"
#undef private
#undef protected

#include "ability_manager_errors.h"
#include "ability_manager_stub_mock_test.h"
#include "connection_observer_errors.h"
#include "hilog_tag_wrapper.h"
#include "session/host/include/session.h"
#include "scene_board_judgement.h"
#include "mock_sa_call.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::AppExecFwk::AbilityType;
using OHOS::AppExecFwk::ExtensionAbilityType;
namespace OHOS {
namespace AAFwk {
namespace {
const int32_t USER_ID_U100 = 100;
const int32_t APP_MEMORY_SIZE = 512;
}  // namespace
class AbilityManagerServiceSixthTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

public:
    AbilityRequest abilityRequest_{};
    Want want_{};
};

void AbilityManagerServiceSixthTest::SetUpTestCase() {}

void AbilityManagerServiceSixthTest::TearDownTestCase() {}

void AbilityManagerServiceSixthTest::SetUp() {}

void AbilityManagerServiceSixthTest::TearDown() {}

/*
 * Feature: AbilityManagerService
 * Function: LockMissionForCleanup
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService LockMissionForCleanup
 */
HWTEST_F(AbilityManagerServiceSixthTest, LockMissionForCleanup_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest LockMissionForCleanup_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_EQ(abilityMs_->LockMissionForCleanup(1), CHECK_PERMISSION_FAILED);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest LockMissionForCleanup_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: ReleaseCall
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService ReleaseCall
 */
HWTEST_F(AbilityManagerServiceSixthTest, ReleaseCall_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest ReleaseCall_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    abilityMs_->subManagersHelper_ = std::make_shared<SubManagersHelper>(nullptr, nullptr);
    abilityMs_->subManagersHelper_->currentUIAbilityManager_ = std::make_shared<UIAbilityLifecycleManager>();
    AppExecFwk::ElementName element;
    EXPECT_EQ(abilityMs_->ReleaseCall(nullptr, element), ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest ReleaseCall_001 end");
}

/**
 * @tc.number: ReportDrawnCompleted_001
 * @tc.name: ReportDrawnCompleted
 * @tc.desc: After passing in a callerToken with parameter nullptr, INNER_ERR is returned
 */
HWTEST_F(AbilityManagerServiceSixthTest, ReportDrawnCompleted_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest ReportDrawnCompleted_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    sptr<IRemoteObject> callerToken = nullptr;
    EXPECT_EQ(abilityMs_->ReportDrawnCompleted(callerToken), INNER_ERR);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest ReportDrawnCompleted_001 end");
}

/**
 * @tc.number: ReportDrawnCompleted_002
 * @tc.name: ReportDrawnCompleted
 * @tc.desc: After passing in a callerToken with parameter nullptr, INNER_ERR is returned
 */
HWTEST_F(AbilityManagerServiceSixthTest, ReportDrawnCompleted_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest ReportDrawnCompleted_002 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    sptr<IRemoteObject> callerToken = new AbilityManagerStubTestMock();
    EXPECT_EQ(abilityMs_->ReportDrawnCompleted(callerToken), INNER_ERR);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest ReportDrawnCompleted_002 end");
}

/*
 * Feature: AbilityManagerService
 * Function: StartUser
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService StartUser
 */
HWTEST_F(AbilityManagerServiceSixthTest, StartUser_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartUser_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_EQ(abilityMs_->StartUser(USER_ID_U100, nullptr), CHECK_PERMISSION_FAILED);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest StartUser_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: RegisterSessionHandler
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService RegisterSessionHandler
 */
HWTEST_F(AbilityManagerServiceSixthTest, RegisterSessionHandler_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest RegisterSessionHandler_001 start");
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    EXPECT_EQ(abilityMs_->RegisterSessionHandler(nullptr), ERR_WRONG_INTERFACE_CALL);
    TAG_LOGI(AAFwkTag::TEST, "AbilityManagerServiceSixthTest RegisterSessionHandler_001 end");
}

/*
 * Feature: AbilityManagerService
 * Function: IsAbilityControllerStart
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsAbilityControllerStart
 */
HWTEST_F(AbilityManagerServiceSixthTest, IsAbilityControllerStart_003, TestSize.Level1)
{
    auto abilityMs_ = std::make_shared<AbilityManagerService>();
    Want want;
    EXPECT_TRUE(abilityMs_->IsAbilityControllerStart(want));
}

}  // namespace AAFwk
}  // namespace OHOS
