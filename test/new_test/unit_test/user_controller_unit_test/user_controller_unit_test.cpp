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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mutex>

#define private public
#include "ability_manager_service.h"
#include "user_callback.h"
#include "user_controller.h"
#undef private

#include "refbase.h"
#include "hilog_tag_wrapper.h"

using namespace testing;
using namespace testing::ext;


namespace OHOS {
namespace AbilityRuntime {
class UserControllerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void UserControllerTest::SetUpTestCase() {}
void UserControllerTest::TearDownTestCase() {}
void UserControllerTest::SetUp() {}
void UserControllerTest::TearDown() {}

/**
 * @tc.name: IsExistOsAccount_001
 * @tc.desc: Verify IsExistOsAccount call.
 *           Branch errcode == 0 && OsAccountExists == true
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, IsExistOsAccount_001, TestSize.Level1)
{
    std::shared_ptr<UserController> controller = std::make_shared<UserController>();
    int32_t userId = 100;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_EQ(controller->IsExistOsAccount(userId), true);
}

/**
 * @tc.name: IsExistOsAccount_002
 * @tc.desc: Verify IsExistOsAccount call.
 *           Branch errcode != 0 && OsAccountExists == true
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, IsExistOsAccount_002, TestSize.Level1)
{
    std::shared_ptr<UserController> controller = std::make_shared<UserController>();
    int32_t userId = 100;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({1}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_EQ(controller->IsExistOsAccount(userId), false);
}

/**
 * @tc.name: IsExistOsAccount_003
 * @tc.desc: Verify IsExistOsAccount call.
 *           Branch errcode == 0 && OsAccountExists == false
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, IsExistOsAccount_003, TestSize.Level1)
{
    std::shared_ptr<UserController> controller = std::make_shared<UserController>();
    int32_t userId = 100;
    std::vector<vector<bool>> expectOuter = {{false}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_EQ(controller->IsExistOsAccount(userId), false);
}

/**
 * @tc.name: IsExistOsAccount_004
 * @tc.desc: Verify IsExistOsAccount call.
 *           Branch errcode == 1 && OsAccountExists == false
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, IsExistOsAccount_004, TestSize.Level1)
{
    std::shared_ptr<UserController> controller = std::make_shared<UserController>();
    int32_t userId = 100;
    std::vector<vector<bool>> expectOuter = {{false}};
    OH_EXPECT_RET_AND_OUTPUT({1}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_EQ(controller->IsExistOsAccount(userId), false);
}

/**
 * @tc.name: SetCurrentUserId_001
 * @tc.desc: Verify SetCurrentUserId call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SetCurrentUserId_001, TestSize.Level1)
{
    std::shared_ptr<UserController> controller = std::make_shared<UserController>();
    uint64_t displayId = 0;
    int32_t userId = 100;
    AbilityRuntime::UserController::GetInstance().SetForegroundUserId(userId, displayId);
    userId = 101;
    AbilityRuntime::UserController::GetInstance().SetForegroundUserId(userId, displayId);
    EXPECT_EQ(AbilityRuntime::UserController::GetInstance().GetForegroundUserId(displayId), 101);
    uint64_t displayId1 = 1;
    EXPECT_EQ(AbilityRuntime::UserController::GetInstance().GetForegroundUserId(displayId1), 0);

    uint64_t displayId2 = 0;
    EXPECT_TRUE(AbilityRuntime::UserController::GetInstance().GetDisplayIdByForegroundUserId(userId, displayId2));
    int32_t userId2 = 102;
    EXPECT_FALSE(AbilityRuntime::UserController::GetInstance().GetDisplayIdByForegroundUserId(userId2, displayId2));

    EXPECT_TRUE(AbilityRuntime::UserController::GetInstance().IsForegroundUser(userId));
    EXPECT_FALSE(AbilityRuntime::UserController::GetInstance().IsForegroundUser(userId2));

    EXPECT_TRUE(AbilityRuntime::UserController::GetInstance().IsForegroundUser(userId, displayId));
    EXPECT_FALSE(AbilityRuntime::UserController::GetInstance().IsForegroundUser(userId2, displayId));

    std::vector<int32_t> userIds;
    AbilityRuntime::UserController::GetInstance().GetAllForegroundUserId(userIds);
    EXPECT_EQ(static_cast<int32_t>(userIds.size()), 1);

    EXPECT_EQ(AbilityRuntime::UserController::GetInstance().GetCallerUserId(), userId);

    AbilityRuntime::UserController::GetInstance().ClearUserId(userId2);
    EXPECT_TRUE(AbilityRuntime::UserController::GetInstance().IsForegroundUser(userId));
    AbilityRuntime::UserController::GetInstance().ClearUserId(userId);
    EXPECT_FALSE(AbilityRuntime::UserController::GetInstance().IsForegroundUser(userId));
}

/**
 * @tc.name: GetFreezingNewUserId_001
 * @tc.desc: Verify GetFreezingNewUserId call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, GetFreezingNewUserId_001, TestSize.Level1)
{
    std::shared_ptr<UserController> controller = std::make_shared<UserController>();
    controller->freezingNewUserId_ = 101;
    EXPECT_EQ(controller->GetFreezingNewUserId(), 101);
}

/**
 * @tc.name: SetFreezingNewUserId_001
 * @tc.desc: Verify SetFreezingNewUserId call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SetFreezingNewUserId_001, TestSize.Level1)
{
    std::shared_ptr<UserController> controller = std::make_shared<UserController>();
    int32_t userId = 101;
    controller->SetFreezingNewUserId(userId);
    EXPECT_EQ(controller->freezingNewUserId_, userId);
}
} // namespace AbilityRuntime
} // namespace OHOS