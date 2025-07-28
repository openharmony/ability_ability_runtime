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
namespace AppExecFwk {
class UserControllerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void UserControllerTest::SetUpTestCase()
{}

void UserControllerTest::TearDownTestCase()
{}

void UserControllerTest::SetUp()
{}

void UserControllerTest::TearDown()
{}

/**
 * @tc.name: UserItem_GetUserId_001
 * @tc.desc: Verify UserItem GetUserId call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, UserItem_GetUserId_001, TestSize.Level1)
{
    int32_t expectUserId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(expectUserId);
    EXPECT_EQ(userItem->GetUserId(), expectUserId);
}

/**
 * @tc.name: UserItem_SetState_001
 * @tc.desc: Verify UserItem SetState call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, UserItem_SetState_001, TestSize.Level1)
{
    AAFwk::UserState userState = AAFwk::UserState::STATE_BOOTING;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    userItem->SetState(userState);
    EXPECT_EQ(userItem->curState_, AAFwk::UserState::STATE_BOOTING);
    EXPECT_EQ(userItem->lastState_, AAFwk::UserState::STATE_BOOTING);
}

/**
 * @tc.name: UserItem_SetState_002
 * @tc.desc: Verify UserItem SetState call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, UserItem_SetState_002, TestSize.Level1)
{
    AAFwk::UserState userState = AAFwk::UserState::STATE_STARTED;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    userItem->SetState(userState);
    EXPECT_EQ(userItem->curState_, AAFwk::UserState::STATE_STARTED);
    EXPECT_EQ(userItem->lastState_, AAFwk::UserState::STATE_BOOTING);
}

/**
 * @tc.name: UserItem_GetState_001
 * @tc.desc: Verify UserItem GetState call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, UserItem_GetState_001, TestSize.Level1)
{
    AAFwk::UserState userState = AAFwk::UserState::STATE_STARTED;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    userItem->SetState(userState);
    EXPECT_EQ(userItem->GetState(), AAFwk::UserState::STATE_STARTED);
}

/**
 * @tc.name: Init_001
 * @tc.desc: Verify Init call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, Init_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    std::shared_ptr<AAFwk::TaskHandlerWrap> handler = nullptr;
    OH_EXPECT_RET({handler}, AbilityManagerService, GetTaskHandler);
    controller->Init();
    EXPECT_EQ(controller->eventHandler_, nullptr);
}

/**
 * @tc.name: Init_002
 * @tc.desc: Verify Init call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, Init_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    std::shared_ptr<AAFwk::TaskHandlerWrap> handler = std::make_shared<AAFwk::TaskHandlerWrap>();
    OH_EXPECT_RET({handler}, AbilityManagerService, GetTaskHandler);
    controller->Init();
    EXPECT_NE(controller->eventHandler_, nullptr);
}

/**
 * @tc.name: Init_003
 * @tc.desc: Verify Init call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, Init_003, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    std::shared_ptr<AAFwk::TaskHandlerWrap> handler = std::make_shared<AAFwk::TaskHandlerWrap>();
    OH_EXPECT_RET({handler}, AbilityManagerService, GetTaskHandler);
    controller->eventHandler_ = std::make_shared<AAFwk::UserEventHandler>(handler, controller);
    controller->Init();
    EXPECT_NE(controller->eventHandler_, nullptr);
}

/**
 * @tc.name: ClearAbilityUserItems_001
 * @tc.desc: Verify ClearAbilityUserItems call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, ClearAbilityUserItems_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({0, userItem});
    controller->ClearAbilityUserItems(0);
    EXPECT_EQ(controller->userItems_.size(), 0);
}

/**
 * @tc.name: ClearAbilityUserItems_002
 * @tc.desc: Verify ClearAbilityUserItems call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, ClearAbilityUserItems_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({0, userItem});
    controller->ClearAbilityUserItems(1);
    EXPECT_EQ(controller->userItems_.size(), 1);
}

/**
 * @tc.name: StartUser_001
 * @tc.desc: Verify StartUser call.
 *           Branch userId < 0 && callback == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = -1;
    sptr<AAFwk::IUserCallback> callback = nullptr;
    bool isAppRecovery = 0;
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), AAFwk::INVALID_USERID_VALUE);
}

/**
 * @tc.name: StartUser_002
 * @tc.desc: Verify StartUser call.
 *           Branch userId < 0 && callback != nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = -1;
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    bool isAppRecovery = 0;
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), AAFwk::INVALID_USERID_VALUE);
}

/**
 * @tc.name: StartUser_003
 * @tc.desc: Verify StartUser call.
 *           Branch userId == USER_ID_NO_HEAD && callback == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_003, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = AAFwk::USER_ID_NO_HEAD;
    sptr<AAFwk::IUserCallback> callback = nullptr;
    bool isAppRecovery = 0;
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), AAFwk::INVALID_USERID_VALUE);
}

/**
 * @tc.name: StartUser_004
 * @tc.desc: Verify StartUser call.
 *           Branch userId == USER_ID_NO_HEAD && callback != nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_004, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = AAFwk::USER_ID_NO_HEAD;
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    bool isAppRecovery = 0;
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), AAFwk::INVALID_USERID_VALUE);
}

/**
 * @tc.name: StartUser_005
 * @tc.desc: Verify StartUser call.
 *           Branch IsCurrentUser == true && callback == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_005, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 101;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({101, userItem});
    sptr<AAFwk::IUserCallback> callback = nullptr;
    bool isAppRecovery = 0;
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), ERR_OK);
}

/**
 * @tc.name: StartUser_006
 * @tc.desc: Verify StartUser call.
 *           Branch IsCurrentUser == true && callback != nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_006, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 101;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({101, userItem});
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    bool isAppRecovery = 0;
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), ERR_OK);
}

/**
 * @tc.name: StartUser_007
 * @tc.desc: Verify StartUser call.
 *           Branch IsExistOsAccount == false && callback == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_007, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({101, userItem});
    sptr<AAFwk::IUserCallback> callback = nullptr;
    bool isAppRecovery = 0;
    std::vector<vector<bool>> expectOuter = {{false}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), AAFwk::INVALID_USERID_VALUE);
}

/**
 * @tc.name: StartUser_008
 * @tc.desc: Verify StartUser call.
 *           Branch IsExistOsAccount == false && callback != nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_008, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({101, userItem});
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    bool isAppRecovery = 0;
    std::vector<vector<bool>> expectOuter = {{false}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), AAFwk::INVALID_USERID_VALUE);
}

/**
 * @tc.name: StartUser_009
 * @tc.desc: Verify StartUser call.
 *           Branch GetCurrentUserId() != USER_ID_NO_HEAD && IsSceneBoardEnabled() == false
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_009, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    controller->freezingNewUserId_ = 0;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({userId, userItem});
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    bool isAppRecovery = 0;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    OH_EXPECT_RET({false}, SceneBoardJudgement, IsSceneBoardEnabled);
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), ERR_OK);
    EXPECT_EQ(controller->freezingNewUserId_, 101);
}

/**
 * @tc.name: StartUser_010
 * @tc.desc: Verify StartUser call.
 *           Branch GetCurrentUserId() == USER_ID_NO_HEAD && IsSceneBoardEnabled() == false
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_010, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 0;
    controller->freezingNewUserId_ = 0;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({userId, userItem});
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    bool isAppRecovery = 0;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    OH_EXPECT_RET({false}, SceneBoardJudgement, IsSceneBoardEnabled);
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), ERR_OK);
    EXPECT_EQ(controller->freezingNewUserId_, 0);
}

/**
 * @tc.name: StartUser_011
 * @tc.desc: Verify StartUser call.
 *           Branch GetCurrentUserId() != USER_ID_NO_HEAD && IsSceneBoardEnabled() == true
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_011, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    controller->freezingNewUserId_ = 0;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({userId, userItem});
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    bool isAppRecovery = 0;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    OH_EXPECT_RET({true}, SceneBoardJudgement, IsSceneBoardEnabled);
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), ERR_OK);
    EXPECT_EQ(controller->freezingNewUserId_, 0);
}

/**
 * @tc.name: StartUser_012
 * @tc.desc: Verify StartUser call.
 *           Branch GetCurrentUserId() == USER_ID_NO_HEAD && IsSceneBoardEnabled() == true
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_012, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 0;
    controller->freezingNewUserId_ = 0;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({userId, userItem});
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    bool isAppRecovery = 0;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    OH_EXPECT_RET({true}, SceneBoardJudgement, IsSceneBoardEnabled);
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), ERR_OK);
    EXPECT_EQ(controller->freezingNewUserId_, 0);
}

/**
 * @tc.name: StartUser_013
 * @tc.desc: Verify StartUser call.
 *           Branch state == STATE_STOPPING && callback != nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_013, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    userItem->SetState(AAFwk::STATE_STOPPING);
    controller->userItems_.insert({userId, userItem});
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    bool isAppRecovery = 0;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), ERR_DEAD_OBJECT);
}

/**
 * @tc.name: StartUser_014
 * @tc.desc: Verify StartUser call.
 *           Branch state == STATE_STOPPING && callback == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_014, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    userItem->SetState(AAFwk::STATE_STOPPING);
    controller->userItems_.insert({userId, userItem});
    sptr<AAFwk::IUserCallback> callback = nullptr;
    bool isAppRecovery = 0;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), ERR_DEAD_OBJECT);
}

/**
 * @tc.name: StartUser_015
 * @tc.desc: Verify StartUser call.
 *           Branch state == STATE_SHUTDOWN && callback != nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_015, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    userItem->SetState(AAFwk::STATE_SHUTDOWN);
    controller->userItems_.insert({userId, userItem});
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    bool isAppRecovery = 0;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), ERR_DEAD_OBJECT);
}

/**
 * @tc.name: StartUser_016
 * @tc.desc: Verify StartUser call.
 *           Branch state == STATE_SHUTDOWN && callback == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_016, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    userItem->SetState(AAFwk::STATE_SHUTDOWN);
    controller->userItems_.insert({userId, userItem});
    sptr<AAFwk::IUserCallback> callback = nullptr;
    bool isAppRecovery = 0;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_EQ(controller->StartUser(userId, callback, isAppRecovery), ERR_DEAD_OBJECT);
}

/**
 * @tc.name: StartUser_017
 * @tc.desc: Verify StartUser call.
 *           Branch state == STATE_BOOTING
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StartUser_017, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    userItem->SetState(AAFwk::STATE_BOOTING);
    controller->userItems_.insert({userId, userItem});
    sptr<AAFwk::IUserCallback> callback = nullptr;
    bool isAppRecovery = 0;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_NE(controller->StartUser(userId, callback, isAppRecovery), ERR_DEAD_OBJECT);
    EXPECT_EQ(controller->currentUserId_, 101);
}

/**
 * @tc.name: StopUser_001
 * @tc.desc: Verify StopUser call.
 *           Branch userId < 0
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StopUser_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = -1;
    EXPECT_EQ(controller->StopUser(userId), -1);
}

/**
 * @tc.name: StopUser_002
 * @tc.desc: Verify StopUser call.
 *           Branch userId == USER_ID_NO_HEAD
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StopUser_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = AAFwk::USER_ID_NO_HEAD;
    EXPECT_EQ(controller->StopUser(userId), -1);
}

/**
 * @tc.name: StopUser_003
 * @tc.desc: Verify StopUser call.
 *           Branch userId == USER_ID_DEFAULT
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StopUser_003, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = AAFwk::USER_ID_DEFAULT;
    EXPECT_EQ(controller->StopUser(userId), -1);
}

/**
 * @tc.name: StopUser_004
 * @tc.desc: Verify StopUser call.
 *           Branch IsCurrentUser == true
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StopUser_004, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 101;
    int32_t userId = 101;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({userId, userItem});
    EXPECT_EQ(controller->StopUser(userId), 0);
}

/**
 * @tc.name: StopUser_005
 * @tc.desc: Verify StopUser call.
 *           Branch IsExistOsAccount == false
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StopUser_005, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    std::vector<vector<bool>> expectOuter = {{false}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_EQ(controller->StopUser(userId), -1);
}

/**
 * @tc.name: StopUser_006
 * @tc.desc: Verify StopUser call.
 *           Branch IsSceneBoardEnabled == false && GetMissionListWrap == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StopUser_006, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    OH_EXPECT_RET({false}, SceneBoardJudgement, IsSceneBoardEnabled);
    std::shared_ptr<AAFwk::MissionListWrap> wrap = nullptr;
    OH_EXPECT_RET({wrap}, AbilityManagerService, GetMissionListWrap);
    EXPECT_EQ(controller->StopUser(userId), -1);
}

/**
 * @tc.name: StopUser_007
 * @tc.desc: Verify StopUser call.
 *           Branch IsSceneBoardEnabled == false && GetMissionListWrap != nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StopUser_007, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    OH_EXPECT_RET({false}, SceneBoardJudgement, IsSceneBoardEnabled);
    std::shared_ptr<AAFwk::MissionListWrap> wrap = std::make_shared<AAFwk::MissionListWrap>();
    OH_EXPECT_RET({wrap}, AbilityManagerService, GetMissionListWrap);
    EXPECT_EQ(controller->StopUser(userId), 0);
}

/**
 * @tc.name: StopUser_008
 * @tc.desc: Verify StopUser call.
 *           Branch IsSceneBoardEnabled == true && GetMissionListWrap == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StopUser_008, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    OH_EXPECT_RET({true}, SceneBoardJudgement, IsSceneBoardEnabled);
    std::shared_ptr<AAFwk::MissionListWrap> wrap = nullptr;
    OH_EXPECT_RET({wrap}, AbilityManagerService, GetMissionListWrap);
    EXPECT_EQ(controller->StopUser(userId), 0);
}

/**
 * @tc.name: StopUser_009
 * @tc.desc: Verify StopUser call.
 *           Branch IsSceneBoardEnabled == true && GetMissionListWrap != nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, StopUser_009, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    OH_EXPECT_RET({true}, SceneBoardJudgement, IsSceneBoardEnabled);
    std::shared_ptr<AAFwk::MissionListWrap> wrap = std::make_shared<AAFwk::MissionListWrap>();
    OH_EXPECT_RET({wrap}, AbilityManagerService, GetMissionListWrap);
    EXPECT_EQ(controller->StopUser(userId), 0);
}

/**
 * @tc.name: LogoutUser_001
 * @tc.desc: Verify LogoutUser call.
 *           Branch userId < 0 && callback == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, LogoutUser_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = -1;
    sptr<AAFwk::IUserCallback> callback = nullptr;
    EXPECT_EQ(controller->LogoutUser(userId, callback), AAFwk::INVALID_USERID_VALUE);
}

/**
 * @tc.name: LogoutUser_002
 * @tc.desc: Verify LogoutUser call.
 *           Branch userId == USER_ID_NO_HEAD && callback == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, LogoutUser_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = AAFwk::USER_ID_NO_HEAD;
    sptr<AAFwk::IUserCallback> callback = nullptr;
    EXPECT_EQ(controller->LogoutUser(userId, callback), AAFwk::INVALID_USERID_VALUE);
}

/**
 * @tc.name: LogoutUser_003
 * @tc.desc: Verify LogoutUser call.
 *           Branch userId < 0 && callback == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, LogoutUser_003, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = -1;
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    EXPECT_EQ(controller->LogoutUser(userId, callback), AAFwk::INVALID_USERID_VALUE);
}

/**
 * @tc.name: LogoutUser_004
 * @tc.desc: Verify LogoutUser call.
 *           Branch userId == USER_ID_NO_HEAD && callback == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, LogoutUser_004, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = AAFwk::USER_ID_NO_HEAD;
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    EXPECT_EQ(controller->LogoutUser(userId, callback), AAFwk::INVALID_USERID_VALUE);
}

/**
 * @tc.name: LogoutUser_005
 * @tc.desc: Verify LogoutUser call.
 *           Branch IsExistOsAccount == false && callback == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, LogoutUser_005, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    sptr<AAFwk::IUserCallback> callback = nullptr;
    std::vector<vector<bool>> expectOuter = {{false}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_EQ(controller->LogoutUser(userId, callback), AAFwk::INVALID_USERID_VALUE);
}

/**
 * @tc.name: LogoutUser_006
 * @tc.desc: Verify LogoutUser call.
 *           Branch IsExistOsAccount == false && callback != nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, LogoutUser_006, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    std::vector<vector<bool>> expectOuter = {{false}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_EQ(controller->LogoutUser(userId, callback), AAFwk::INVALID_USERID_VALUE);
}

/**
 * @tc.name: LogoutUser_007
 * @tc.desc: Verify LogoutUser call.
 *           Branch IsSceneBoardEnabled == true
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, LogoutUser_007, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    OH_EXPECT_RET({true}, SceneBoardJudgement, IsSceneBoardEnabled);
    EXPECT_EQ(controller->LogoutUser(userId, callback), 0);
    EXPECT_LOG_MATCH(LOG_INFO, AAFwkTag::ABILITYMGR, "user_controller.cpp", "SceneBoard exit normally.");
}

/**
 * @tc.name: LogoutUser_008
 * @tc.desc: Verify LogoutUser call.
 *           Branch IsSceneBoardEnabled == false
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, LogoutUser_008, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    OH_EXPECT_RET({false}, SceneBoardJudgement, IsSceneBoardEnabled);
    EXPECT_EQ(controller->LogoutUser(userId, callback), 0);
}

/**
 * @tc.name: LogoutUser_009
 * @tc.desc: Verify LogoutUser call.
 *           Branch IsSceneBoardEnabled == true
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, LogoutUser_009, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 100;
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({userId, userItem});
    EXPECT_EQ(controller->LogoutUser(userId, callback), 0);
    EXPECT_EQ(controller->currentUserId_, 0);
}

/**
 * @tc.name: LogoutUser_010
 * @tc.desc: Verify LogoutUser call.
 *           Branch IsSceneBoardEnabled == true
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, LogoutUser_010, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    sptr<AAFwk::IUserCallback> callback = sptr<AAFwk::IUserCallback>::MakeSptr();
    std::vector<vector<bool>> expectOuter = {{true}};
    OH_EXPECT_RET_AND_OUTPUT({0}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({userId, userItem});
    EXPECT_EQ(controller->LogoutUser(userId, callback), 0);
    EXPECT_EQ(controller->currentUserId_, 100);
}

/**
 * @tc.name: GetCurrentUserId_001
 * @tc.desc: Verify GetCurrentUserId call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, GetCurrentUserId_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    EXPECT_EQ(controller->GetCurrentUserId(), 100);
}

/**
 * @tc.name: GetUserItem_001
 * @tc.desc: Verify GetUserItem call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, GetUserItem_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = 100;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({userId, userItem});
    EXPECT_EQ(controller->GetUserItem(userId), userItem);
}

/**
 * @tc.name: GetUserItem_002
 * @tc.desc: Verify GetUserItem call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, GetUserItem_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = 100;
    EXPECT_EQ(controller->GetUserItem(userId), nullptr);
}

/**
 * @tc.name: IsExistOsAccount_001
 * @tc.desc: Verify IsExistOsAccount call.
 *           Branch errcode == 0 && OsAccountExists == true
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, IsExistOsAccount_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
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
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
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
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
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
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = 100;
    std::vector<vector<bool>> expectOuter = {{false}};
    OH_EXPECT_RET_AND_OUTPUT({1}, expectOuter, OsAccountManagerWrapper,
        IsOsAccountExists, const int, bool& isOsAccountExists);
    EXPECT_EQ(controller->IsExistOsAccount(userId), false);
}

/**
 * @tc.name: GetOrCreateUserItem_001
 * @tc.desc: Verify GetOrCreateUserItem call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, GetOrCreateUserItem_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = 100;
    std::shared_ptr<AAFwk::UserItem> userItem = std::make_shared<AAFwk::UserItem>(userId);
    controller->userItems_.insert({userId, userItem});
    EXPECT_EQ(controller->GetOrCreateUserItem(userId), userItem);
}

/**
 * @tc.name: GetOrCreateUserItem_002
 * @tc.desc: Verify GetOrCreateUserItem call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, GetOrCreateUserItem_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    int32_t userId = 100;
    EXPECT_NE(controller->GetOrCreateUserItem(userId), nullptr);
}

/**
 * @tc.name: SetCurrentUserId_001
 * @tc.desc: Verify SetCurrentUserId call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SetCurrentUserId_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    controller->SetCurrentUserId(userId);
    EXPECT_EQ(controller->currentUserId_, 101);
}

/**
 * @tc.name: MoveUserToForeground_001
 * @tc.desc: Verify MoveUserToForeground call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, MoveUserToForeground_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    OH_EXPECT_RET({0}, AbilityManagerService, SwitchToUser, int32_t, int32_t,
        sptr<AAFwk::IUserCallback>, bool isAppRecovery = false);
    int32_t oldUserId = 100;
    int32_t newUserId = 101;
    sptr<AAFwk::IUserCallback> callback = nullptr;
    bool isAppRecovery = false;
    EXPECT_EQ(controller->MoveUserToForeground(oldUserId, newUserId, callback, isAppRecovery), ERR_OK);
}

/**
 * @tc.name: MoveUserToForeground_002
 * @tc.desc: Verify MoveUserToForeground call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, MoveUserToForeground_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->currentUserId_ = 100;
    int32_t userId = 101;
    OH_EXPECT_RET({1}, AbilityManagerService, SwitchToUser, int32_t, int32_t,
        sptr<AAFwk::IUserCallback>, bool isAppRecovery = false);
    int32_t oldUserId = 100;
    int32_t newUserId = 101;
    sptr<AAFwk::IUserCallback> callback = nullptr;
    bool isAppRecovery = false;
    EXPECT_EQ(controller->MoveUserToForeground(oldUserId, newUserId, callback, isAppRecovery), 1);
}

/**
 * @tc.name: UserBootDone_001
 * @tc.desc: Verify UserBootDone call.
 *           Branch item == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, UserBootDone_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    std::shared_ptr<AAFwk::UserItem> item = nullptr;
    controller->UserBootDone(item);
    EXPECT_LOG_MATCH(LOG_ERROR, AAFwkTag::ABILITYMGR, "user_controller.cpp", "null item");
}

/**
 * @tc.name: UserBootDone_002
 * @tc.desc: Verify UserBootDone call.
 *           Branch userId invalid
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, UserBootDone_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    std::shared_ptr<AAFwk::UserItem> item = std::make_shared<AAFwk::UserItem>(101);
    AAFwk::UserState userState = AAFwk::UserState::STATE_BOOTING;
    item->SetState(userState);
    controller->UserBootDone(item);
    EXPECT_EQ(item->GetState(), AAFwk::UserState::STATE_BOOTING);
}

/**
 * @tc.name: UserBootDone_003
 * @tc.desc: Verify UserBootDone call.
 *           Branch item not match
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, UserBootDone_003, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    std::shared_ptr<AAFwk::UserItem> item1 = std::make_shared<AAFwk::UserItem>(101);
    std::shared_ptr<AAFwk::UserItem> item2 = std::make_shared<AAFwk::UserItem>(101);
    controller->userItems_.insert({101, item2});
    AAFwk::UserState userState = AAFwk::UserState::STATE_BOOTING;
    item1->SetState(userState);
    controller->UserBootDone(item1);
    EXPECT_EQ(item1->GetState(), AAFwk::UserState::STATE_BOOTING);
}

/**
 * @tc.name: UserBootDone_004
 * @tc.desc: Verify UserBootDone call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, UserBootDone_004, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    std::shared_ptr<AAFwk::UserItem> item = std::make_shared<AAFwk::UserItem>(101);
    controller->userItems_.insert({101, item});
    AAFwk::UserState userState = AAFwk::UserState::STATE_BOOTING;
    item->SetState(userState);
    controller->UserBootDone(item);
    EXPECT_EQ(item->GetState(), AAFwk::UserState::STATE_STARTED);
}

/**
 * @tc.name: BroadcastUserBackground_001
 * @tc.desc: Verify BroadcastUserBackground call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, BroadcastUserBackground_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->BroadcastUserBackground(100);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp", "user background");
}

/**
 * @tc.name: BroadcastUserForeground_001
 * @tc.desc: Verify BroadcastUserForeground call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, BroadcastUserForeground_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->BroadcastUserForeground(100);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp", "user foreground");
}

/**
 * @tc.name: BroadcastUserStopping_001
 * @tc.desc: Verify BroadcastUserStopping call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, BroadcastUserStopping_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->BroadcastUserStopping(100);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp", "user stopping");
}

/**
 * @tc.name: BroadcastUserStopped_001
 * @tc.desc: Verify BroadcastUserStopped call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, BroadcastUserStopped_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->BroadcastUserStopped(100);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp", "user stopped");
}

/**
 * @tc.name: SendSystemUserStart_001
 * @tc.desc: Verify SendSystemUserStart call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SendSystemUserStart_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->eventHandler_ = std::make_shared<AAFwk::UserEventHandler>(nullptr, controller);
    controller->SendSystemUserStart(100);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp", "SendEvent(EVENT_SYSTEM_USER_START)");
}

/**
 * @tc.name: SendSystemUserStart_002
 * @tc.desc: Verify SendSystemUserStart call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SendSystemUserStart_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->eventHandler_ = nullptr;
    controller->SendSystemUserStart(100);
    EXPECT_LOG_MATCH(LOG_ERROR, AAFwkTag::ABILITYMGR, "user_controller.cpp", "null handler");
}

/**
 * @tc.name: ProcessEvent_001
 * @tc.desc: Verify ProcessEvent call.
 *           Branch event.GetEventData() == nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, ProcessEvent_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    AAFwk::EventWrap event(0);
    std::shared_ptr<AAFwk::EventDataBase> eventDataBase = nullptr;
    OH_EXPECT_RET({eventDataBase}, EventWrap, GetEventData);
    controller->ProcessEvent(event);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp", "no event data, event id:");
}

/**
 * @tc.name: ProcessEvent_002
 * @tc.desc: Verify ProcessEvent call.
 *           Branch event.GetEventId() == UserEventHandler::EVENT_SYSTEM_USER_START
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, ProcessEvent_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    AAFwk::EventWrap event(0);
    std::shared_ptr<AAFwk::EventDataBase> userEvent = std::make_shared<AAFwk::UserEvent>();
    OH_EXPECT_RET({userEvent}, EventWrap, GetEventData);
    OH_EXPECT_RET({AAFwk::UserEventHandler::EVENT_SYSTEM_USER_START}, EventWrap, GetEventId);
    controller->ProcessEvent(event);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp", "notify system user start.");
}

/**
 * @tc.name: ProcessEvent_003
 * @tc.desc: Verify ProcessEvent call.
 *           Branch event.GetEventId() == UserEventHandler::EVENT_SYSTEM_USER_CURRENT
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, ProcessEvent_003, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    AAFwk::EventWrap event(0);
    std::shared_ptr<AAFwk::EventDataBase> userEvent = std::make_shared<AAFwk::UserEvent>();
    OH_EXPECT_RET({userEvent}, EventWrap, GetEventData);
    OH_EXPECT_RET({AAFwk::UserEventHandler::EVENT_SYSTEM_USER_CURRENT}, EventWrap, GetEventId);
    controller->ProcessEvent(event);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp", "notify system user current.");
}

/**
 * @tc.name: ProcessEvent_004
 * @tc.desc: Verify ProcessEvent call.
 *           Branch event.GetEventId() == UserEventHandler::EVENT_REPORT_USER_SWITCH
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, ProcessEvent_004, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    AAFwk::EventWrap event(0);
    std::shared_ptr<AAFwk::EventDataBase> userEvent = std::make_shared<AAFwk::UserEvent>();
    OH_EXPECT_RET({userEvent}, EventWrap, GetEventData);
    OH_EXPECT_RET({AAFwk::UserEventHandler::EVENT_REPORT_USER_SWITCH}, EventWrap, GetEventId);
    controller->ProcessEvent(event);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp", "notify report user switch.");
}

/**
 * @tc.name: ProcessEvent_005
 * @tc.desc: Verify ProcessEvent call.
 *           Branch event.GetEventId() == UserEventHandler::EVENT_CONTINUE_USER_SWITCH
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, ProcessEvent_005, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    AAFwk::EventWrap event(0);
    std::shared_ptr<AAFwk::EventDataBase> userEvent = std::make_shared<AAFwk::UserEvent>();
    OH_EXPECT_RET({userEvent}, EventWrap, GetEventData);
    OH_EXPECT_RET({AAFwk::UserEventHandler::EVENT_CONTINUE_USER_SWITCH}, EventWrap, GetEventId);
    controller->ProcessEvent(event);
    EXPECT_LOG_MATCH(LOG_ERROR, AAFwkTag::ABILITYMGR, "user_controller.cpp", "null handler");
}

/**
 * @tc.name: ProcessEvent_006
 * @tc.desc: Verify ProcessEvent call.
 *           Branch event.GetEventId() == UserEventHandler::EVENT_USER_SWITCH_TIMEOUT
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, ProcessEvent_006, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    AAFwk::EventWrap event(0);
    std::shared_ptr<AAFwk::EventDataBase> userEvent = std::make_shared<AAFwk::UserEvent>();
    OH_EXPECT_RET({userEvent}, EventWrap, GetEventData);
    OH_EXPECT_RET({AAFwk::UserEventHandler::EVENT_USER_SWITCH_TIMEOUT}, EventWrap, GetEventId);
    controller->ProcessEvent(event);
    EXPECT_LOG_MATCH(LOG_ERROR, AAFwkTag::ABILITYMGR, "user_controller.cpp", "null handler");
}

/**
 * @tc.name: ProcessEvent_007
 * @tc.desc: Verify ProcessEvent call.
 *           Branch event.GetEventId() == UserEventHandler::EVENT_REPORT_USER_SWITCH_DONE
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, ProcessEvent_007, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    AAFwk::EventWrap event(0);
    std::shared_ptr<AAFwk::EventDataBase> userEvent = std::make_shared<AAFwk::UserEvent>();
    OH_EXPECT_RET({userEvent}, EventWrap, GetEventData);
    OH_EXPECT_RET({AAFwk::UserEventHandler::EVENT_REPORT_USER_SWITCH_DONE}, EventWrap, GetEventId);
    controller->ProcessEvent(event);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp", "handle user switch done.");
}

/**
 * @tc.name: ProcessEvent_008
 * @tc.desc: Verify ProcessEvent call.
 *           Branch event.GetEventId() == invalid value
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, ProcessEvent_008, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    AAFwk::EventWrap event(0);
    std::shared_ptr<AAFwk::EventDataBase> userEvent = std::make_shared<AAFwk::UserEvent>();
    OH_EXPECT_RET({userEvent}, EventWrap, GetEventData);
    uint32_t eventId = 111;
    OH_EXPECT_RET({eventId}, EventWrap, GetEventId);
    controller->ProcessEvent(event);
    EXPECT_LOG_MATCH(LOG_WARN, AAFwkTag::ABILITYMGR, "user_controller.cpp", "Unsupported  event.");
}

/**
 * @tc.name: SendSystemUserCurrent_001
 * @tc.desc: Verify SendSystemUserCurrent call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SendSystemUserCurrent_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->eventHandler_ = std::make_shared<AAFwk::UserEventHandler>(nullptr, controller);
    controller->SendSystemUserCurrent(100, 101);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp", "SendEvent(EVENT_SYSTEM_USER_CURRENT)");
}

/**
 * @tc.name: SendSystemUserCurrent_002
 * @tc.desc: Verify SendSystemUserCurrent call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SendSystemUserCurrent_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->eventHandler_ = nullptr;
    controller->SendSystemUserCurrent(100, 101);
    EXPECT_LOG_MATCH(LOG_ERROR, AAFwkTag::ABILITYMGR, "user_controller.cpp", "null handler");
}

/**
 * @tc.name: SendReportUserSwitch_001
 * @tc.desc: Verify SendReportUserSwitch call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SendReportUserSwitch_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->eventHandler_ = std::make_shared<AAFwk::UserEventHandler>(nullptr, controller);
    std::shared_ptr<AAFwk::UserItem> usrItem = nullptr;
    controller->SendReportUserSwitch(100, 101, usrItem);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp", "SendEvent(EVENT_REPORT_USER_SWITCH)");
}

/**
 * @tc.name: SendReportUserSwitch_002
 * @tc.desc: Verify SendReportUserSwitch call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SendReportUserSwitch_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->eventHandler_ = nullptr;
    std::shared_ptr<AAFwk::UserItem> usrItem = nullptr;
    controller->SendReportUserSwitch(100, 101, usrItem);
    EXPECT_LOG_MATCH(LOG_ERROR, AAFwkTag::ABILITYMGR, "user_controller.cpp", "null handler");
}

/**
 * @tc.name: SendUserSwitchTimeout_001
 * @tc.desc: Verify SendUserSwitchTimeout call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SendUserSwitchTimeout_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->eventHandler_ = std::make_shared<AAFwk::UserEventHandler>(nullptr, controller);
    std::shared_ptr<AAFwk::UserItem> usrItem = nullptr;
    controller->SendUserSwitchTimeout(100, 101, usrItem);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp", "SendEvent(EVENT_USER_SWITCH_TIMEOUT)");
}

/**
 * @tc.name: SendUserSwitchTimeout_002
 * @tc.desc: Verify SendUserSwitchTimeout call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SendUserSwitchTimeout_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->eventHandler_ = nullptr;
    std::shared_ptr<AAFwk::UserItem> usrItem = nullptr;
    controller->SendUserSwitchTimeout(100, 101, usrItem);
    EXPECT_LOG_MATCH(LOG_ERROR, AAFwkTag::ABILITYMGR, "user_controller.cpp", "null handler");
}

/**
 * @tc.name: SendContinueUserSwitch_001
 * @tc.desc: Verify SendContinueUserSwitch call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SendContinueUserSwitch_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->eventHandler_ = std::make_shared<AAFwk::UserEventHandler>(nullptr, controller);
    std::shared_ptr<AAFwk::UserItem> usrItem = nullptr;
    controller->SendContinueUserSwitch(100, 101, usrItem);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp", "SendEvent(EVENT_CONTINUE_USER_SWITCH)");
}

/**
 * @tc.name: SendContinueUserSwitch_002
 * @tc.desc: Verify SendContinueUserSwitch call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SendContinueUserSwitch_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->eventHandler_ = nullptr;
    std::shared_ptr<AAFwk::UserItem> usrItem = nullptr;
    controller->SendContinueUserSwitch(100, 101, usrItem);
    EXPECT_LOG_MATCH(LOG_ERROR, AAFwkTag::ABILITYMGR, "user_controller.cpp", "null handler");
}

/**
 * @tc.name: SendUserSwitchDone_001
 * @tc.desc: Verify SendUserSwitchDone call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SendUserSwitchDone_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->eventHandler_ = std::make_shared<AAFwk::UserEventHandler>(nullptr, controller);
    controller->SendUserSwitchDone(100);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp",
        "SendEvent(EVENT_REPORT_USER_SWITCH_DONE)");
}

/**
 * @tc.name: SendUserSwitchDone_002
 * @tc.desc: Verify SendUserSwitchDone call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, SendUserSwitchDone_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->eventHandler_ = nullptr;
    controller->SendUserSwitchDone(100);
    EXPECT_LOG_MATCH(LOG_ERROR, AAFwkTag::ABILITYMGR, "user_controller.cpp", "null handler");
}

/**
 * @tc.name: HandleContinueUserSwitch_001
 * @tc.desc: Verify HandleContinueUserSwitch call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, HandleContinueUserSwitch_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->eventHandler_ = std::make_shared<AAFwk::UserEventHandler>(nullptr, controller);
    OH_EXPECT_RET({false}, SceneBoardJudgement, IsSceneBoardEnabled);
    std::shared_ptr<AAFwk::UserItem> usrItem = nullptr;
    controller->HandleContinueUserSwitch(100, 101, usrItem);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp",
        "SendEvent(EVENT_REPORT_USER_SWITCH_DONE)");
}

/**
 * @tc.name: HandleContinueUserSwitch_002
 * @tc.desc: Verify HandleContinueUserSwitch call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, HandleContinueUserSwitch_002, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->eventHandler_ = std::make_shared<AAFwk::UserEventHandler>(nullptr, controller);
    OH_EXPECT_RET({true}, SceneBoardJudgement, IsSceneBoardEnabled);
    std::shared_ptr<AAFwk::UserItem> usrItem = nullptr;
    controller->HandleContinueUserSwitch(100, 101, usrItem);
    EXPECT_LOG_MATCH(LOG_DEBUG, AAFwkTag::ABILITYMGR, "user_controller.cpp",
        "SendEvent(EVENT_REPORT_USER_SWITCH_DONE)");
}

/**
 * @tc.name: GetFreezingNewUserId_001
 * @tc.desc: Verify GetFreezingNewUserId call.
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, GetFreezingNewUserId_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
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
    std::shared_ptr<AAFwk::UserController> controller = std::make_shared<AAFwk::UserController>();
    controller->SetFreezingNewUserId(101);
    EXPECT_EQ(controller->freezingNewUserId_, 101);
}
} // namespace AppExecFwk
} // namespace OHOS