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
#include <mutex>

#define private public
#include "user_record_manager.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class UserRecordManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void UserRecordManagerTest::SetUpTestCase()
{}

void UserRecordManagerTest::TearDownTestCase()
{}

void UserRecordManagerTest::SetUp()
{}

void UserRecordManagerTest::TearDown()
{}

/**
 * @tc.name: UserRecordManagerTest_001
 * @tc.desc: Verify enable start process
 * @tc.type: FUNC
 */
HWTEST_F(UserRecordManagerTest, UserRecordManagerTest_001, TestSize.Level1)
{
    auto userRecordManager = std::make_shared<UserRecordManager>();
    int32_t userId = 101;
    userRecordManager->SetEnableStartProcessFlagByUserId(userId, true);
    EXPECT_EQ(userRecordManager->IsLogoutUser(userId), false);
}

/**
 * @tc.name: UserRecordManagerTest_002
 * @tc.desc: Verify disable start process
 * @tc.type: FUNC
 */
HWTEST_F(UserRecordManagerTest, UserRecordManagerTest_002, TestSize.Level1)
{
    auto userRecordManager = std::make_shared<UserRecordManager>();
    int32_t userId = 101;
    userRecordManager->SetEnableStartProcessFlagByUserId(userId, false);
    EXPECT_EQ(userRecordManager->IsLogoutUser(userId), true);
}
} // namespace AppExecFwk
} // namespace OHOS
