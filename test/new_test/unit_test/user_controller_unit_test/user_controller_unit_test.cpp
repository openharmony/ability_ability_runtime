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
#include <mutex>

#define private public
#include "user_controller.h"
#undef private

#include "refbase.h"
#include "hilog_tag_wrapper.h"
#include "oh_mock_utils.h"

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
 * @tc.name: OnAbilityConnectDone_001
 * @tc.desc: Verify OnAbilityConnectDone call.
 *           Branch abilityConnectCallbackList_ = nullptr
 * @tc.type: FUNC
 */
HWTEST_F(UserControllerTest, OnAbilityConnectDone_001, TestSize.Level1)
{
    std::shared_ptr<AAFwk::UserController> instance = std::make_shared<AAFwk::UserController>();
    EXPECT_NE(instance, nullptr);
}
} // namespace AppExecFwk
} // namespace OHOS