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
#include "ability_background_connection.h"
#include "hilog_tag_wrapper.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace testing;
namespace OHOS {
namespace AAFwk {
class AbilityBackgroundConnectionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void AbilityBackgroundConnectionTest::SetUpTestCase(void) {}
void AbilityBackgroundConnectionTest::TearDownTestCase(void) {}
void AbilityBackgroundConnectionTest::TearDown() {}
void AbilityBackgroundConnectionTest::SetUp() {}

/**
 * @tc.name: AbilityBackgroundConnectionTest_OnAbilityConnectDone_0001
 * @tc.desc: Test the state of OnAbilityConnectDone
 * @tc.type: FUNC
 */
HWTEST_F(AbilityBackgroundConnectionTest, OnAbilityConnectDone_0001, TestSize.Level1)
{
    AppExecFwk::ElementName element;
    sptr<IRemoteObject> remoteObject;
    int resultCode = 1;
    auto connection = std::make_shared<AbilityBackgroundConnection>();
    connection->OnAbilityConnectDone(element, remoteObject, resultCode);
    EXPECT_NE(resultCode, ERR_OK);
}
} // namespace AAFwk
} // namespace OHOS
