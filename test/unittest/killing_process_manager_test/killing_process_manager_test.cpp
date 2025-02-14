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

#include "killing_process_manager.h"
#include "hilog_tag_wrapper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t CLEAR_CALLER_KEY_DELAY_TIME = 6;
} // namespace

class KillingProcessManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void KillingProcessManagerTest::SetUpTestCase()
{}

void KillingProcessManagerTest::TearDownTestCase()
{}

void KillingProcessManagerTest::SetUp()
{}

void KillingProcessManagerTest::TearDown()
{}

/**
 * @tc.name: IsCallerKilling_001
 * @tc.desc: test IsCallerKilling function.
 * @tc.type: FUNC
 */
HWTEST_F(KillingProcessManagerTest, IsCallerKilling_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "KillingProcessManagerTest IsCallerKilling_001 start");
    std::string callerKey = "testcallerKey";
    KillingProcessManager &killingProcessManager = KillingProcessManager::GetInstance();
    bool ret = killingProcessManager.IsCallerKilling(callerKey);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "KillingProcessManagerTest IsCallerKilling_001 end");
}

/**
 * @tc.name: AddKillingCallerKey_001
 * @tc.desc: test AddKillingCallerKey function.
 * @tc.type: FUNC
 */
HWTEST_F(KillingProcessManagerTest, AddKillingCallerKey_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "KillingProcessManagerTest AddKillingCallerKey_001 start");
    std::string nullKey = "";
    std::string callerKey = "testcallerKey";
    KillingProcessManager &killingProcessManager = KillingProcessManager::GetInstance();
    killingProcessManager.AddKillingCallerKey(nullKey);
    killingProcessManager.RemoveKillingCallerKey(nullKey);

    killingProcessManager.AddKillingCallerKey(callerKey);
    EXPECT_EQ(killingProcessManager.killingCallerKeySet_.count(callerKey), 1);
    killingProcessManager.AddKillingCallerKey(callerKey);
    sleep(CLEAR_CALLER_KEY_DELAY_TIME);
    EXPECT_EQ(killingProcessManager.killingCallerKeySet_.count(callerKey), 0);
    TAG_LOGI(AAFwkTag::TEST, "KillingProcessManagerTest AddKillingCallerKey_001 end");
}
} // namespace AppExecFwk
} // namespace OHOS
