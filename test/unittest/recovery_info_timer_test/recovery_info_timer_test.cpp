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
#include "recovery_info_timer.h"
#undef private

using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace AAFwk {
class RecoveryInfoTimerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void RecoveryInfoTimerTest::SetUpTestCase(void)
{}
void RecoveryInfoTimerTest::TearDownTestCase(void)
{}
void RecoveryInfoTimerTest::TearDown(void)
{}
void RecoveryInfoTimerTest::SetUp()
{}

/**
 * @tc.number: SubmitSaveRecoveryInfo_001
 * @tc.name: SubmitSaveRecoveryInfo
 * @tc.desc: Test whether SubmitSaveRecoveryInfo is called normally.
 * @tc.type: FUNC
 */
HWTEST_F(RecoveryInfoTimerTest, SubmitSaveRecoveryInfo_001, TestSize.Level1)
{
    RecoveryInfoTimer &instance = RecoveryInfoTimer::GetInstance();
    RecoveryInfo recoveryInfo;
    recoveryInfo.bundleName = "testBundleName";
    recoveryInfo.moduleName = "testModuleName";
    recoveryInfo.abilityName = "testAbilityName";
    instance.SubmitSaveRecoveryInfo(recoveryInfo);
    auto findByInfo = [&recoveryInfo](const RecoveryInfo &item) {
        return item.abilityName == recoveryInfo.abilityName && item.bundleName == recoveryInfo.bundleName &&
               item.moduleName == recoveryInfo.moduleName;
    };
    auto i = find_if(instance.recoveryInfoQueue_.begin(), instance.recoveryInfoQueue_.end(), findByInfo);
    EXPECT_TRUE(i != instance.recoveryInfoQueue_.end());
}
} // namespace AAFwk
} // namespace OHOS
