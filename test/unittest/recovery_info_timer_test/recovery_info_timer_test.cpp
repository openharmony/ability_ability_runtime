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
/**
 * @tc.number: SubmitSaveRecoveryInfo_002
 * @tc.name: SubmitSaveRecoveryInfo
 * @tc.desc: Test that submitting a recovery info with the same identifiers replaces the existing one.
 * @tc.type: FUNC
 */
HWTEST_F(RecoveryInfoTimerTest, SubmitSaveRecoveryInfo_002, TestSize.Level1)
{
    RecoveryInfoTimer &instance = RecoveryInfoTimer::GetInstance();
    instance.recoveryInfoQueue_.clear();
    
    RecoveryInfo recoveryInfo1;
    recoveryInfo1.bundleName = "testBundleName";
    recoveryInfo1.moduleName = "testModuleName";
    recoveryInfo1.abilityName = "testAbilityName";
    recoveryInfo1.time = 1000;
    instance.SubmitSaveRecoveryInfo(recoveryInfo1);
    
    RecoveryInfo recoveryInfo2;
    recoveryInfo2.bundleName = "testBundleName";
    recoveryInfo2.moduleName = "testModuleName";
    recoveryInfo2.abilityName = "testAbilityName";
    recoveryInfo2.time = 2000;
    instance.SubmitSaveRecoveryInfo(recoveryInfo2);

    EXPECT_EQ(instance.recoveryInfoQueue_.size(), 1);
    EXPECT_EQ(instance.recoveryInfoQueue_.front().time, 2000);
}

/**
 * @tc.number: SubmitSaveRecoveryInfo_003
 * @tc.name: SubmitSaveRecoveryInfo_TimeoutDeletion
 * @tc.desc: Test that old recovery infos are deleted when they exceed the reserve number.
 * @tc.type: FUNC
 */
HWTEST_F(RecoveryInfoTimerTest, SubmitSaveRecoveryInfo_003, TestSize.Level1)
{
    RecoveryInfoTimer &instance = RecoveryInfoTimer::GetInstance();
    instance.recoveryInfoQueue_.clear();

    int64_t currentTime = 1000000;

    for (int i = 0; i < 7; i++) {
        RecoveryInfo oldInfo;
        oldInfo.bundleName = "oldBundle" + std::to_string(i);
        oldInfo.moduleName = "oldModule" + std::to_string(i);
        oldInfo.abilityName = "oldAbility" + std::to_string(i);
        oldInfo.time = currentTime - (168 * 60 * 60 + 1);
        oldInfo.tokenId = i;
        instance.recoveryInfoQueue_.push_back(oldInfo);
    }
    
    RecoveryInfo newInfo;
    newInfo.bundleName = "newBundle";
    newInfo.moduleName = "newModule";
    newInfo.abilityName = "newAbility";
    newInfo.time = currentTime;
    instance.SubmitSaveRecoveryInfo(newInfo);
    
    EXPECT_EQ(instance.recoveryInfoQueue_.size(), 6);
    EXPECT_NE(instance.recoveryInfoQueue_.front().bundleName, "oldBundle0");
    EXPECT_NE(instance.recoveryInfoQueue_.front().bundleName, "oldBundle1");
    EXPECT_EQ(instance.recoveryInfoQueue_.back().bundleName, "newBundle");
}

/**
 * @tc.number: SubmitSaveRecoveryInfo_004
 * @tc.name: SubmitSaveRecoveryInfo_FewerTimeoutsThanReserve
 * @tc.desc: Test case when there are timed out items but fewer than the reserve limit.
 * @tc.type: FUNC
 */
HWTEST_F(RecoveryInfoTimerTest, SubmitSaveRecoveryInfo_004, TestSize.Level1)
{
    RecoveryInfoTimer &instance = RecoveryInfoTimer::GetInstance();
    instance.recoveryInfoQueue_.clear();
    
    int64_t currentTime = 1000000;
    
    for (int i = 0; i < 3; i++) {
        RecoveryInfo oldInfo;
        oldInfo.bundleName = "oldBundle" + std::to_string(i);
        oldInfo.moduleName = "oldModule" + std::to_string(i);
        oldInfo.abilityName = "oldAbility" + std::to_string(i);
        oldInfo.time = currentTime - (168 * 60 * 60 + 1);
        oldInfo.tokenId = i;
        instance.recoveryInfoQueue_.push_back(oldInfo);
    }

    for (int i = 0; i < 2; i++) {
        RecoveryInfo recentInfo;
        recentInfo.bundleName = "recentBundle" + std::to_string(i);
        recentInfo.moduleName = "recentModule" + std::to_string(i);
        recentInfo.abilityName = "recentAbility" + std::to_string(i);
        recentInfo.time = currentTime - 1000;
        recentInfo.tokenId = i + 10;
        instance.recoveryInfoQueue_.push_back(recentInfo);
    }
    
    int originalSize = instance.recoveryInfoQueue_.size();

    RecoveryInfo newInfo;
    newInfo.bundleName = "newBundle";
    newInfo.moduleName = "newModule";
    newInfo.abilityName = "newAbility";
    newInfo.time = currentTime;
    instance.SubmitSaveRecoveryInfo(newInfo);
    EXPECT_EQ(instance.recoveryInfoQueue_.size(), originalSize + 1);
    bool foundFirstOld = false;
    for (const auto& info : instance.recoveryInfoQueue_) {
        if (info.bundleName == "oldBundle0") {
            foundFirstOld = true;
            break;
        }
    }
    EXPECT_TRUE(foundFirstOld);
    EXPECT_EQ(instance.recoveryInfoQueue_.back().bundleName, "newBundle");
}
} // namespace AAFwk
} // namespace OHOS
