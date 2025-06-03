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

#define private public
#include "ability_start_with_wait_observer_manager.h"
#undef private
 
#include "ability_start_with_wait_observer_utils.h"
#include "ability_start_with_wait_observer_proxy.h"
#include "ability_start_with_wait_observer_stub.h"
#include "hilog_tag_wrapper.h"

using namespace testing;
using namespace testing::ext;
 
namespace OHOS {
namespace AAFwk {

class MockAbilityStartWithWaitObserver : public AbilityStartWithWaitObserverStub {
public:
    int32_t NotifyAATerminateWait(const AbilityStartWithWaitObserverData &abilityStartWithWaitData) override
    {
        return 0;
    }
};
class AbilityStartWithWaitObserverUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AbilityStartWithWaitObserverUtilsTest::SetUpTestCase(void)
{}

void AbilityStartWithWaitObserverUtilsTest::TearDownTestCase(void)
{}

void AbilityStartWithWaitObserverUtilsTest::SetUp()
{}

void AbilityStartWithWaitObserverUtilsTest::TearDown()
{}

/**
 * @tc.name: AbilityStartWithWaitObserverUtilsTest_0100
 * @tc.desc: Ability stage basic func test.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AbilityStartWithWaitObserverUtilsTest, AbilityStartWithWaitObserverUtilsTest_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Want want;
    sptr<IAbilityStartWithWaitObserver> observer;
    AbilityStartWithWaitObserverManager::GetInstance().RegisterObserver(want, observer);
    EXPECT_EQ(want.GetIntParam(Want::START_ABILITY_WITH_WAIT_OBSERVER_ID_KEY, -1), -1);

    sptr<IRemoteObject> observerStub = nullptr;
    sptr<IAbilityStartWithWaitObserver> observer2 = sptr<AbilityStartWithWaitObserverProxy>::MakeSptr(observerStub);
    AbilityStartWithWaitObserverManager::GetInstance().RegisterObserver(want, observer2);
    EXPECT_EQ(want.GetIntParam(Want::START_ABILITY_WITH_WAIT_OBSERVER_ID_KEY, -1), -1);
}

/**
 * @tc.name: AbilityStartWithWaitObserverUtilsTest_0200
 * @tc.desc: Ability stage basic func test.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AbilityStartWithWaitObserverUtilsTest, AbilityStartWithWaitObserverUtilsTest_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AbilityStartWithWaitObserverManager::GetInstance().observerList_.clear();
    Want want;
    sptr<IRemoteObject> observerStub = sptr<MockAbilityStartWithWaitObserver>::MakeSptr();
    sptr<IAbilityStartWithWaitObserver> observer = sptr<AbilityStartWithWaitObserverProxy>::MakeSptr(observerStub);
    AbilityStartWithWaitObserverManager::GetInstance().RegisterObserver(want, observer);
    EXPECT_EQ(AbilityStartWithWaitObserverManager::GetInstance().observerList_.size(), 1);

    // duplicate regist same observer, failed
    AbilityStartWithWaitObserverManager::GetInstance().RegisterObserver(want, observer);
    EXPECT_EQ(AbilityStartWithWaitObserverManager::GetInstance().observerList_.size(), 1);

    // register new observer success, expect key = 1
    observerStub = sptr<MockAbilityStartWithWaitObserver>::MakeSptr();
    observer = sptr<AbilityStartWithWaitObserverProxy>::MakeSptr(observerStub);
    AbilityStartWithWaitObserverManager::GetInstance().RegisterObserver(want, observer);
    EXPECT_EQ(AbilityStartWithWaitObserverManager::GetInstance().observerList_.size(), 2); // 2 means object number
}

/**
 * @tc.name: AbilityStartWithWaitObserverUtilsTest_0300
 * @tc.desc: Ability stage basic func test.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AbilityStartWithWaitObserverUtilsTest, AbilityStartWithWaitObserverUtilsTest_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AbilityStartWithWaitObserverManager::GetInstance().observerList_.clear();
    AbilityForegroundInfo info;
    sptr<IAbilityStartWithWaitObserver> observer1 = nullptr;
    AbilityStartWithWaitObserverManager::GetInstance().observerList_.emplace(observer1, info);

    sptr<IRemoteObject> observerStub = sptr<MockAbilityStartWithWaitObserver>::MakeSptr();
    sptr<IAbilityStartWithWaitObserver> observer = sptr<AbilityStartWithWaitObserverProxy>::MakeSptr(observerStub);
    Want want;
    AbilityStartWithWaitObserverManager::GetInstance().RegisterObserver(want, observer);
    EXPECT_EQ(AbilityStartWithWaitObserverManager::GetInstance().observerList_.size(), 2); // 2 means object left

    // unregist observer success.
    AbilityStartWithWaitObserverManager::GetInstance().UnregisterObserver(observer);
    EXPECT_EQ(AbilityStartWithWaitObserverManager::GetInstance().observerList_.size(), 1);
}

/**
 * @tc.name: AbilityStartWithWaitObserverUtilsTest_0400
 * @tc.desc: Ability stage basic func test.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AbilityStartWithWaitObserverUtilsTest, AbilityStartWithWaitObserverUtilsTest_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AbilityStartWithWaitObserverManager::GetInstance().observerList_.clear();
    AbilityForegroundInfo info;
    sptr<IAbilityStartWithWaitObserver> observer1 = nullptr;
    AbilityStartWithWaitObserverManager::GetInstance().observerList_.emplace(observer1, info);

    sptr<IRemoteObject> observerStub1 = nullptr;
    sptr<IAbilityStartWithWaitObserver> observer2 = sptr<AbilityStartWithWaitObserverProxy>::MakeSptr(observerStub1);
    AbilityStartWithWaitObserverManager::GetInstance().observerList_.emplace(observer2, info);

    sptr<IRemoteObject> observerStub2 = sptr<MockAbilityStartWithWaitObserver>::MakeSptr();
    sptr<IAbilityStartWithWaitObserver> observer3 = sptr<AbilityStartWithWaitObserverProxy>::MakeSptr(observerStub2);

    Want want;
    AbilityStartWithWaitObserverManager::GetInstance().RegisterObserver(want, observer3);

    Want newWant;
    AbilityStartWithWaitObserverManager::GetInstance().NotifyAATerminateWait(
        newWant, TerminateReason::TERMINATE_FOR_NON_UI_ABILITY);
    EXPECT_EQ(AbilityStartWithWaitObserverManager::GetInstance().observerList_.size(), 3); // 3 means object left
    // unregist observer success
    AbilityStartWithWaitObserverManager::GetInstance().NotifyAATerminateWait(
        want, TerminateReason::TERMINATE_FOR_NON_UI_ABILITY);
    EXPECT_EQ(AbilityStartWithWaitObserverManager::GetInstance().observerList_.size(), 2); // 2 means object left
}

/**
 * @tc.name: AbilityStartWithWaitObserverUtilsTest_0500
 * @tc.desc: Ability stage basic func test.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AbilityStartWithWaitObserverUtilsTest, AbilityStartWithWaitObserverUtilsTest_0500, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AbilityStartWithWaitObserverManager::GetInstance().observerList_.clear();
    sptr<IAbilityStartWithWaitObserver> observer1 = nullptr;
    AbilityForegroundInfo info;
    AbilityStartWithWaitObserverManager::GetInstance().observerList_.emplace(observer1, info);

    sptr<IRemoteObject> observerStub1 = nullptr;
    sptr<IAbilityStartWithWaitObserver> observer2 = sptr<AbilityStartWithWaitObserverProxy>::MakeSptr(observerStub1);
    AbilityStartWithWaitObserverManager::GetInstance().observerList_.emplace(observer2, info);

    sptr<IRemoteObject> observerStub2 = sptr<MockAbilityStartWithWaitObserver>::MakeSptr();
    sptr<IAbilityStartWithWaitObserver> observer3 = sptr<AbilityStartWithWaitObserverProxy>::MakeSptr(observerStub2);

    Want want;
    AbilityStartWithWaitObserverManager::GetInstance().RegisterObserver(want, observer3);

    std::shared_ptr<AbilityRecord> abilityRecord1 = nullptr;
    AbilityStartWithWaitObserverManager::GetInstance().NotifyAATerminateWait(abilityRecord1);
    EXPECT_EQ(AbilityStartWithWaitObserverManager::GetInstance().observerList_.size(), 3); // 3 means object left

    Want newWant;
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo appInfo;
    std::shared_ptr<AbilityRecord> abilityRecord2 = std::make_shared<AbilityRecord>(newWant, abilityInfo, appInfo);
    AbilityStartWithWaitObserverManager::GetInstance().NotifyAATerminateWait(abilityRecord2);
    EXPECT_EQ(AbilityStartWithWaitObserverManager::GetInstance().observerList_.size(), 3); // 3 means object left

    std::shared_ptr<AbilityRecord> abilityRecord3 = std::make_shared<AbilityRecord>(want, abilityInfo, appInfo);
    AbilityStartWithWaitObserverManager::GetInstance().NotifyAATerminateWait(abilityRecord3);
    EXPECT_EQ(AbilityStartWithWaitObserverManager::GetInstance().observerList_.size(), 2); // 2 means object left
}

/**
 * @tc.name: AbilityStartWithWaitObserverUtilsTest_0600
 * @tc.desc: SetColdStartForShellCall func test.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AbilityStartWithWaitObserverUtilsTest, AbilityStartWithWaitObserverUtilsTest_0600, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AbilityStartWithWaitObserverManager::GetInstance().observerList_.clear();
    AbilityForegroundInfo info;
    sptr<IAbilityStartWithWaitObserver> observer1 = nullptr;
    AbilityStartWithWaitObserverManager::GetInstance().observerList_.emplace(observer1, info);

    sptr<IRemoteObject> observerStub1 = nullptr;
    sptr<IAbilityStartWithWaitObserver> observer2 = sptr<AbilityStartWithWaitObserverProxy>::MakeSptr(observerStub1);
    AbilityStartWithWaitObserverManager::GetInstance().observerList_.emplace(observer2, info);

    sptr<IRemoteObject> observerStub2 = sptr<MockAbilityStartWithWaitObserver>::MakeSptr();
    sptr<IAbilityStartWithWaitObserver> observer3 = sptr<AbilityStartWithWaitObserverProxy>::MakeSptr(observerStub2);
    Want want;
    AbilityStartWithWaitObserverManager::GetInstance().RegisterObserver(want, observer3);

    std::shared_ptr<AbilityRecord> abilityRecord1 = nullptr;
    AbilityStartWithWaitObserverManager::GetInstance().SetColdStartForShellCall(abilityRecord1);
    EXPECT_EQ(AbilityStartWithWaitObserverManager::GetInstance().observerList_.size(), 3); // 3 means object left

    Want newWant;
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ApplicationInfo appInfo;
    std::shared_ptr<AbilityRecord> abilityRecord2 = std::make_shared<AbilityRecord>(newWant, abilityInfo, appInfo);
    AbilityStartWithWaitObserverManager::GetInstance().NotifyAATerminateWait(abilityRecord2);
    EXPECT_EQ(AbilityStartWithWaitObserverManager::GetInstance().observerList_.size(), 3); // 3 means object left

    std::shared_ptr<AbilityRecord> abilityRecord3 = std::make_shared<AbilityRecord>(want, abilityInfo, appInfo);
    AbilityStartWithWaitObserverManager::GetInstance().NotifyAATerminateWait(abilityRecord3);
    EXPECT_EQ(AbilityStartWithWaitObserverManager::GetInstance().observerList_.size(), 2); // 2 means object left
}

/**
 * @tc.name: AbilityStartWithWaitObserverUtilsTest_0700
 * @tc.desc: GenerateDeathRecipient func test.
 * @tc.type: FUNC
 * @tc.require: issue
 */
HWTEST_F(AbilityStartWithWaitObserverUtilsTest, AbilityStartWithWaitObserverUtilsTest_0700, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    sptr<IAbilityStartWithWaitObserver> observer1 = nullptr;
    auto deathRecipient = AbilityStartWithWaitObserverManager::GetInstance().GenerateDeathRecipient(observer1);
    EXPECT_EQ(deathRecipient, nullptr);

    sptr<IRemoteObject> observerStub1 = nullptr;
    sptr<IAbilityStartWithWaitObserver> observer2 = sptr<AbilityStartWithWaitObserverProxy>::MakeSptr(observerStub1);
    deathRecipient = AbilityStartWithWaitObserverManager::GetInstance().GenerateDeathRecipient(observer2);
    EXPECT_EQ(deathRecipient, nullptr);

    sptr<IRemoteObject> observerStub2 = sptr<MockAbilityStartWithWaitObserver>::MakeSptr();
    sptr<IAbilityStartWithWaitObserver> observer3 = sptr<AbilityStartWithWaitObserverProxy>::MakeSptr(observerStub2);
    deathRecipient = AbilityStartWithWaitObserverManager::GetInstance().GenerateDeathRecipient(observer3);
    EXPECT_NE(deathRecipient, nullptr);
}
} // namespace AAFwk
} // namespace OHOS