/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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
#include "interceptor/screen_unlock_interceptor.h"
#undef private
#undef protected

#include "ability_util.h"
#include "event_report.h"
#include "parameters.h"
#include "scene_board_judgement.h"
#include "start_ability_utils.h"
#include "screenlock_manager.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
class ScreenUnlockInterceptorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

public:
};

void ScreenUnlockInterceptorTest::SetUpTestCase()
{}

void ScreenUnlockInterceptorTest::TearDownTestCase()
{}

void ScreenUnlockInterceptorTest::SetUp()
{}

void ScreenUnlockInterceptorTest::TearDown()
{}

/**
 * @tc.name: ScreenUnlockInterceptorTest_DoProcess_001
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require: issueI5I0DY
 */
HWTEST_F(ScreenUnlockInterceptorTest, DoProcess_WhenScreenLocked_001, TestSize.Level1)
{
    ScreenUnlockInterceptor screenUnlockInterceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken;
    std::function<bool(void)> shouldBlockAllAppStartFunc = []() -> bool {
        return false;
    };
    StartAbilityUtils::startAbilityInfo = std::make_shared<StartAbilityInfo>();
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldBlockAllAppStartFunc);
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        auto screenLockManager = OHOS::ScreenLock::ScreenLockManager::GetInstance();
        EXPECT_NE(screenLockManager, nullptr);
        screenLockManager->SetScreenLockedState(true);
        auto ret = screenUnlockInterceptor.DoProcess(param);
        bool isLocked = screenLockManager->IsScreenLocked();
        EXPECT_TRUE(isLocked);
        EXPECT_EQ(ret, ERR_BLOCK_START_FIRST_BOOT_SCREEN_UNLOCK);
    }
}

/**
 * @tc.name: ScreenUnlockInterceptorTest_DoProcess_001
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require: issueI5I0DY
 */
HWTEST_F(ScreenUnlockInterceptorTest, DoProcess_WhenScreenUnLocked_001, TestSize.Level1)
{
    ScreenUnlockInterceptor screenUnlockInterceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken;
    std::function<bool(void)> shouldBlockAllAppStartFunc = []() -> bool {
        return false;
    };
    StartAbilityUtils::startAbilityInfo = std::make_shared<StartAbilityInfo>();
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldBlockAllAppStartFunc);
    auto ret = screenUnlockInterceptor.DoProcess(param);
    if (!Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        auto screenLockManager = OHOS::ScreenLock::ScreenLockManager::GetInstance();
        EXPECT_NE(screenLockManager, nullptr);
        screenLockManager->SetScreenLockedState(false);
        auto ret = screenUnlockInterceptor.DoProcess(param);
        bool isLocked = screenLockManager->IsScreenLocked();
        EXPECT_FALSE(isLocked);
        EXPECT_EQ(ret, ERR_OK);
    }
}

/**
 * @tc.name: ScreenUnlockInterceptorTest_DoProcess_002
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require: issueI5I0DY
 */
HWTEST_F(ScreenUnlockInterceptorTest, DoProcess_002, TestSize.Level1)
{
    ScreenUnlockInterceptor screenUnlockInterceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken;
    std::function<bool(void)> shouldBlockAllAppStartFunc = []() -> bool {
        return false;
    };
    StartAbilityUtils::startAbilityInfo ->abilityInfo.applicationInfo.allowAppRunWhenDeviceFirstLocked = true;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldBlockAllAppStartFunc);
    auto ret = screenUnlockInterceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: ScreenUnlockInterceptorTest_DoProcess_003
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require: issueI5I0DY
 */
HWTEST_F(ScreenUnlockInterceptorTest, DoProcess_003, TestSize.Level1)
{
    ScreenUnlockInterceptor screenUnlockInterceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken;
    std::function<bool(void)> shouldBlockAllAppStartFunc = []() -> bool {
        return false;
    };
    StartAbilityUtils::startAbilityInfo ->abilityInfo.applicationInfo.allowAppRunWhenDeviceFirstLocked = false;
    StartAbilityUtils::startAbilityInfo ->abilityInfo.applicationInfo.isSystemApp = true;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldBlockAllAppStartFunc);
    auto ret = screenUnlockInterceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: ScreenUnlockInterceptorTest_DoProcess_004
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require: issueI5I0DY
 */
HWTEST_F(ScreenUnlockInterceptorTest, DoProcess_004, TestSize.Level1)
{
    ScreenUnlockInterceptor screenUnlockInterceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken;
    std::function<bool(void)> shouldBlockAllAppStartFunc = []() -> bool {
        return false;
    };
    StartAbilityUtils::startAbilityInfo = nullptr;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldBlockAllAppStartFunc);
    auto ret = screenUnlockInterceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: ScreenUnlockInterceptorTest_DoProcess_005
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require: issueI5I0DY
 */
HWTEST_F(ScreenUnlockInterceptorTest, DoProcess_005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DoProcess_005 start";
    ScreenUnlockInterceptor screenUnlockInterceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken;
    std::function<bool(void)> shouldBlockAllAppStartFunc = []() -> bool {
        return false;
    };
    StartAbilityUtils::startAbilityInfo = std::make_shared<StartAbilityInfo>();
    AppExecFwk::AbilityInfo targetAbilityInfo;
    targetAbilityInfo.type = AppExecFwk::AbilityType::EXTENSION;
    StartAbilityUtils::startAbilityInfo->abilityInfo = targetAbilityInfo;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldBlockAllAppStartFunc);
    auto ret = screenUnlockInterceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
    GTEST_LOG_(INFO) << "DoProcess_005 end";
}

/**
 * @tc.name: ScreenUnlockInterceptorTest_DoProcess_003
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 */
HWTEST_F(ScreenUnlockInterceptorTest, RecordExtensionEventWhenScreenUnlock_ScreenUnlocked, TestSize.Level1)
{
    ScreenUnlockInterceptor screenUnlockInterceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken;
    std::function<bool(void)> shouldBlockAllAppStartFunc = []() -> bool {
        return false;
    };
    StartAbilityUtils::startAbilityInfo ->abilityInfo.applicationInfo.allowAppRunWhenDeviceFirstLocked = false;
    StartAbilityUtils::startAbilityInfo ->abilityInfo.applicationInfo.isSystemApp = true;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldBlockAllAppStartFunc);
    auto screenLockManager = OHOS::ScreenLock::ScreenLockManager::GetInstance();
    EXPECT_NE(screenLockManager, nullptr);
    screenLockManager->SetScreenLockedState(false);
    auto ret = screenUnlockInterceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: RecordExtensionEventWhenScreenlock_BundleNameIsEmpty
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 */
HWTEST_F(ScreenUnlockInterceptorTest, RecordExtensionEventWhenScreenlock_BundleNameIsEmpty, TestSize.Level1)
{
    ScreenUnlockInterceptor screenUnlockInterceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken;
    std::function<bool(void)> shouldBlockAllAppStartFunc = []() -> bool {
        return false;
    };
    StartAbilityUtils::startAbilityInfo ->abilityInfo.applicationInfo.allowAppRunWhenDeviceFirstLocked = false;
    StartAbilityUtils::startAbilityInfo ->abilityInfo.applicationInfo.isSystemApp = true;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldBlockAllAppStartFunc);
    auto screenLockManager = OHOS::ScreenLock::ScreenLockManager::GetInstance();
    EXPECT_NE(screenLockManager, nullptr);
    screenLockManager->SetScreenLockedState(true);
    auto ret = screenUnlockInterceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: RecordExtensionEventWhenScreenlock_BundleNameNotEmpty
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 */
HWTEST_F(ScreenUnlockInterceptorTest, RecordExtensionEventWhenScreenlock_BundleNameNotEmpty, TestSize.Level1)
{
    ScreenUnlockInterceptor screenUnlockInterceptor;
    Want want;
    int requestCode = 123;
    int32_t userId = 1001;
    bool isWithUI = true;
    sptr<IRemoteObject> callerToken;
    std::function<bool(void)> shouldBlockAllAppStartFunc = []() -> bool {
        return false;
    };
    want.GetElement().SetBundleName("com.ohos.testapp");
    want.GetElement().SetAbilityName("testAbility");
    StartAbilityUtils::startAbilityInfo ->abilityInfo.applicationInfo.allowAppRunWhenDeviceFirstLocked = false;
    StartAbilityUtils::startAbilityInfo ->abilityInfo.applicationInfo.isSystemApp = true;
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, callerToken, shouldBlockAllAppStartFunc);
    auto screenLockManager = OHOS::ScreenLock::ScreenLockManager::GetInstance();
    EXPECT_NE(screenLockManager, nullptr);
    screenLockManager->SetScreenLockedState(true);
    auto ret = screenUnlockInterceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
}
} // namespace AAFwk
} // namespace OHOS
