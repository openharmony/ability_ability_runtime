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
#include "interceptor/screen_unlock_interceptor.h"
#include "screenlock_manager_proxy.h"
#include "screenlock_manager.h"
#include "sclock_log.h"
#include "screenlock_server_ipc_interface_code.h"
#include "parameters.h"
#undef private
#undef protected
#include "start_ability_utils.h"

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
};

void ScreenUnlockInterceptorTest::SetUpTestCase()
{}

void ScreenUnlockInterceptorTest::TearDownTestCase()
{}

void ScreenUnlockInterceptorTest::SetUp()
{}

void ScreenUnlockInterceptorTest::TearDown()
{}

HWTEST_F(ScreenUnlockInterceptorTest, CreateScreenUnlockInterceptor_001, TestSize.Level1)
{
    std::shared_ptr<ScreenUnlockInterceptor> executer = std::make_shared<ScreenUnlockInterceptor>();
    EXPECT_NE(executer, nullptr);
}

/**
 * @tc.name: ScreenUnlockInterceptorTest_001
 * @tc.desc: ScreenUnlockInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenUnlockInterceptorTest, ScreenUnlockInterceptor_001, TestSize.Level1)
{
    std::shared_ptr<ScreenUnlockInterceptor> executer = std::make_shared<ScreenUnlockInterceptor>();
    Want want;
    ElementName element("", "com.test.unlock", "MainAbility");
    want.SetElement(element);
    std::string SUPPORT_SCREEN_UNLOCK_STARTUP = "persist.sys.ability.support.screen_unlock_startup";
    bool isset = OHOS::system::SetParameter(SUPPORT_SCREEN_UNLOCK_STARTUP, "false");
    int requestCode = 0;
    int userId = 100;
    AbilityInterceptorParam param = AbilityInterceptorParam(want, requestCode, userId, true, nullptr);
    int result = executer->DoProcess(param);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ScreenUnlockInterceptorTest_002
 * @tc.desc: ScreenUnlockInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenUnlockInterceptorTest, ScreenUnlockInterceptor_002, TestSize.Level1)
{
    std::shared_ptr<ScreenUnlockInterceptor> executer = std::make_shared<ScreenUnlockInterceptor>();
    Want want;
    ElementName element("", "com.test.unlock3", "MainAbility");
    want.SetElement(element);
    int32_t abilityuserId = 0;
    int32_t appIndex = 0;
    std::string SUPPORT_SCREEN_UNLOCK_STARTUP = "persist.sys.ability.support.screen_unlock_startup";
    bool isset = OHOS::system::SetParameter(SUPPORT_SCREEN_UNLOCK_STARTUP, "false");
    StartAbilityUtils::startAbilityInfo =  StartAbilityInfo::CreateStartExtensionInfo(want, abilityuserId, appIndex);
    StartAbilityUtils::startAbilityInfo->abilityInfo.applicationInfo.isSystemApp = true;
    int userId = 100;
    AbilityInterceptorParam param = AbilityInterceptorParam(want, 0, userId, false, nullptr);
    int result = executer->DoProcess(param);
    EXPECT_EQ(result, ERR_OK);
}

/**
 * @tc.name: ScreenUnlockInterceptorTest_003
 * @tc.desc: ScreenUnlockInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenUnlockInterceptorTest, ScreenUnlockInterceptor_003, TestSize.Level1)
{
    std::shared_ptr<ScreenUnlockInterceptor> executer = std::make_shared<ScreenUnlockInterceptor>();
    Want want;
    ElementName element("", "com.test..unlock4", "MainAbility");
    want.SetElement(element);
    int32_t abilityuserId = 0;
    int32_t appIndex = 0;
    std::string SUPPORT_SCREEN_UNLOCK_STARTUP = "persist.sys.ability.support.screen_unlock_startup";
    bool isset = OHOS::system::SetParameter(SUPPORT_SCREEN_UNLOCK_STARTUP, "false");
    StartAbilityUtils::startAbilityInfo =  StartAbilityInfo::CreateStartExtensionInfo(want, abilityuserId, appIndex);
    int userId = 100;
    AbilityInterceptorParam param = AbilityInterceptorParam(want, 0, userId, false, nullptr);
    int result = executer->DoProcess(param);
    EXPECT_EQ(result, ERR_BLOCK_START_FIRST_BOOT_SCREEN_UNLOCK);
}

/**
 * @tc.name: ScreenUnlockInterceptorTest_004
 * @tc.desc: ScreenUnlockInterceptor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ScreenUnlockInterceptorTest, ScreenUnlockInterceptor_004, TestSize.Level1)
{
    std::shared_ptr<ScreenUnlockInterceptor> executer = std::make_shared<ScreenUnlockInterceptor>();
    Want want;
    ElementName element("", "com.test.unlock2", "MainAbility");
    want.SetElement(element);
    std::string SUPPORT_SCREEN_UNLOCK_STARTUP = "persist.sys.ability.support.screen_unlock_startup";
    bool isset = OHOS::system::SetParameter(SUPPORT_SCREEN_UNLOCK_STARTUP, "true");
    int userId = 100;
    AbilityInterceptorParam param = AbilityInterceptorParam(want, 0, userId, false, nullptr);
    int result = executer->DoProcess(param);
    EXPECT_EQ(result, ERR_OK);
}
} // namespace AAFwk
} // namespace OHOS
