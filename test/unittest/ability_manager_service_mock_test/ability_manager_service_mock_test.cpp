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
#define protected public
#include "ability_manager_service.h"
#include "session_info.h"
#include "sub_managers_helper.h"
#undef private
#undef protected
#include "ability_manager_errors.h"
#include "start_ability_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
namespace {
    constexpr char INSIGHT_INTENT_EXECUTE_PARAM_NAME[] = "ohos.insightIntent.executeParam.name";
}
class AbilityManagerServiceMockTest : public Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
    
void AbilityManagerServiceMockTest::SetUpTestCase() {}
    
void AbilityManagerServiceMockTest::TearDownTestCase() {}
    
void AbilityManagerServiceMockTest::SetUp() {}
    
void AbilityManagerServiceMockTest::TearDown() {}

/**
 * @tc.name: ExecuteIntent_0100
 * @tc.desc: Test  StartAbilityByCallWithInsightIntent error
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerServiceMockTest, ExecuteIntent_0100, TestSize.Level1)
{
    auto abilityMs = std::make_shared<AbilityManagerService>();
    ASSERT_NE(abilityMs, nullptr);
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "ability1";
    param.insightIntentName_ = "test1";
    param.insightIntentParam_ = std::make_shared<WantParams>();
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND;
    std::shared_ptr<AbilityRecord> ability = nullptr;
    sptr<IRemoteObject> callerToken = new OHOS::AAFwk::Token(ability);
    uint64_t key = 1;
    auto ret = abilityMs->ExecuteIntent(key, callerToken, param);
    EXPECT_EQ(ret, RESOLVE_ABILITY_ERR);
}

/**
 * @tc.name: ExecuteIntent_0200
 * @tc.desc: Test  StartAbilityWithInsightIntent error
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerServiceMockTest, ExecuteIntent_0200, TestSize.Level1)
{
    auto abilityMs = std::make_shared<AbilityManagerService>();
    ASSERT_NE(abilityMs, nullptr);
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "ability1";
    param.insightIntentName_ = "test1";
    param.insightIntentParam_ = std::make_shared<WantParams>();
    param.executeMode_ = AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND;
    std::shared_ptr<AbilityRecord> ability = nullptr;
    sptr<IRemoteObject> callerToken = new OHOS::AAFwk::Token(ability);
    uint64_t key = 1;
    auto ret = abilityMs->ExecuteIntent(key, callerToken, param);
    EXPECT_EQ(ret, ERR_NULL_INTERCEPTOR_EXECUTER);
}

/**
 * @tc.name: ExecuteIntent_0300
 * @tc.desc: Test  StartExtensionAbilityWithInsightIntent error
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerServiceMockTest, ExecuteIntent_0300, TestSize.Level1)
{
    auto abilityMs = std::make_shared<AbilityManagerService>();
    ASSERT_NE(abilityMs, nullptr);
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "ability1";
    param.insightIntentName_ = "test1";
    param.insightIntentParam_ = std::make_shared<WantParams>();
    param.executeMode_ = AppExecFwk::ExecuteMode::SERVICE_EXTENSION_ABILITY;
    std::shared_ptr<AbilityRecord> ability = nullptr;
    sptr<IRemoteObject> callerToken = new OHOS::AAFwk::Token(ability);
    uint64_t key = 1;
    auto ret = abilityMs->ExecuteIntent(key, callerToken, param);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: PreloadUIExtensionAbilityInner_0100
 * @tc.desc: Test  GetConnectManagerByUserId error
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerServiceMockTest, PreloadUIExtensionAbilityInner_0100, TestSize.Level1)
{
    auto abilityMs = std::make_shared<AbilityManagerService>();
    ASSERT_NE(abilityMs, nullptr);
    std::string bundleName = "testBundleName";
    std::string abilityName_ = "testAbility";
    Want want;
    want.SetElementName(bundleName, abilityName_);
    StartAbilityUtils::startAbilityInfo = std::make_shared<StartAbilityInfo>();
    AppExecFwk::ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    applicationInfo.name = "test";
    StartAbilityUtils::startAbilityInfo->abilityInfo.applicationInfo = applicationInfo;
    StartAbilityUtils::startAbilityInfo->status = ERR_OK;
    StartAbilityUtils::startAbilityInfo->abilityInfo.visible = true;
    abilityMs->subManagersHelper_ = nullptr;
    auto ret = abilityMs->PreloadUIExtensionAbilityInner(want, bundleName, 1, 1);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: StartUIExtensionAbility_0100
 * @tc.desc: Test  getabilityInfos error
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerServiceMockTest, StartUIExtensionAbility_0100, TestSize.Level1)
{
    auto abilityMs = std::make_shared<AbilityManagerService>();
    ASSERT_NE(abilityMs, nullptr);
    Want want;
    want.SetParam(AAFwk::SCREEN_MODE_KEY, AAFwk::EMBEDDED_FULL_SCREEN_MODE);
    sptr<SessionInfo> sessionInfo(new SessionInfo());
    sessionInfo->want = want;
    auto ret = abilityMs->StartUIExtensionAbility(sessionInfo, 1);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}

/**
 * @tc.name: StartUIExtensionAbility_0200
 * @tc.desc: Test  CheckAndUpdateWant error
 * @tc.type: FUNC
 */
HWTEST_F(AbilityManagerServiceMockTest, StartUIExtensionAbility_0200, TestSize.Level1)
{
    auto abilityMs = std::make_shared<AbilityManagerService>();
    ASSERT_NE(abilityMs, nullptr);
    Want want;
    want.SetParam(INSIGHT_INTENT_EXECUTE_PARAM_NAME, true);
    sptr<SessionInfo> sessionInfo(new SessionInfo());
    sessionInfo->want = want;
    auto ret = abilityMs->StartUIExtensionAbility(sessionInfo, 1);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
}
}
}