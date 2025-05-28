/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "hilog_wrapper.h"
#define private public
#define protected public
#include "ability_context_impl.h"
#include "js_ui_ability.h"
#include "mock_scene_board_judgement.h"
#undef private
#undef protected
#include "js_runtime_utils.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AbilityRuntime {

class JsUiAbilityTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void JsUiAbilityTest::SetUpTestCase() {}

void JsUiAbilityTest::TearDownTestCase() {}

void JsUiAbilityTest::SetUp() {}

void JsUiAbilityTest::TearDown() {}

/**
 * @tc.name: JSUIAbility_OnWillForeground_0100
 * @tc.desc: OnWillForeground test
 * @tc.desc: Verify function OnWillForeground.
 */
HWTEST_F(JsUiAbilityTest, JSUIAbility_OnWillForeground_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "JSUIAbility_OnWillForeground_0100 start";
    AbilityRuntime::Runtime::Options options;
    options.lang = AbilityRuntime::Runtime::Language::JS;
    auto runtime = AbilityRuntime::Runtime::Create(options);
    auto ability = AbilityRuntime::JsUIAbility::Create(runtime);
    ASSERT_NE(ability, nullptr);
    ability->OnWillForeground();
    GTEST_LOG_(INFO) << "JSUIAbility_OnWillForeground_0100 end";
}
/**
 * @tc.name: JSUIAbility_OnDidForeground_0100
 * @tc.desc: OnDidForeground test
 * @tc.desc: Verify function OnDidForeground.
 */
HWTEST_F(JsUiAbilityTest, JSUIAbility_OnDidForeground_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "JSUIAbility_OnDidForeground_0100 start";
    AbilityRuntime::Runtime::Options options;
    options.lang = AbilityRuntime::Runtime::Language::JS;
    auto runtime = AbilityRuntime::Runtime::Create(options);
    auto ability = AbilityRuntime::JsUIAbility::Create(runtime);
    ASSERT_NE(ability, nullptr);
    ability->OnDidForeground();
    GTEST_LOG_(INFO) << "JSUIAbility_OnDidForeground_0100 end";
}

/**
 * @tc.name: JSUIAbility_OnWillBackground_0100
 * @tc.desc: OnWillBackground test
 * @tc.desc: Verify function OnWillBackground.
 */
HWTEST_F(JsUiAbilityTest, JSUIAbility_OnWillBackground_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "JSUIAbility_OnWillBackground_0100 start";
    AbilityRuntime::Runtime::Options options;
    options.lang = AbilityRuntime::Runtime::Language::JS;
    auto runtime = AbilityRuntime::Runtime::Create(options);
    auto ability = AbilityRuntime::JsUIAbility::Create(runtime);
    ASSERT_NE(ability, nullptr);
    ability->OnWillBackground();
    GTEST_LOG_(INFO) << "JSUIAbility_OnWillBackground_0100 end";
}

/**
 * @tc.name: JSUIAbility_OnDidBackground_0100
 * @tc.desc: OnDidBackground test
 * @tc.desc: Verify function OnDidBackground.
 */
HWTEST_F(JsUiAbilityTest, JSUIAbility_OnDidBackground_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "JSUIAbility_OnDidBackground_0100 start";
    AbilityRuntime::Runtime::Options options;
    options.lang = AbilityRuntime::Runtime::Language::JS;
    auto runtime = AbilityRuntime::Runtime::Create(options);
    auto ability = AbilityRuntime::JsUIAbility::Create(runtime);
    ASSERT_NE(ability, nullptr);
    ability->OnDidBackground();
    GTEST_LOG_(INFO) << "JSUIAbility_OnDidBackground_0100 end";
}

/**
 * @tc.name: JSUIAbility_OnAbilityRequestFailure_0100
 * @tc.desc: OnAbilityRequestFailure test
 * @tc.desc: Verify function OnAbilityRequestFailure.
 */
HWTEST_F(JsUiAbilityTest, JSUIAbility_OnAbilityRequestFailure_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "JSUIAbility_OnAbilityRequestFailure_0100 start";
    AbilityRuntime::Runtime::Options options;
    options.lang = AbilityRuntime::Runtime::Language::JS;
    auto runtime = AbilityRuntime::Runtime::Create(options);
    auto ability = AbilityRuntime::JsUIAbility::Create(runtime);
    ASSERT_NE(ability, nullptr);
    std::string requestId = "1234567890";
    AppExecFwk::ElementName element("", "com.example.com", "MainAbility");
    std::string message = "failure";
    ability->OnAbilityRequestFailure(requestId, element, message);
    GTEST_LOG_(INFO) << "JSUIAbility_OnAbilityRequestFailure_0100 end";
}

/**
 * @tc.name: JSUIAbility_OnAbilityRequestSuccess_0100
 * @tc.desc: OnAbilityRequestSuccess test
 * @tc.desc: Verify function OnAbilityRequestSuccess.
 */
HWTEST_F(JsUiAbilityTest, JSUIAbility_OnAbilityRequestSuccess_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "JSUIAbility_OnAbilityRequestSuccess_0100 start";
    AbilityRuntime::Runtime::Options options;
    options.lang = AbilityRuntime::Runtime::Language::JS;
    auto runtime = AbilityRuntime::Runtime::Create(options);
    auto ability = AbilityRuntime::JsUIAbility::Create(runtime);
    ASSERT_NE(ability, nullptr);
    std::string requestId = "1234567890";
    AppExecFwk::ElementName element("", "com.example.com", "MainAbility");
    std::string message = "success";
    ability->OnAbilityRequestSuccess(requestId, element, message);
    GTEST_LOG_(INFO) << "JSUIAbility_OnAbilityRequestSuccess_0100 end";
}

/**
 * @tc.name: JSUIAbility_DoOnForegroundForSceneIsNull_0100
 * @tc.desc: DoOnForegroundForSceneIsNull test
 * @tc.desc: Verify function DoOnForegroundForSceneIsNull.
 */
HWTEST_F(JsUiAbilityTest, JSUIAbility_DoOnForegroundForSceneIsNull_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "JSUIAbility_DoOnForegroundForSceneIsNull_0100 start";
    AbilityRuntime::Runtime::Options options;
    options.lang = AbilityRuntime::Runtime::Language::JS;
    auto runtime = AbilityRuntime::Runtime::Create(options);
    auto jsRuntime = static_cast<AbilityRuntime::JsRuntime*>(runtime.get());
    auto ability = std::make_shared<AbilityRuntime::JsUIAbility>(*jsRuntime);

    wptr<IRemoteObject> token(new IPCObjectStub());
    ability->sessionToken_ = token;
    auto abilityContextImpl = std::make_shared<AbilityContextImpl>();
    ability->abilityContext_ = abilityContextImpl;
    Rosen::SceneBoardJudgement::flag_ = true;
    Want want;
    std::string navDestinationInfo = "testNavDestinationInfo";
    want.SetParam(Want::ATOMIC_SERVICE_SHARE_ROUTER, navDestinationInfo);
    ability->DoOnForegroundForSceneIsNull(want);
    EXPECT_NE(abilityContextImpl->GetSessionToken(), nullptr);

    navDestinationInfo = "";
    want.SetParam(Want::ATOMIC_SERVICE_SHARE_ROUTER, navDestinationInfo);
    ability->DoOnForegroundForSceneIsNull(want);
    EXPECT_NE(abilityContextImpl->GetSessionToken(), nullptr);
    GTEST_LOG_(INFO) << "JSUIAbility_DoOnForegroundForSceneIsNull_0100 end";
}
} // namespace AbilityRuntime
} // namespace OHOS