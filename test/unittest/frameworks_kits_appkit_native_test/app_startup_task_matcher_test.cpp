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
#include "app_startup_task_matcher.h"
#undef private
#undef protected
#include "insight_intent_execute_param.h"
#include "js_startup_task.h"
#include "preload_so_startup_task.h"

using namespace testing::ext;
namespace OHOS {
namespace AbilityRuntime {
class AppStartupTaskMatcherTest : public testing::Test {
public:
    AppStartupTaskMatcherTest()
    {}
    ~AppStartupTaskMatcherTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AppStartupTaskMatcherTest::SetUpTestCase(void)
{}

void AppStartupTaskMatcherTest::TearDownTestCase(void)
{}

void AppStartupTaskMatcherTest::SetUp(void)
{}

void AppStartupTaskMatcherTest::TearDown(void)
{}

/**
 * @tc.name: MatchRulesStartupTaskMatcher_0100
 * @tc.type: FUNC
 * @tc.Function: MatchRulesStartupTaskMatcher
 */
HWTEST_F(AppStartupTaskMatcherTest, MatchRulesStartupTaskMatcher_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "MatchRulesStartupTaskMatcher_0100 start";
    std::unique_ptr<NativeReference> startupJsRef = nullptr;
    std::shared_ptr<NativeReference> contextJsRef = nullptr;
    JsRuntime jsRuntime;
    JsStartupTask task("task1", jsRuntime, startupJsRef, contextJsRef);
    StartupTaskMatchRules matchRules;
    matchRules.actions.emplace_back("com.example.test.action1");
    task.SetModuleName("entry");
    task.SetMatchRules(matchRules);

    auto want = std::make_shared<AAFwk::Want>();
    want->SetAction("com.example.test.action2");
    MatchRulesStartupTaskMatcher taskMatcher(want);
    auto ret = taskMatcher.Match(task);
    EXPECT_EQ(ret, false);

    auto moduleMatcher = std::make_shared<ModuleStartStartupTaskMatcher>("feature");
    taskMatcher.SetModuleMatcher(moduleMatcher);
    ret = taskMatcher.Match(task);
    EXPECT_EQ(ret, false);

    auto moduleMatcher2 = std::make_shared<ModuleStartStartupTaskMatcher>("entry");
    taskMatcher.SetModuleMatcher(moduleMatcher2);
    ret = taskMatcher.Match(task);
    EXPECT_EQ(ret, false);
    GTEST_LOG_(INFO) << "MatchRulesStartupTaskMatcher_0100 end";
}

/**
 * @tc.name: MatchRulesStartupTaskMatcher_0200
 * @tc.type: FUNC
 * @tc.Function: MatchRulesStartupTaskMatcher
 */
HWTEST_F(AppStartupTaskMatcherTest, MatchRulesStartupTaskMatcher_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "MatchRulesStartupTaskMatcher_0200 start";
    std::unique_ptr<NativeReference> startupJsRef = nullptr;
    std::shared_ptr<NativeReference> contextJsRef = nullptr;
    JsRuntime jsRuntime;
    JsStartupTask task("task1", jsRuntime, startupJsRef, contextJsRef);
    StartupTaskMatchRules matchRules;
    matchRules.actions.emplace_back("com.example.test.action1");
    task.SetModuleName("entry");
    task.SetMatchRules(matchRules);

    auto want = std::make_shared<AAFwk::Want>();
    want->SetAction("com.example.test.action1");
    MatchRulesStartupTaskMatcher taskMatcher(want);
    auto ret = taskMatcher.Match(task);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "MatchRulesStartupTaskMatcher_0200 end";
}

/**
 * @tc.name: MatchRulesStartupTaskMatcher_0300
 * @tc.type: FUNC
 * @tc.Function: MatchRulesStartupTaskMatcher
 */
HWTEST_F(AppStartupTaskMatcherTest, MatchRulesStartupTaskMatcher_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "MatchRulesStartupTaskMatcher_0300 start";
    std::unique_ptr<NativeReference> startupJsRef = nullptr;
    std::shared_ptr<NativeReference> contextJsRef = nullptr;
    JsRuntime jsRuntime;
    JsStartupTask task("task1", jsRuntime, startupJsRef, contextJsRef);
    StartupTaskMatchRules matchRules;
    matchRules.actions.emplace_back("com.example.test.action1");
    matchRules.customization.emplace_back("custom1");
    task.SetModuleName("entry");
    task.SetMatchRules(matchRules);

    auto want = std::make_shared<AAFwk::Want>();
    want->SetAction("com.example.test.action2");
    MatchRulesStartupTaskMatcher taskMatcher(want);
    auto customizationMatcher = std::make_shared<CustomizationStartupTaskMatcher>("custom1");
    taskMatcher.SetCustomizationMatcher(customizationMatcher);
    auto ret = taskMatcher.Match(task);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "MatchRulesStartupTaskMatcher_0300 end";
}

/**
 * @tc.name: DefaultStartupTaskMatcher_0100
 * @tc.type: FUNC
 * @tc.Function: DefaultStartupTaskMatcher
 */
HWTEST_F(AppStartupTaskMatcherTest, DefaultStartupTaskMatcher_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "DefaultStartupTaskMatcher_0100 start";
    PreloadSoStartupTask task("task1", "url", "path");
    task.SetModuleName("entry");
    task.SetIsExcludeFromAutoStart(false);

    DefaultStartupTaskMatcher taskMatcher("feature");
    auto ret = taskMatcher.Match(task);
    EXPECT_EQ(ret, false);

    DefaultStartupTaskMatcher taskMatcher2("entry");
    ret = taskMatcher2.Match(task);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "DefaultStartupTaskMatcher_0100 end";
}

/**
 * @tc.name: ModuleStartStartupTaskMatcher_0100
 * @tc.type: FUNC
 * @tc.Function: ModuleStartStartupTaskMatcher
 */
HWTEST_F(AppStartupTaskMatcherTest, ModuleStartStartupTaskMatcher_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "ModuleStartStartupTaskMatcher_0100 start";
    PreloadSoStartupTask task("task1", "url", "path");
    task.SetModuleName("entry");

    ModuleStartStartupTaskMatcher matcher("entry");
    auto ret = matcher.Match(task);
    EXPECT_EQ(ret, true);

    ModuleStartStartupTaskMatcher matcher2("feature");
    ret = matcher2.Match(task);
    EXPECT_EQ(ret, false);

    task.SetModuleType(AppExecFwk::ModuleType::SHARED);
    ret = matcher2.Match(task);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ModuleStartStartupTaskMatcher_0100 end";
}

/**
 * @tc.name: ExcludeFromAutoStartStartupTaskMatcher_0100
 * @tc.type: FUNC
 * @tc.Function: ExcludeFromAutoStartStartupTaskMatcher
 */
HWTEST_F(AppStartupTaskMatcherTest, ExcludeFromAutoStartStartupTaskMatcher_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "ExcludeFromAutoStartStartupTaskMatcher_0100 start";
    PreloadSoStartupTask task("task1", "url", "path");
    task.SetIsExcludeFromAutoStart(true);

    ExcludeFromAutoStartStartupTaskMatcher matcher;
    auto ret = matcher.Match(task);
    EXPECT_EQ(ret, false);

    task.SetIsExcludeFromAutoStart(false);
    ret = matcher.Match(task);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ModuleStartStartupTaskMatcher_0100 end";
}

/**
 * @tc.name: UriStartupTaskMatcher_0100
 * @tc.type: FUNC
 * @tc.Function: UriStartupTaskMatcher
 */
HWTEST_F(AppStartupTaskMatcherTest, UriStartupTaskMatcher_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "UriStartupTaskMatcher_0100 start";
    PreloadSoStartupTask task("task1", "url", "path");
    StartupTaskMatchRules matchRules;
    matchRules.uris.emplace_back("scheme://host/path");
    task.SetMatchRules(matchRules);

    auto want = std::make_shared<AAFwk::Want>();
    UriStartupTaskMatcher matcher(want);
    auto ret = matcher.Match(task);
    EXPECT_EQ(ret, false);

    auto want2 = std::make_shared<AAFwk::Want>();
    Uri uri2("");
    want2->SetUri(uri2);
    UriStartupTaskMatcher matcher2(want);
    ret = matcher2.Match(task);
    EXPECT_EQ(ret, false);

    auto want3 = std::make_shared<AAFwk::Want>();
    Uri uri3("scheme://host/path");
    want3->SetUri(uri3);
    UriStartupTaskMatcher matcher3(want3);
    ret = matcher3.Match(task);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "UriStartupTaskMatcher_0100 end";
}

/**
 * @tc.name: InsightIntentStartupTaskMatcher_0100
 * @tc.type: FUNC
 * @tc.Function: InsightIntentStartupTaskMatcher
 */
HWTEST_F(AppStartupTaskMatcherTest, InsightIntentStartupTaskMatcher_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "InsightIntentStartupTaskMatcher_0100 start";
    PreloadSoStartupTask task("task1", "url", "path");
    StartupTaskMatchRules matchRules;
    matchRules.insightIntents.emplace_back("intentName1");
    task.SetMatchRules(matchRules);

    std::shared_ptr<AAFwk::Want> want = nullptr;
    InsightIntentStartupTaskMatcher matcher(want);
    auto ret = matcher.Match(task);
    EXPECT_EQ(ret, false);

    auto want2 = std::make_shared<AAFwk::Want>();
    InsightIntentStartupTaskMatcher matcher2(want2);
    ret = matcher2.Match(task);
    EXPECT_EQ(ret, false);

    auto want3 = std::make_shared<AAFwk::Want>();
    std::string param("intentName1");
    want3->SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_NAME, param);
    InsightIntentStartupTaskMatcher matcher3(want3);
    ret = matcher3.Match(task);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "InsightIntentStartupTaskMatcher_0100 end";
}

/**
 * @tc.name: ActionStartupTaskMatcher_0100
 * @tc.type: FUNC
 * @tc.Function: ActionStartupTaskMatcher
 */
HWTEST_F(AppStartupTaskMatcherTest, ActionStartupTaskMatcher_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "ActionStartupTaskMatcher_0100 start";
    PreloadSoStartupTask task("task1", "url", "path");
    StartupTaskMatchRules matchRules;
    matchRules.actions.emplace_back("com.example.test.action1");
    task.SetMatchRules(matchRules);

    std::shared_ptr<AAFwk::Want> want = nullptr;
    ActionStartupTaskMatcher matcher(want);
    auto ret = matcher.Match(task);
    EXPECT_EQ(ret, false);

    auto want2 = std::make_shared<AAFwk::Want>();
    want2->SetAction("com.example.test.action1");
    ActionStartupTaskMatcher matcher2(want2);
    ret = matcher2.Match(task);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "ActionStartupTaskMatcher_0100 end";
}

/**
 * @tc.name: CustomizationStartupTaskMatcher_0100
 * @tc.type: FUNC
 * @tc.Function: CustomizationStartupTaskMatcher
 */
HWTEST_F(AppStartupTaskMatcherTest, CustomizationStartupTaskMatcher_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO) << "CustomizationStartupTaskMatcher_0100 start";
    PreloadSoStartupTask task("task1", "url", "path");
    StartupTaskMatchRules matchRules;
    matchRules.customization.emplace_back("custom1");
    task.SetMatchRules(matchRules);

    CustomizationStartupTaskMatcher matcher("");
    auto ret = matcher.Match(task);
    EXPECT_EQ(ret, false);

    CustomizationStartupTaskMatcher matcher2("custom1");
    ret = matcher2.Match(task);
    EXPECT_EQ(ret, true);
    GTEST_LOG_(INFO) << "CustomizationStartupTaskMatcher_0100 end";
}
}
}