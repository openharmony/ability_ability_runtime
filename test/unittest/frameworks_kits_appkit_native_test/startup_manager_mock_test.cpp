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
#include "startup_manager.h"
#include "js_startup_task.h"
#include "js_insight_intent_executor.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace AppExecFwk {
class StartupManagerMockTest : public testing::Test {
public:
    StartupManagerMockTest() {}
    ~StartupManagerMockTest() {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void StartupManagerMockTest::SetUpTestCase(void) {}
void StartupManagerMockTest::TearDownTestCase(void) {}
void StartupManagerMockTest::SetUp(void) {}
void StartupManagerMockTest::TearDown(void) {}

/**
 * @tc.name: GetStartupConfigString_0200
 * @tc.type: FUNC
 * @tc.Function: GetStartupConfigString
 */
HWTEST_F(StartupManagerMockTest, GetStartupConfigString_0100, Function | MediumTest | Level1)
{
    std::string name = "test_name";
    std::string config = "test_config";
    std::string startupConfig = "$profile:test";
    std::shared_ptr<StartupManager> startupManager = DelayedSingleton<StartupManager>::GetInstance();
    EXPECT_TRUE(startupManager != nullptr);
    ModuleStartupConfigInfo info(name, startupConfig, "", AppExecFwk::ModuleType::UNKNOWN, false);
    int32_t ret = startupManager->GetStartupConfigString(info, config);
    EXPECT_EQ(ret, ERR_STARTUP_CONFIG_PARSE_ERROR);
}

/**
 * @tc.name: PreloadSoStartupTask_0100
 * @tc.type: FUNC
 * @tc.Function: RunTaskInit
 */
HWTEST_F(StartupManagerMockTest, PreloadSoStartupTask_0100, Function | MediumTest | Level1)
{
    std::string name = "test_name";
    std::string ohmUrl = "@normalized:Y&&<bundleName>&<IMPORT_PATH>&<VERSION>";
    std::shared_ptr<PreloadSoStartupTask> startupTask = std::make_shared<PreloadSoStartupTask>(name, ohmUrl);
    auto ret = startupTask->RunTaskInit(nullptr);
    EXPECT_EQ(ret, ERR_STARTUP_INTERNAL_ERROR);
}

/**
 * @tc.name: JsStartupTask_0100
 * @tc.type: FUNC
 * @tc.Function: RunTaskInit
 */
HWTEST_F(StartupManagerMockTest, JsStartupTask_0100, Function | MediumTest | Level1)
{
    std::string name = "test_name";
    JsRuntime jsRuntime;
    std::unique_ptr<NativeReference> startupJsRef = nullptr;
    std::shared_ptr<NativeReference> contextJsRef = nullptr;
    std::shared_ptr<JsStartupTask> startupTask = std::make_shared<JsStartupTask>(
        name, jsRuntime, startupJsRef, contextJsRef);
    startupTask->callCreateOnMainThread_ = false;
    auto ret = startupTask->RunTaskInit(nullptr);
    EXPECT_EQ(ret, ERR_STARTUP_INTERNAL_ERROR);
}

/**
 * @tc.name: js_insight_intent_executor_0100
 * @tc.type: FUNC
 * @tc.Function: RunTaskInit
 */
HWTEST_F(StartupManagerMockTest, js_insight_intent_executor_0100, Function | MediumTest | Level1)
{
    InsightIntentExecutorAsyncCallback* callback = InsightIntentExecutorAsyncCallback::Create();
    JsInsightIntentExecutor::ReplyFailed(callback);
    EXPECT_TRUE(callback != nullptr);
    callback = nullptr;
}
}
}