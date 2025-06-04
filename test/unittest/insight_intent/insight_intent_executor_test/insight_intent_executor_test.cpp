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

#include "ability_transaction_callback_info.h"
#define private public
#define protected public
#include "insight_intent_executor.h"
#undef private
#undef protected
#include "mock_runtime.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class MockInsightIntentExecutor : public InsightIntentExecutor {
public:
    MockInsightIntentExecutor() {}
    ~MockInsightIntentExecutor() {}
    bool Init(const InsightIntentExecutorInfo& intentInfo) override
    {
        return InsightIntentExecutor::Init(intentInfo);
    }

    bool HandleExecuteIntent(
        std::shared_ptr<InsightIntentExecuteParam> executeParam,
        const std::shared_ptr<NativeReference>& pageLoader,
        std::unique_ptr<InsightIntentExecutorAsyncCallback> callback,
        bool& isAsync) override
    {
        return false;
    }
};

class InsightIntentExecutorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void InsightIntentExecutorTest::SetUpTestCase(void)
{}

void InsightIntentExecutorTest::TearDownTestCase(void)
{}

void InsightIntentExecutorTest::SetUp()
{}

void InsightIntentExecutorTest::TearDown()
{}

/*
* Feature: JsInsightIntentFunc
* Function: Create
* SubFunction: NA
*/
HWTEST_F(InsightIntentExecutorTest, JsInsightIntentPageCreate_001, TestSize.Level1)
{
    auto runtime = std::make_shared<MockRuntime>();
    auto res = InsightIntentExecutor::Create(*runtime, InsightIntentType::DECOR_NONE);
    EXPECT_NE(res, nullptr);
}

/*
* Feature: JsInsightIntentFunc
* Function: Create
* SubFunction: NA
*/
HWTEST_F(InsightIntentExecutorTest, JsInsightIntentPageCreate_002, TestSize.Level1)
{
    auto runtime = std::make_shared<MockRuntime>();
    auto res = InsightIntentExecutor::Create(*runtime, InsightIntentType::DECOR_ENTRY);
    EXPECT_NE(res, nullptr);
}

/*
* Feature: JsInsightIntentFunc
* Function: Create
* SubFunction: NA
*/
HWTEST_F(InsightIntentExecutorTest, JsInsightIntentPageCreate_003, TestSize.Level1)
{
    auto runtime = std::make_shared<MockRuntime>();
    auto res = InsightIntentExecutor::Create(*runtime, InsightIntentType::DECOR_FUNC);
    EXPECT_NE(res, nullptr);
}

/*
* Feature: JsInsightIntentFunc
* Function: Create
* SubFunction: NA
*/
HWTEST_F(InsightIntentExecutorTest, JsInsightIntentPageCreate_004, TestSize.Level1)
{
    auto runtime = std::make_shared<MockRuntime>();
    auto res = InsightIntentExecutor::Create(*runtime, InsightIntentType::DECOR_PAGE);
    EXPECT_NE(res, nullptr);
}

/*
* Feature: JsInsightIntentFunc
* Function: Create
* SubFunction: NA
*/
HWTEST_F(InsightIntentExecutorTest, JsInsightIntentPageCreate_005, TestSize.Level1)
{
    auto runtime = std::make_shared<MockRuntime>();
    auto res = InsightIntentExecutor::Create(*runtime, InsightIntentType::DECOR_LINK);
    EXPECT_EQ(res, nullptr);
}

/*
* Feature: JsInsightIntentFunc
* Function: Create
* SubFunction: NA
*/
HWTEST_F(InsightIntentExecutorTest, JsInsightIntentPageCreate_006, TestSize.Level1)
{
    auto runtime = std::make_shared<MockRuntime>();
    runtime->SetLanguage(Runtime::Language::CJ);
    auto res = InsightIntentExecutor::Create(*runtime, InsightIntentType::DECOR_LINK);
    EXPECT_EQ(res, nullptr);
}

/*
* Feature: JsInsightIntentFunc
* Function: Init
* SubFunction: NA
*/
HWTEST_F(InsightIntentExecutorTest, JsInsightIntentPageInit_001, TestSize.Level1)
{
    auto insightIntentExecutor = std::make_shared<MockInsightIntentExecutor>();
    InsightIntentExecutorInfo info;
    info.executeParam = std::make_shared<AppExecFwk::InsightIntentExecuteParam>();
    auto res = insightIntentExecutor->Init(info);
    EXPECT_TRUE(res);
}
} // namespace AbilityRuntime
} // namespace OHOS
