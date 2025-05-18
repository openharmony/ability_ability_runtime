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
#include "hilog_tag_wrapper.h"
#include "insight_intent_executor.h"
#include "js_insight_intent_entry.h"
#include "js_insight_intent_utils.h"
#include "js_runtime.h"
#include "want_params.h"
#include "string_wrapper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class JsInsightIntentEntryTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

static std::unique_ptr<JsRuntime> runtime_;

void JsInsightIntentEntryTest::SetUpTestCase(void)
{
    std::shared_ptr<OHOS::JsEnv::JsEnvironment> jsEnv = nullptr;
    AbilityRuntime::Runtime::Options options;
    runtime_ = JsRuntime::Create(options);
}

void JsInsightIntentEntryTest::TearDownTestCase(void)
{}

void JsInsightIntentEntryTest::SetUp()
{}

void JsInsightIntentEntryTest::TearDown()
{}

/**
 * @tc.name: CreateAndInit_0100
 * @tc.desc: basic function test of Create and Init.
 * @tc.type: FUNC
 * @tc.require: issueIC77WL
 */
HWTEST_F(JsInsightIntentEntryTest, CreateAndInit_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "testcase begin");
    ASSERT_NE(runtime_, nullptr);

    std::shared_ptr<JsInsightIntentEntry> executor = JsInsightIntentEntry::Create(*runtime_);
    ASSERT_NE(executor, nullptr);

    InsightIntentExecutorInfo info;
    auto ret = executor->Init(info);
    EXPECT_EQ(ret, false);
    TAG_LOGI(AAFwkTag::TEST, "testcase end");
}

/**
 * @tc.name: HandleExecuteIntent_0100
 * @tc.desc: basic function test of HandleExecuteIntent.
 * @tc.type: FUNC
 * @tc.require: issueIC77WL
 */
HWTEST_F(JsInsightIntentEntryTest, HandleExecuteIntent_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "testcase begin");
    ASSERT_NE(runtime_, nullptr);

    std::shared_ptr<JsInsightIntentEntry> executor = JsInsightIntentEntry::Create(*runtime_);
    ASSERT_NE(executor, nullptr);

    InsightIntentExecutorInfo info;
    auto ret = executor->Init(info);
    EXPECT_EQ(ret, false);

    auto executeParam = std::make_shared<AppExecFwk::InsightIntentExecuteParam>();
    executeParam->insightIntentParam_ = std::make_shared<AAFwk::WantParams>();
    auto callback = std::make_unique<InsightIntentExecutorAsyncCallback>();
    auto asyncCallback = [](AppExecFwk::InsightIntentExecuteResult result) {
        TAG_LOGD(AAFwkTag::INTENT, "execute insightIntent finished");
    };
    callback->Push(asyncCallback);
    bool isAsync = false;
    ret = executor->HandleExecuteIntent(executeParam, nullptr, std::move(callback), isAsync);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(isAsync, false);
    TAG_LOGI(AAFwkTag::TEST, "testcase end");
}

/**
 * @tc.name: HandleExecuteIntent_0200
 * @tc.desc: basic function test of HandleExecuteIntent.
 * @tc.type: FUNC
 * @tc.require: issueIC77WL
 */
HWTEST_F(JsInsightIntentEntryTest, HandleExecuteIntent_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "testcase begin");
    ASSERT_NE(runtime_, nullptr);

    std::shared_ptr<JsInsightIntentEntry> executor = JsInsightIntentEntry::Create(*runtime_);
    ASSERT_NE(executor, nullptr);

    InsightIntentExecutorInfo info;
    auto ret = executor->Init(info);
    EXPECT_EQ(ret, false);

    auto wantParams = std::make_shared<AAFwk::WantParams>();
    wantParams->SetParam("key1", AAFwk::String::Box("value1"));
    wantParams->SetParam("key2", AAFwk::String::Box("value2"));
    auto executeParam = std::make_shared<AppExecFwk::InsightIntentExecuteParam>();
    executeParam->insightIntentParam_ = wantParams;
    executeParam->insightIntentName_ = "intentName";
    executeParam->srcEntrance_ = "srcEntrance";
    executeParam->executeMode_ = 1;
    auto callback = std::make_unique<InsightIntentExecutorAsyncCallback>();
    auto asyncCallback = [](AppExecFwk::InsightIntentExecuteResult result) {
        TAG_LOGD(AAFwkTag::INTENT, "execute insightIntent finished");
    };
    callback->Push(asyncCallback);
    bool isAsync = false;
    ret = executor->HandleExecuteIntent(executeParam, nullptr, std::move(callback), isAsync);
    EXPECT_EQ(ret, false);
    EXPECT_EQ(isAsync, false);
    TAG_LOGI(AAFwkTag::TEST, "testcase end");
}
} // namespace AbilityRuntime
} // namespace OHOS
