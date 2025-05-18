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
#include "js_insight_intent_utils.h"
#include "js_runtime_lite.h"
#include "js_runtime_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class JsInsightIntentUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

static napi_env env_ = nullptr;

void JsInsightIntentUtilsTest::SetUpTestCase(void)
{
    std::shared_ptr<OHOS::JsEnv::JsEnvironment> jsEnv = nullptr;
    AbilityRuntime::Runtime::Options options;
    auto err = JsRuntimeLite::GetInstance().CreateJsEnv(options, jsEnv);
    env_ = reinterpret_cast<napi_env>(jsEnv->GetNativeEngine());
}

void JsInsightIntentUtilsTest::TearDownTestCase(void)
{}

void JsInsightIntentUtilsTest::SetUp()
{}

void JsInsightIntentUtilsTest::TearDown()
{}

/**
 * @tc.name: CallJsFunctionWithResult_0100
 * @tc.desc: basic function test of CallJsFunctionWithResult and ResolveCbCpp.
 * @tc.type: FUNC
 * @tc.require: issueIC77WI
 */
HWTEST_F(JsInsightIntentUtilsTest, CallJsFunctionWithResult_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "testcase begin");
    ASSERT_NE(env_, nullptr);
    napi_value objValue = nullptr;
    auto status = napi_create_object(env_, &objValue);
    EXPECT_EQ(status, napi_ok);
    EXPECT_NE(objValue, nullptr);

    napi_value callback;
    status = napi_create_function(env_, nullptr, 0, JsInsightIntentUtils::ResolveCbCpp, nullptr, &callback);
    EXPECT_EQ(status, napi_ok);

    status = napi_set_named_property(env_, objValue, "test", callback);
    EXPECT_EQ(status, napi_ok);

    napi_value result = nullptr;
    auto ret = JsInsightIntentUtils::CallJsFunctionWithResult(env_, objValue, "test", 0, nullptr, result);
    EXPECT_EQ(ret, true);
    auto jsRet = JsInsightIntentUtils::GetResultFromJs(env_, result);
    EXPECT_EQ(jsRet, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "testcase end");
}

/**
 * @tc.name: CallJsFunctionWithResult_0200
 * @tc.desc: basic function test of CallJsFunctionWithResult and RejectCbCpp.
 * @tc.type: FUNC
 * @tc.require: issueIC77WI
 */
HWTEST_F(JsInsightIntentUtilsTest, CallJsFunctionWithResult_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "testcase begin");
    ASSERT_NE(env_, nullptr);
    napi_value objValue = nullptr;
    auto status = napi_create_object(env_, &objValue);
    EXPECT_EQ(status, napi_ok);
    EXPECT_NE(objValue, nullptr);

    napi_value callback;
    status = napi_create_function(env_, nullptr, 0, JsInsightIntentUtils::RejectCbCpp, nullptr, &callback);
    EXPECT_EQ(status, napi_ok);

    status = napi_set_named_property(env_, objValue, "test", callback);
    EXPECT_EQ(status, napi_ok);

    napi_value result = nullptr;
    auto ret = JsInsightIntentUtils::CallJsFunctionWithResult(env_, objValue, "test", 0, nullptr, result);
    EXPECT_EQ(ret, true);
    auto jsRet = JsInsightIntentUtils::GetResultFromJs(env_, result);
    EXPECT_EQ(jsRet, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "testcase end");
}

/**
 * @tc.name: ReplyFailed_0100
 * @tc.desc: basic function test of ReplyFailed.
 * @tc.type: FUNC
 * @tc.require: issueIC77WI
 */
HWTEST_F(JsInsightIntentUtilsTest, ReplyFailed_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "testcase begin");
    ASSERT_NE(env_, nullptr);

    auto callback = std::make_unique<InsightIntentExecutorAsyncCallback>();
    callback.reset(InsightIntentExecutorAsyncCallback::Create());
    auto bareCallback = callback.release();
    JsInsightIntentUtils::ReplyFailed(bareCallback);

    TAG_LOGI(AAFwkTag::TEST, "testcase end");
}

/**
 * @tc.name: ReplySucceeded_0100
 * @tc.desc: basic function test of ReplySucceeded.
 * @tc.type: FUNC
 * @tc.require: issueIC77WI
 */
HWTEST_F(JsInsightIntentUtilsTest, ReplySucceeded_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "testcase begin");
    ASSERT_NE(env_, nullptr);

    auto callback = std::make_unique<InsightIntentExecutorAsyncCallback>();
    callback.reset(InsightIntentExecutorAsyncCallback::Create());
    auto resultCpp = std::make_shared<AppExecFwk::InsightIntentExecuteResult>();
    auto bareCallback = callback.release();
    JsInsightIntentUtils::ReplySucceeded(bareCallback, resultCpp);

    TAG_LOGI(AAFwkTag::TEST, "testcase end");
}

/**
 * @tc.name: StringifyObject_0100
 * @tc.desc: basic function test of StringifyObject.
 * @tc.type: FUNC
 * @tc.require: issueIC77WI
 */
HWTEST_F(JsInsightIntentUtilsTest, StringifyObject_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "testcase begin");
    ASSERT_NE(env_, nullptr);

    std::string testVal = "testVal";
    napi_value objValue = CreateJsValue(env_, testVal);
    std::string valStr = JsInsightIntentUtils::StringifyObject(env_, objValue);
    EXPECT_EQ(testVal == valStr, 0);

    TAG_LOGI(AAFwkTag::TEST, "testcase end");
}
} // namespace AbilityRuntime
} // namespace OHOS
