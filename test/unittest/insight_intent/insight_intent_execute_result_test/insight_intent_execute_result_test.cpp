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
#include "hilog_tag_wrapper.h"
#include "insight_intent_execute_result.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
using InsightIntentExecuteResult = AppExecFwk::InsightIntentExecuteResult;

namespace {
} // namespace

class InsightIntentExecuteResultTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void InsightIntentExecuteResultTest::SetUpTestCase(void)
{}

void InsightIntentExecuteResultTest::TearDownTestCase(void)
{}

void InsightIntentExecuteResultTest::SetUp()
{}

void InsightIntentExecuteResultTest::TearDown()
{}

/**
 * @tc.name: ReadFromParcel_0100
 * @tc.desc: basic function test of get caller info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteResultTest, ReadFromParcel_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    InsightIntentExecuteResult testclass;
    Parcel parcel;
    auto ret = testclass.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: Marshalling_0100
 * @tc.desc: basic function test of get caller info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteResultTest, Marshalling_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    InsightIntentExecuteResult testclass;
    Parcel parcel;
    auto ret = testclass.Marshalling(parcel);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: Unmarshalling_0100
 * @tc.desc: basic function test of get caller info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteResultTest, Unmarshalling_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Parcel parcel;
    auto ret = InsightIntentExecuteResult::Unmarshalling(parcel);
    EXPECT_TRUE(ret != nullptr);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckResult_0100
 * @tc.desc: basic function test of get caller info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteResultTest, CheckResult_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    std::shared_ptr<const WantParams> result;
    auto ret = InsightIntentExecuteResult::CheckResult(result);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

} // namespace AAFwk
} // namespace OHOS
