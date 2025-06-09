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
#include "insight_intent_constant.h"
#include "insight_intent_execute_param.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#include "want.h"
#include "want_params_wrapper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
using InsightIntentExecuteParam = AppExecFwk::InsightIntentExecuteParam;

namespace {
const std::string TEST_INSIGHT_INTENT_NANE = "PlayMusic";
}

class InsightIntentExecuteParamSecondTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void InsightIntentExecuteParamSecondTest::SetUpTestCase(void)
{}

void InsightIntentExecuteParamSecondTest::TearDownTestCase(void)
{}

void InsightIntentExecuteParamSecondTest::SetUp()
{}

void InsightIntentExecuteParamSecondTest::TearDown()
{}

/**
 * @tc.name: UpdateInsightIntentCallerInfo_0100
 * @tc.desc: basic function test of get caller info.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteParamSecondTest, UpdateInsightIntentCallerInfo_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    WantParams wantParams;
    wantParams.SetParam("ohos.insightIntent.executeParam.name",
        AAFwk::String::Box("test.bundleName"));
    wantParams.SetParam("ohos.insightIntent.executeParam.id",
        AAFwk::String::Box("1"));
    wantParams.SetParam("ohos.insightIntent.executeParam.mode",
        AAFwk::String::Box("execution"));
    wantParams.SetParam("ohos.insightIntent.executeParam.param",
        AAFwk::String::Box("executionParameter"));
    wantParams.SetParam("ohos.insightIntent.srcEntry",
        AAFwk::String::Box("testEntry"));
    wantParams.SetParam("ohos.insightIntent.executeParam.uris",
        AAFwk::String::Box("testUri"));
    wantParams.SetParam("ohos.insightIntent.executeParam.flags",
        AAFwk::String::Box("testFlags"));
    Want want;
    want.SetElementName("", "test.bundleName", "test.abilityName", "test.entry");
    want.SetParams(wantParams);
    WantParams insightIntentParam;
    InsightIntentExecuteParam info;
    auto ret = info.RemoveInsightIntent(want);
    EXPECT_EQ(ret, true);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}
/**
 * @tc.name: ReadFromParcel_0100
 * @tc.desc: basic function test of ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteParamSecondTest, ReadFromParcel_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Parcel parcel;
    InsightIntentExecuteParam param;
    bool ret = param.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: ReadFromParcel_0200
 * @tc.desc: basic function test of ReadFromParcel
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteParamSecondTest, ReadFromParcel_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Parcel parcel;
    WantParams wantParams;
    wantParams.SetParam("ohos.insightIntent.executeParam.name", AAFwk::String::Box("test.bundleName"));
    wantParams.SetParam("ohos.insightIntent.executeParam.id", AAFwk::String::Box("1"));
    wantParams.SetParam("ohos.insightIntent.executeParam.mode", AAFwk::String::Box("execution"));
    wantParams.SetParam("ohos.insightIntent.executeParam.param", AAFwk::String::Box("executionParameter"));
    wantParams.SetParam("ohos.insightIntent.srcEntry", AAFwk::String::Box("testEntry"));
    wantParams.SetParam("ohos.insightIntent.executeParam.uris", AAFwk::String::Box("testUri"));
    wantParams.SetParam("ohos.insightIntent.executeParam.flags", AAFwk::String::Box("testFlags"));
    parcel.WriteParcelable(&wantParams);
    InsightIntentExecuteParam param;
    bool ret = param.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: Unmarshalling_0100
 * @tc.desc: basic function test of Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteParamSecondTest, Unmarshalling_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Parcel parcel;
    InsightIntentExecuteParam param;
    auto retPtr = param.Unmarshalling(parcel);
    EXPECT_EQ(retPtr, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: Unmarshalling_0200
 * @tc.desc: basic function test of Unmarshalling
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteParamSecondTest, Unmarshalling_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Parcel parcel;
    WantParams wantParams;
    wantParams.SetParam("ohos.insightIntent.executeParam.name", AAFwk::String::Box("test.bundleName"));
    wantParams.SetParam("ohos.insightIntent.executeParam.id", AAFwk::String::Box("1"));
    wantParams.SetParam("ohos.insightIntent.executeParam.mode", AAFwk::String::Box("execution"));
    wantParams.SetParam("ohos.insightIntent.executeParam.param", AAFwk::String::Box("executionParameter"));
    wantParams.SetParam("ohos.insightIntent.srcEntry", AAFwk::String::Box("testEntry"));
    wantParams.SetParam("ohos.insightIntent.executeParam.uris", AAFwk::String::Box("testUri"));
    wantParams.SetParam("ohos.insightIntent.executeParam.flags", AAFwk::String::Box("testFlags"));
    parcel.WriteParcelable(&wantParams);
    InsightIntentExecuteParam param;
    auto retPtr = param.Unmarshalling(parcel);
    EXPECT_NE(retPtr, nullptr);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: IsInsightIntentPage_0100
 * @tc.desc: basic function test of IsInsightIntentPage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteParamSecondTest, IsInsightIntentPage_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Want want;
    InsightIntentExecuteParam param;
    bool ret = param.IsInsightIntentPage(want);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: IsInsightIntentPage_0200
 * @tc.desc: basic function test of IsInsightIntentPage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteParamSecondTest, IsInsightIntentPage_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    WantParams wantParams;
    wantParams.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_NAME, AAFwk::String::Box(TEST_INSIGHT_INTENT_NANE));
    wantParams.SetParam(AppExecFwk::INSIGHT_INTENT_DECORATOR_TYPE,
        AAFwk::Integer::Box(static_cast<int>(AbilityRuntime::InsightIntentType::DECOR_PAGE)));
    Want want;
    want.SetParams(wantParams);
    InsightIntentExecuteParam param;
    bool ret = param.IsInsightIntentPage(want);
    EXPECT_TRUE(ret);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: IsInsightIntentPage_0300
 * @tc.desc: basic function test of IsInsightIntentPage
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteParamSecondTest, IsInsightIntentPage_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    WantParams wantParams;
    wantParams.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_NAME, AAFwk::String::Box(TEST_INSIGHT_INTENT_NANE));
    wantParams.SetParam(AppExecFwk::INSIGHT_INTENT_DECORATOR_TYPE,
        AAFwk::String::Box(std::to_string(static_cast<int>((AbilityRuntime::InsightIntentType::DECOR_NONE)))));
    Want want;
    want.SetParams(wantParams);
    InsightIntentExecuteParam param;
    bool ret = param.IsInsightIntentPage(want);
    EXPECT_FALSE(ret);
    TAG_LOGI(AAFwkTag::TEST, "end.");;
}
} // namespace AAFwk
} // namespace OHOS
