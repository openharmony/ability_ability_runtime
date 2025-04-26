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
#include "insight_intent_execute_manager.h"
#include "insight_intent_execute_param.h"
#include "mock_ability_token.h"
#include "want.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class InsightIntentExecuteManagerSecondTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void InsightIntentExecuteManagerSecondTest::SetUpTestCase(void)
{}

void InsightIntentExecuteManagerSecondTest::TearDownTestCase(void)
{}

void InsightIntentExecuteManagerSecondTest::SetUp()
{}

void InsightIntentExecuteManagerSecondTest::TearDown()
{}

/**
 * @tc.name: CheckAndUpdateParam_0100
 * @tc.desc: CheckAndUpdateParam_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckAndUpdateParam_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = std::make_shared<WantParams>();
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    sptr<IRemoteObject> callerToken = new AppExecFwk::MockAbilityToken();
    uint64_t key = 1;
    std::string callerBundleName = "com.bundlename.test";
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->CheckAndUpdateParam(
        key, callerToken, paramPtr, callerBundleName);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckAndUpdateParam_0200
 * @tc.desc: CheckAndUpdateParam_0200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckAndUpdateParam_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = std::make_shared<WantParams>();
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    sptr<IRemoteObject> callerToken;
    uint64_t key = 1;
    std::string callerBundleName = "com.bundlename.test";
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->CheckAndUpdateParam(
        key, callerToken, paramPtr, callerBundleName);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckAndUpdateParam_0300
 * @tc.desc: CheckAndUpdateParam_0300
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckAndUpdateParam_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    std::shared_ptr<AppExecFwk::InsightIntentExecuteParam> paramPtr = nullptr;
    sptr<IRemoteObject> callerToken = new AppExecFwk::MockAbilityToken();
    uint64_t key = 1;
    std::string callerBundleName = "com.bundlename.test";
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->CheckAndUpdateParam(
        key, callerToken, paramPtr, callerBundleName);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckAndUpdateParam_0400
 * @tc.desc: CheckAndUpdateParam_0400
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckAndUpdateParam_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    AppExecFwk::InsightIntentExecuteParam param;
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = std::make_shared<WantParams>();
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    sptr<IRemoteObject> callerToken = new AppExecFwk::MockAbilityToken();
    uint64_t key = 1;
    std::string callerBundleName = "com.bundlename.test";
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->CheckAndUpdateParam(
        key, callerToken, paramPtr, callerBundleName);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckAndUpdateWant_0100
 * @tc.desc: CheckAndUpdateWant_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckAndUpdateWant_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Want want;
    auto executeMode = AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND;
    std::string callerBundleName = "test";
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->CheckAndUpdateWant(
        want, executeMode, callerBundleName);
    EXPECT_NE(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckAndUpdateWant_0200
 * @tc.desc: CheckAndUpdateWant_0200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckAndUpdateWant_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Want want;
    want.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("com.example.test"));
    auto executeMode = AppExecFwk::ExecuteMode::UI_ABILITY_FOREGROUND;
    std::string callerBundleName = "test";
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->CheckAndUpdateWant(
        want, executeMode, callerBundleName);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: CheckAndUpdateWant_0300
 * @tc.desc: CheckAndUpdateWant_0300
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, CheckAndUpdateWant_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    Want want;
    want.SetParam(AppExecFwk::INSIGHT_INTENT_EXECUTE_PARAM_NAME, std::string("com.example.test"));
    auto executeMode = AppExecFwk::ExecuteMode::UI_ABILITY_BACKGROUND;
    std::string callerBundleName = "test";
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->CheckAndUpdateWant(
        want, executeMode, callerBundleName);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: ExecuteIntentDone_0100
 * @tc.desc: ExecuteIntentDone_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, ExecuteIntentDone_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    uint64_t intentId = 0;
    int32_t resultCode = 0;
    AppExecFwk::InsightIntentExecuteResult result;
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->ExecuteIntentDone(
        intentId, resultCode, result);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: ExecuteIntentDone_0200
 * @tc.desc: ExecuteIntentDone_0200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, ExecuteIntentDone_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    uint64_t intentId = 0;
    int32_t resultCode = 0;
    AppExecFwk::InsightIntentExecuteResult result;
    std::string bundle = "com.bundle.test";
    AppExecFwk::InsightIntentExecuteParam param;
    param.bundleName_ = "test.bundleName";
    param.moduleName_ = "test.entry";
    param.abilityName_ = "test.abilityName";
    param.insightIntentName_ = "PlayMusic";
    param.insightIntentParam_ = std::make_shared<WantParams>();
    auto paramPtr = std::make_shared<AppExecFwk::InsightIntentExecuteParam>(param);
    sptr<IRemoteObject> callerToken = new AppExecFwk::MockAbilityToken();
    uint64_t key = 1;
    std::string callerBundleName = "com.bundlename.test";
    DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->AddRecord(
        key, callerToken, param.bundleName_, intentId, callerBundleName);
    intentId = 1;
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->ExecuteIntentDone(
        intentId, resultCode, result);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: ExecuteIntentDone_0300
 * @tc.desc: ExecuteIntentDone_0300
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, ExecuteIntentDone_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    uint64_t intentId = 0;
    int32_t resultCode = 0;
    AppExecFwk::InsightIntentExecuteResult result;
    DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->records_[intentId] = nullptr;
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->ExecuteIntentDone(
        intentId, resultCode, result);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: ExecuteIntentDone_0400
 * @tc.desc: ExecuteIntentDone_0400
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, ExecuteIntentDone_0400, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    uint64_t intentId = 0;
    int32_t resultCode = 0;
    AppExecFwk::InsightIntentExecuteResult result;
    auto record = std::make_shared<InsightIntentExecuteRecord>();
    record->state = InsightIntentExecuteState::UNKNOWN;
    DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->records_[intentId] = record;
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->ExecuteIntentDone(
        intentId, resultCode, result);
    EXPECT_EQ(ret, ERR_INVALID_OPERATION);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GetCallerBundleName_0100
 * @tc.desc: GetCallerBundleName_0100
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, GetCallerBundleName_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    uint64_t intentId = 0;
    std::string callerBundleName = "com.bundlename.test";
    DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->records_.clear();
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->GetCallerBundleName(
        intentId, callerBundleName);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GetCallerBundleName_0200
 * @tc.desc: GetCallerBundleName_0200
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, GetCallerBundleName_0200, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    uint64_t intentId = 0;
    std::string callerBundleName = "com.bundlename.test";
    auto record = std::make_shared<InsightIntentExecuteRecord>();
    record->state = InsightIntentExecuteState::UNKNOWN;
    DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->records_[intentId] = record;
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->GetCallerBundleName(
        intentId, callerBundleName);
    EXPECT_EQ(ret, ERR_OK);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: GetCallerBundleName_0300
 * @tc.desc: GetCallerBundleName_0300
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(InsightIntentExecuteManagerSecondTest, GetCallerBundleName_0300, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    uint64_t intentId = 0;
    std::string callerBundleName = "com.bundlename.test";
    DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->records_[intentId] = nullptr;
    auto ret = DelayedSingleton<InsightIntentExecuteManager>::GetInstance()->GetCallerBundleName(
        intentId, callerBundleName);
    EXPECT_EQ(ret, ERR_INVALID_VALUE);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}
} // namespace AAFwk
} // namespace OHOS
