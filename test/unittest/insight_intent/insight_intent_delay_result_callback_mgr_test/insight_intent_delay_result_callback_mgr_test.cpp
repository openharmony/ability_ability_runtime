/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define private public
#define protected public
#include "insight_intent_delay_result_callback_mgr.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {

class InsightIntentDelayResultCallbackMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void InsightIntentDelayResultCallbackMgrTest::SetUpTestCase(void)
{}

void InsightIntentDelayResultCallbackMgrTest::TearDownTestCase(void)
{}

void InsightIntentDelayResultCallbackMgrTest::SetUp()
{}

void InsightIntentDelayResultCallbackMgrTest::TearDown()
{}

/**
 * @tc.name: AddDelayResultCallback_0100
 * @tc.desc: basic function test of InsightIntentDelayResultCallbackMgr.
 * @tc.type: FUNC
 * @tc.require: issueI8ZRAG
 */
HWTEST_F(InsightIntentDelayResultCallbackMgrTest, AddDelayResultCallback_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    auto intentId = 1;
    auto delayResultCallback = [] (AppExecFwk::InsightIntentExecuteResult result) -> int32_t {
        if (result.isNeedDelayResult) {
            return 0;
        } else {
            return -1;
        }
    };
    std::shared_ptr<InsightIntentDelayResultCallbackMgr> manager =
        std::make_shared<InsightIntentDelayResultCallbackMgr>();
    EXPECT_EQ(manager->delayResultCallbackMap_.size(), 0);
    manager->AddDelayResultCallback(intentId, {delayResultCallback, false});
    EXPECT_EQ(manager->delayResultCallbackMap_.size(), 1);
    manager->RemoveDelayResultCallback(intentId);
    EXPECT_EQ(manager->delayResultCallbackMap_.size(), 0);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}

/**
 * @tc.name: HandleExecuteDone_0100
 * @tc.desc: basic function test of InsightIntentDelayResultCallbackMgr.
 * @tc.type: FUNC
 * @tc.require: issueI8ZRAG
 */
HWTEST_F(InsightIntentDelayResultCallbackMgrTest, HandleExecuteDone_0100, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "begin.");
    auto intentId = 1;
    auto delayResultCallback = [] (AppExecFwk::InsightIntentExecuteResult result) -> int32_t {
        if (result.isNeedDelayResult) {
            return 0;
        } else {
            return -1;
        }
    };
    std::shared_ptr<InsightIntentDelayResultCallbackMgr> manager =
        std::make_shared<InsightIntentDelayResultCallbackMgr>();
    EXPECT_EQ(manager->delayResultCallbackMap_.size(), 0);
    manager->AddDelayResultCallback(intentId, {delayResultCallback, false});
    EXPECT_EQ(manager->delayResultCallbackMap_.size(), 1);
    auto resultCpp = std::make_shared<AppExecFwk::InsightIntentExecuteResult>();
    resultCpp->isNeedDelayResult = true;
    EXPECT_EQ(manager->HandleExecuteDone(intentId, *resultCpp), 0);
    EXPECT_EQ(manager->delayResultCallbackMap_.size(), 0);
    manager->AddDelayResultCallback(intentId, {delayResultCallback, false});
    resultCpp->isNeedDelayResult = false;
    EXPECT_EQ(manager->HandleExecuteDone(intentId, *resultCpp), -1);
    TAG_LOGI(AAFwkTag::TEST, "end.");
}
} // namespace AbilityRuntime
} // namespace OHOS
