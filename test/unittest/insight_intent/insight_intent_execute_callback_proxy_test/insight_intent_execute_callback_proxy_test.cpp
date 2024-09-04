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

#define private public
#include "ability_record.h"
#include "ability_manager_service.h"
#include "hilog_tag_wrapper.h"
#include "insight_intent_execute_callback_interface.h"
#include "insight_intent_execute_callback_proxy.h"
#include "insight_intent_execute_manager.h"
#include "iremote_proxy.h"
#include "want.h"
#undef private

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace AAFwk {
class InsightIntentExecuteCallbackProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    sptr<Token> MockToken();
};

void InsightIntentExecuteCallbackProxyTest::SetUpTestCase(void)
{}

void InsightIntentExecuteCallbackProxyTest::TearDownTestCase(void)
{}

void InsightIntentExecuteCallbackProxyTest::SetUp()
{}

sptr<Token> InsightIntentExecuteCallbackProxyTest::MockToken()
{
    sptr<Token> token = nullptr;
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.test.demo";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::PAGE;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    if (!abilityRecord) {
        return nullptr;
    }
    return abilityRecord->GetToken();
}

void InsightIntentExecuteCallbackProxyTest::TearDown()
{}

/**
 * @tc.number: DumpFfrtHelperTest_001
 * @tc.name: DumpFfrt
 * @tc.desc: Test whether GetBundleName is called normally.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(InsightIntentExecuteCallbackProxyTest, OnExecuteDone_001, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl;
    auto info = std::make_shared<InsightIntentExecuteCallbackProxy>(impl);
    uint64_t key = 0;
    int32_t resultCode = 0;
    AppExecFwk::InsightIntentExecuteResult executeResult;
    info->OnExecuteDone(key, resultCode, executeResult);
    EXPECT_EQ(impl, nullptr);
}

/**
 * @tc.number: DumpFfrtHelperTest_001
 * @tc.name: DumpFfrt
 * @tc.desc: Test whether GetBundleName is called normally.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(InsightIntentExecuteCallbackProxyTest, OnExecuteDone_002, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl = MockToken();
    auto info = std::make_shared<InsightIntentExecuteCallbackProxy>(impl);
    uint64_t key = 0;
    int32_t resultCode = 0;
    AppExecFwk::InsightIntentExecuteResult executeResult;
    info->OnExecuteDone(key, resultCode, executeResult);
    EXPECT_NE(impl, nullptr);
}

/**
 * @tc.number: DumpFfrtHelperTest_001
 * @tc.name: DumpFfrt
 * @tc.desc: Test whether GetBundleName is called normally.
 * @tc.type: FUNC
 * @tc.require: SR000GH1HL
 */
HWTEST_F(InsightIntentExecuteCallbackProxyTest, OnExecuteDone_003, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> impl = MockToken();
    auto info = std::make_shared<InsightIntentExecuteCallbackProxy>(impl);
    uint64_t key = 1;
    int32_t resultCode = 1;
    AppExecFwk::InsightIntentExecuteResult executeResult;
    info->OnExecuteDone(key, resultCode, executeResult);
    EXPECT_NE(impl, nullptr);
}
}
}
