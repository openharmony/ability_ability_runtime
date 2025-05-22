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
#include "napi_common_want_agent.h"
#include "napi/native_api.h"

namespace OHOS {
namespace AppExecFwk {
using namespace testing;
using namespace testing::ext;

class NapiCommonWantAgentTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void NapiCommonWantAgentTest::SetUpTestCase()
{
}

void NapiCommonWantAgentTest::TearDownTestCase()
{
}

void NapiCommonWantAgentTest::SetUp()
{
}

void NapiCommonWantAgentTest::TearDown()
{
}

/**
 * @tc.number: WrapWantAgent_0100
 * @tc.name: WrapWantAgent_0100
 * @tc.desc: WrapWantAgent.
 */
HWTEST_F(NapiCommonWantAgentTest, WrapWantAgent_0100, Function | MediumTest | Level1)
{
    napi_env env = nullptr;
    AbilityRuntime::WantAgent::WantAgent* wantAgent = nullptr;
    napi_finalize finalizeCb = nullptr;
    auto test = OHOS::AppExecFwk::WrapWantAgent(env, wantAgent, finalizeCb);
    EXPECT_EQ(test, nullptr);
}

/**
 * @tc.number: UnwrapWantAgent_0100
 * @tc.name: UnwrapWantAgent_0100
 * @tc.desc: UnwrapWantAgent.
 */
HWTEST_F(NapiCommonWantAgentTest, UnwrapWantAgent_0100, Function | MediumTest | Level1)
{
    napi_env env = nullptr;
    napi_value jsParam = nullptr;
    void **result = nullptr;
    OHOS::AppExecFwk::UnwrapWantAgent(env, jsParam, result);
    EXPECT_EQ(result, nullptr);
}
} // namespace AppExecFwk
} // namespace OHOS

