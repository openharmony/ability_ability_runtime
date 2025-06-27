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
#include "interceptor/crowd_test_interceptor.h"
#undef private
#undef protected

#include "ability_util.h"
#include "start_ability_utils.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AAFwk {
class CrowdTestInterceptorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CrowdTestInterceptorTest::SetUpTestCase()
{}

void CrowdTestInterceptorTest::TearDownTestCase()
{}

void CrowdTestInterceptorTest::SetUp()
{}

void CrowdTestInterceptorTest::TearDown()
{}

/**
 * @tc.name: CrowdTestInterceptorTest_CheckCrowdtest_001
 * @tc.desc: CheckCrowdtest
 * @tc.type: FUNC
 * @tc.require: CheckCrowdtest
 */
HWTEST_F(CrowdTestInterceptorTest, CheckCrowdtest_001, TestSize.Level1)
{
    CrowdTestInterceptor crowdTestInterceptor;
    Want want;
    int32_t userId = 1001;
    StartAbilityUtils::retGetApplicationInfo = false;
    auto ret = crowdTestInterceptor.CheckCrowdtest(want, userId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CrowdTestInterceptorTest_CheckCrowdtest_002
 * @tc.desc: CheckCrowdtest
 * @tc.type: FUNC
 * @tc.require: CheckCrowdtest
 */
HWTEST_F(CrowdTestInterceptorTest, CheckCrowdtest_002, TestSize.Level1)
{
    CrowdTestInterceptor crowdTestInterceptor;
    Want want;
    int32_t userId = 1001;
    StartAbilityUtils::retGetApplicationInfo = true;
    StartAbilityUtils::applicationInfo.crowdtestDeadline = 0;
    auto ret = crowdTestInterceptor.CheckCrowdtest(want, userId);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CrowdTestInterceptorTest_DoProcess_001
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require: DoProcess
 */
HWTEST_F(CrowdTestInterceptorTest, DoProcess_001, TestSize.Level1)
{
    CrowdTestInterceptor crowdTestInterceptor;
    Want want;
    int requestCode = 0;
    int userId = 100;
    auto shouldBlockFunc = []() { return false; };
    AbilityInterceptorParam param(want, requestCode, userId, false, nullptr, shouldBlockFunc);
    StartAbilityUtils::skipCrowTest = true;
    auto ret = crowdTestInterceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: CrowdTestInterceptorTest_DoProcess_002
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require: DoProcess
 */
HWTEST_F(CrowdTestInterceptorTest, DoProcess_002, TestSize.Level1)
{
    CrowdTestInterceptor crowdTestInterceptor;
    Want want;
    int requestCode = 0;
    int userId = 100;
    auto shouldBlockFunc = []() { return false; };
    AbilityInterceptorParam param(want, requestCode, userId, false, nullptr, shouldBlockFunc);

    StartAbilityUtils::skipCrowTest = false;
    StartAbilityUtils::retGetApplicationInfo = false;
    auto ret = crowdTestInterceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: CrowdTestInterceptorTest_DoProcess_003
 * @tc.desc: DoProcess
 * @tc.type: FUNC
 * @tc.require: DoProcess
 */
HWTEST_F(CrowdTestInterceptorTest, DoProcess_003, TestSize.Level1)
{
    CrowdTestInterceptor crowdTestInterceptor;
    Want want;
    int requestCode = 0;
    int userId = 100;
    bool isWithUI = true;
    auto shouldBlockFunc = []() { return false; };
    AbilityInterceptorParam param(want, requestCode, userId, isWithUI, nullptr, shouldBlockFunc);

    StartAbilityUtils::skipCrowTest = false;
    StartAbilityUtils::retGetApplicationInfo = true;
    StartAbilityUtils::applicationInfo.crowdtestDeadline = 1;

    AbilityUtil::retStartAppgallery = ERR_OK;
    auto ret = crowdTestInterceptor.DoProcess(param);
    EXPECT_EQ(ret, ERR_OK);
}
} // namespace AAFwk
} // namespace OHOS
