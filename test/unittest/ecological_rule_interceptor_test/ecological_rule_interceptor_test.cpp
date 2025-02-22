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
#include "ecological_rule/ability_ecological_rule_mgr_service_param.h"
#include "interceptor/ecological_rule_interceptor.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using ErmsCallerInfo = OHOS::EcologicalRuleMgrService::AbilityCallerInfo;

namespace OHOS {
namespace AAFwk {
class EcologicalRuleInterceptorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void EcologicalRuleInterceptorTest::SetUpTestCase()
{}

void EcologicalRuleInterceptorTest::TearDownTestCase()
{}

void EcologicalRuleInterceptorTest::SetUp()
{}

void EcologicalRuleInterceptorTest::TearDown()
{}

/**
 * @tc.name: EcologicalRuleInterceptorTest_GetAppTypeByBundleType_001
 * @tc.desc: GetAppTypeByBundleType
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, EcologicalRuleInterceptorTest_GetAppTypeByBundleType_001, TestSize.Level1)
{
    int32_t bundleType = static_cast<int32_t>(AppExecFwk::BundleType::ATOMIC_SERVICE);
    auto result = EcologicalRuleInterceptor::GetAppTypeByBundleType(bundleType);
    EXPECT_EQ(result, ErmsCallerInfo::TYPE_ATOM_SERVICE);
}

/**
 * @tc.name: EcologicalRuleInterceptorTest_GetAppTypeByBundleType_002
 * @tc.desc: GetAppTypeByBundleType
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, EcologicalRuleInterceptorTest_GetAppTypeByBundleType_002, TestSize.Level1)
{
    int32_t bundleType = static_cast<int32_t>(AppExecFwk::BundleType::APP);
    auto result = EcologicalRuleInterceptor::GetAppTypeByBundleType(bundleType);
    EXPECT_EQ(result, ErmsCallerInfo::TYPE_HARMONY_APP);
}

/**
 * @tc.name: EcologicalRuleInterceptorTest_GetAppTypeByBundleType_003
 * @tc.desc: GetAppTypeByBundleType
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, EcologicalRuleInterceptorTest_GetAppTypeByBundleType_003, TestSize.Level1)
{
    int32_t bundleType = static_cast<int32_t>(AppExecFwk::BundleType::APP_SERVICE_FWK);
    auto result = EcologicalRuleInterceptor::GetAppTypeByBundleType(bundleType);
    EXPECT_EQ(result, ErmsCallerInfo::TYPE_APP_SERVICE);
}

/**
 * @tc.name: EcologicalRuleInterceptorTest_GetAppTypeByBundleType_004
 * @tc.desc: GetAppTypeByBundleType
 * @tc.type: FUNC
 * @tc.require: No
 */
HWTEST_F(EcologicalRuleInterceptorTest, EcologicalRuleInterceptorTest_GetAppTypeByBundleType_004, TestSize.Level1)
{
    int32_t bundleType = static_cast<int32_t>(-1);
    auto result = EcologicalRuleInterceptor::GetAppTypeByBundleType(bundleType);
    EXPECT_EQ(result, ErmsCallerInfo::TYPE_INVALID);
}

} // namespace AAFwk
} // namespace OHOS
