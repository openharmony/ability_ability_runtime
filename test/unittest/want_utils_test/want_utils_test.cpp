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
#include "app_mgr_util.h"
#include "want_utils.h"
#include "hilog_tag_wrapper.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class WantUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void WantUtilsTest::SetUpTestCase() {}

void WantUtilsTest::TearDownTestCase() {}

void WantUtilsTest::SetUp() {}

void WantUtilsTest::TearDown() {}

/*
 * Feature: WantUtilsTest
 * Function: ConvertToExplicitWant
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService ConvertToExplicitWant
 */
HWTEST_F(WantUtilsTest, ConvertToExplicitWant_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "WantUtilsTest ConvertToExplicitWant_001 start");
    Want want;
    want.SetUri("a_short_atomic_service_uri");
    auto client = AppDomainVerify::AppDomainVerifyMgrClient::GetInstance();
    EXPECT_NE(client, nullptr);
    AppDomainVerify::AppDomainVerifyMgrClient::convertResultCode_ = 0;
    AppDomainVerify::AppDomainVerifyMgrClient::explicitWant_.SetElementName("short_bundle", "short_ability");
    auto errCode = WantUtils::ConvertToExplicitWant(want);
    auto bundle = want.GetElement().GetBundleName();
    auto ability = want.GetElement().GetAbilityName();
    EXPECT_EQ(errCode, 0);
    EXPECT_EQ(bundle, "short_bundle");
    EXPECT_EQ(ability, "short_ability");
    TAG_LOGI(AAFwkTag::TEST, "WantUtilsTest ConvertToExplicitWant_001 end");
}

/*
 * Feature: WantUtilsTest
 * Function: ConvertToExplicitWant
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService ConvertToExplicitWant
 */
HWTEST_F(WantUtilsTest, ConvertToExplicitWant_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "WantUtilsTest ConvertToExplicitWant_002 start");
    Want want;
    want.SetUri("a_short_atomic_service_uri");
    auto client = AppDomainVerify::AppDomainVerifyMgrClient::GetInstance();
    EXPECT_NE(client, nullptr);
    AppDomainVerify::AppDomainVerifyMgrClient::convertResultCode_ = -1;
    auto errCode = WantUtils::ConvertToExplicitWant(want);
    EXPECT_EQ(errCode, -1);
    TAG_LOGI(AAFwkTag::TEST, "WantUtilsTest ConvertToExplicitWant_002 end");
}

/*
 * Feature: WantUtilsTest
 * Function: ConvertToExplicitWant
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService ConvertToExplicitWant
 */
HWTEST_F(WantUtilsTest, ConvertToExplicitWant_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "WantUtilsTest ConvertToExplicitWant_003 start");
    Want want;
    want.SetUri("a_short_atomic_service_uri");
    auto client = AppDomainVerify::AppDomainVerifyMgrClient::GetInstance();
    EXPECT_NE(client, nullptr);
    AppDomainVerify::AppDomainVerifyMgrClient::convertResultCode_ = ERR_TIMED_OUT;
    auto errCode = WantUtils::ConvertToExplicitWant(want);
    EXPECT_EQ(errCode, ERR_TIMED_OUT);
    TAG_LOGI(AAFwkTag::TEST, "WantUtilsTest ConvertToExplicitWant_003 end");
}

/*
 * Feature: WantUtilsTest
 * Function: IsAtomicServiceUrl
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsAtomicServiceUrl
 */
HWTEST_F(WantUtilsTest, IsAtomicServiceUrl_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "WantUtilsTest IsAtomicServiceUrl_001 start");
    Want want;
    want.SetUri("not_a_short_atomic_service_uri");
    auto client = AppDomainVerify::AppDomainVerifyMgrClient::GetInstance();
    EXPECT_NE(client, nullptr);
    AppDomainVerify::AppDomainVerifyMgrClient::isAtomicServiceUrlFlag_ = false;
    auto result = WantUtils::IsAtomicServiceUrl(want);
    EXPECT_EQ(result, false);
    TAG_LOGI(AAFwkTag::TEST, "WantUtilsTest IsAtomicServiceUrl_001 end");
}

/*
 * Feature: WantUtilsTest
 * Function: IsAtomicServiceUrl
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService IsAtomicServiceUrl
 */
HWTEST_F(WantUtilsTest, IsAtomicServiceUrl_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "WantUtilsTest IsAtomicServiceUrl_002 start");
    Want want;
    want.SetUri("a_short_atomic_service_uri");
    auto client = AppDomainVerify::AppDomainVerifyMgrClient::GetInstance();
    EXPECT_NE(client, nullptr);
    AppDomainVerify::AppDomainVerifyMgrClient::isAtomicServiceUrlFlag_ = true;
    auto result = WantUtils::IsAtomicServiceUrl(want);
    EXPECT_EQ(result, true);
    TAG_LOGI(AAFwkTag::TEST, "WantUtilsTest IsAtomicServiceUrl_002 end");
}

/*
 * Feature: WantUtilsTest
 * Function: GetCallerBundleName
 * SubFunction: NA
 * FunctionPoints: AbilityManagerService GetCallerBundleName
 */
HWTEST_F(WantUtilsTest, GetCallerBundleName_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "WantUtilsTest GetCallerBundleName_001 start");
    std::string callerBundleName;
    auto errCode = WantUtils::GetCallerBundleName(callerBundleName);
    EXPECT_NE(errCode, 0);
    TAG_LOGI(AAFwkTag::TEST, "WantUtilsTest GetCallerBundleName_001 end");
}
} // namespace AAFwk
} // namespace OHOS
