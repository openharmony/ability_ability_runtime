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

#include "mock_my_flag.h"
#include "mock_accesstoken_kit.h"

#include "app_utils.h"
#include "array_wrapper.h"
#include "string_wrapper.h"

#include "uri_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
namespace {
const uint32_t TOKEN_ID = 1001;
}
class UriUtilsSecondTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void UriUtilsSecondTest::SetUpTestCase() {}

void UriUtilsSecondTest::TearDownTestCase() {}

void UriUtilsSecondTest::SetUp() {}

void UriUtilsSecondTest::TearDown() {}

/*
 * Feature: UriUtils
 * Function: PublishFileOpenEvent
 * SubFunction: NA
 * FunctionPoints: UriUtils PublishFileOpenEvent
 */
HWTEST_F(UriUtilsSecondTest, PublishFileOpenEvent_001, TestSize.Level1)
{
    Want want;
    WantParams params;
    auto wangUri = want.GetUri();
    std::string uriStr = wangUri.ToString();
    std::string schemeStr = wangUri.GetScheme();
    EXPECT_EQ(uriStr, "");
    EXPECT_EQ(schemeStr, "");
    sptr<AAFwk::IArray> ao = new (std::nothrow) AAFwk::Array(1, AAFwk::g_IID_IString);
    if (ao != nullptr) {
        ao->Set(0, String::Box("file"));
        params.SetParam("ability.params.stream", ao);
    }
    want.SetParams(params);
    want.SetUri("file://data/storage/el2/distributedfiles/test.txt");
    UriUtils::GetInstance().PublishFileOpenEvent(want);
    wangUri = want.GetUri();
    EXPECT_NE(wangUri.ToString(), "");
}

/*
 * Feature: UriUtils
 * Function: PublishFileOpenEvent
 * SubFunction: NA
 * FunctionPoints: UriUtils PublishFileOpenEvent
 */
HWTEST_F(UriUtilsSecondTest, PublishFileOpenEvent_002, TestSize.Level1)
{
    Want want;
    UriUtils::GetInstance().PublishFileOpenEvent(want);
    auto wangUri = want.GetUri();
    EXPECT_EQ(wangUri.ToString(), "");
}

/*
 * Feature: UriUtils
 * Function: IsDmsCall
 * SubFunction: NA
 * FunctionPoints: UriUtils IsDmsCall
 */
HWTEST_F(UriUtilsSecondTest, IsDmsCall_002, TestSize.Level1)
{
    uint32_t fromTokenId = TOKEN_ID;
    MyFlag::flag_ = 1;
    MyFlag::bundleName_ = "";
    bool ret = UriUtils::GetInstance().IsDmsCall(fromTokenId);
    EXPECT_FALSE(ret);
}

/*
 * Feature: UriUtils
 * Function: IsDmsCall
 * SubFunction: NA
 * FunctionPoints: UriUtils IsDmsCall
 */
HWTEST_F(UriUtilsSecondTest, IsDmsCall_003, TestSize.Level1)
{
    uint32_t fromTokenId = TOKEN_ID;
    MyFlag::flag_ = 1;
    MyFlag::bundleName_ = "distributedsched";
    bool ret = UriUtils::GetInstance().IsDmsCall(fromTokenId);
    EXPECT_TRUE(ret);
}

/*
 * Feature: UriUtils
 * Function: IsDmsCall
 * SubFunction: NA
 * FunctionPoints: UriUtils IsDmsCall
 */
HWTEST_F(UriUtilsSecondTest, IsDmsCall_004, TestSize.Level1)
{
    uint32_t fromTokenId = TOKEN_ID;
    MyFlag::flag_ = 1;
    MyFlag::bundleName_ = "distributedschedtest";
    bool ret = UriUtils::GetInstance().IsDmsCall(fromTokenId);
    EXPECT_FALSE(ret);
}

/*
 * Feature: UriUtils
 * Function: IsSandboxApp
 * SubFunction: NA
 * FunctionPoints: UriUtils IsSandboxApp
 */
HWTEST_F(UriUtilsSecondTest, IsSandboxApp_001, TestSize.Level1)
{
    MyFlag::flag_ = 0;
    MyFlag::bundleName_ = "";
    uint32_t tokenId = 0;
    bool ret = UriUtils::GetInstance().IsSandboxApp(tokenId);
    EXPECT_FALSE(ret);
}

/*
 * Feature: UriUtils
 * Function: IsSandboxApp
 * SubFunction: NA
 * FunctionPoints: UriUtils IsSandboxApp
 */
HWTEST_F(UriUtilsSecondTest, IsSandboxApp_002, TestSize.Level1)
{
    MyFlag::flag_ = 0;
    MyFlag::bundleName_ = "bundleName";
    uint32_t tokenId = 0;
    bool ret = UriUtils::GetInstance().IsSandboxApp(tokenId);
    EXPECT_TRUE(ret);
}
}
}