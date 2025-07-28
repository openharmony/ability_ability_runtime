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
#include <memory>

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "hilog_tag_wrapper.h"
#include "mock_accesstoken_kit.h"
#define private public
#include "dataobs_mgr_service.h"
#undef private

using namespace OHOS::Security::AccessToken;
namespace OHOS {
namespace AAFwk {
using namespace testing::ext;
class DataObsMgrServiceThirdTest : public testing::Test {
public:
    DataObsMgrServiceThirdTest() = default;
    virtual ~DataObsMgrServiceThirdTest() = default;

    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};
void DataObsMgrServiceThirdTest::SetUpTestCase(void)
{}
void DataObsMgrServiceThirdTest::TearDownTestCase(void)
{}
void DataObsMgrServiceThirdTest::SetUp()
{}
void DataObsMgrServiceThirdTest::TearDown()
{}

/*
 * Feature: DataObsMgrService
 * Function: GetCallingUserId
 * SubFunction: NA
 * FunctionPoints: DataObsMgrService GetCallingUserId
 * EnvConditions: NA
 */
HWTEST_F(DataObsMgrServiceThirdTest, DataObsMgrServiceThirdTest_GetCallingUserId_001, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DataObsMgrServiceThirdTest_GetCallingUserId_001 start");
    AccessTokenKit::tokenTypeFlag_ = Security::AccessToken::TOKEN_NATIVE;
    auto dataObsMgrServer = DelayedSingleton<DataObsMgrService>::GetInstance();
    int32_t ret = dataObsMgrServer->GetCallingUserId(0);
    EXPECT_EQ(ret, 0);
    TAG_LOGI(AAFwkTag::TEST, "DataObsMgrServiceThirdTest_GetCallingUserId_001 end");
}


/*
 * Feature: DataObsMgrService
 * Function: GetCallingUserId
 * SubFunction: NA
 * FunctionPoints: DataObsMgrService GetCallingUserId
 * EnvConditions: NA
 */
HWTEST_F(DataObsMgrServiceThirdTest, DataObsMgrServiceThirdTest_GetCallingUserId_002, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DataObsMgrServiceThirdTest_GetCallingUserId_002 start");
    AccessTokenKit::tokenTypeFlag_ = Security::AccessToken::TOKEN_SHELL;
    auto dataObsMgrServer = DelayedSingleton<DataObsMgrService>::GetInstance();
    int32_t ret = dataObsMgrServer->GetCallingUserId(0);
    EXPECT_EQ(ret, 0);
    TAG_LOGI(AAFwkTag::TEST, "DataObsMgrServiceThirdTest_GetCallingUserId_002 end");
}

/*
 * Feature: DataObsMgrService
 * Function: GetCallingUserId
 * SubFunction: NA
 * FunctionPoints: DataObsMgrService GetCallingUserId
 * EnvConditions: NA
 */
HWTEST_F(DataObsMgrServiceThirdTest, DataObsMgrServiceThirdTest_GetCallingUserId_003, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DataObsMgrServiceThirdTest_GetCallingUserId_003 start");
    AccessTokenKit::tokenTypeFlag_ = Security::AccessToken::TOKEN_HAP;
    AccessTokenKit::hapTokenInfo_ = -1;
    auto dataObsMgrServer = DelayedSingleton<DataObsMgrService>::GetInstance();
    int32_t ret = dataObsMgrServer->GetCallingUserId(0);
    EXPECT_EQ(ret, -1);
    TAG_LOGI(AAFwkTag::TEST, "DataObsMgrServiceThirdTest_GetCallingUserId_003 end");
}

/*
 * Feature: DataObsMgrService
 * Function: GetCallingUserId
 * SubFunction: NA
 * FunctionPoints: DataObsMgrService GetCallingUserId
 * EnvConditions: NA
 */
HWTEST_F(DataObsMgrServiceThirdTest, DataObsMgrServiceThirdTest_GetCallingUserId_004, TestSize.Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "DataObsMgrServiceThirdTest_GetCallingUserId_004 start");
    AccessTokenKit::tokenTypeFlag_ = Security::AccessToken::TOKEN_HAP;
    AccessTokenKit::hapTokenInfo_ = 0;
    AccessTokenKit::hapTokenUserId_ = 2;
    auto dataObsMgrServer = DelayedSingleton<DataObsMgrService>::GetInstance();
    int32_t ret = dataObsMgrServer->GetCallingUserId(0);
    EXPECT_EQ(ret, 2);
    TAG_LOGI(AAFwkTag::TEST, "DataObsMgrServiceThirdTest_GetCallingUserId_004 end");
}
}  // namespace AAFwk
}  // namespace OHOS