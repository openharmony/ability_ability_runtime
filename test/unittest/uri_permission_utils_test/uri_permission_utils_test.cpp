/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "ability_manager_errors.h"
#include "event_report.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"
#define private public
#include "uri_permission_utils.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class UriPermissionUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void UriPermissionUtilsTest::SetUpTestCase() {}

void UriPermissionUtilsTest::TearDownTestCase() {}

void UriPermissionUtilsTest::SetUp() {}

void UriPermissionUtilsTest::TearDown() {}

/*
 * Feature: UPMSUtils
 * Function: ConnectManager
 * SubFunction: NA
 * FunctionPoints: UPMSUtils SendSystemAppGrantUriPermissionEvent
 */
HWTEST_F(UriPermissionUtilsTest, Upms_SendSystemAppGrantUriPermissionEvent_001, TestSize.Level1)
{
    std::vector<std::string> uriVec = { "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt" };
    const std::vector<int32_t> resVec = { ERR_OK };
    auto ret = UPMSUtils::SendSystemAppGrantUriPermissionEvent(1001, 1002, uriVec, resVec);
    EXPECT_EQ(ret, false);
}

/*
 * Feature: UPMSUtils
 * Function: SendShareUnPrivilegeUriEvent
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService SendShareUnPrivilegeUriEvent
 */
HWTEST_F(UriPermissionUtilsTest, Upms_SendShareUnPrivilegeUriEvent_001, TestSize.Level1)
{
    auto ret = UPMSUtils::SendShareUnPrivilegeUriEvent(1001, 1002);
    EXPECT_EQ(ret, false);
}

/*
 * Feature: UPMSUtils
 * Function: GetCurrentAccountId
 * SubFunction: NA
 * FunctionPoints: UPMSUtils GetCurrentAccountId
 */
HWTEST_F(UriPermissionUtilsTest, Upms_GetCurrentAccountId_001, TestSize.Level1)
{
    auto testCurrentAccountId = UPMSUtils::GetCurrentAccountId();
    EXPECT_EQ(testCurrentAccountId, 100);
}

/*
 * Feature: UPMSUtils
 * Function: IsFoundationCall
 * SubFunction: NA
 * FunctionPoints: UPMSUtils IsFoundationCall
 */
HWTEST_F(UriPermissionUtilsTest, Upms_IsFoundationCall_001, TestSize.Level1)
{
    auto testIsFoundationCall = UPMSUtils::IsFoundationCall();
    EXPECT_EQ(testIsFoundationCall, false);
}

/*
 * Feature: UPMSUtils
 * Function: IsSAOrSystemAppCall
 * SubFunction: NA
 * FunctionPoints: UPMSUtils IsSAOrSystemAppCall
 */
HWTEST_F(UriPermissionUtilsTest, Upms_IsSAOrSystemAppCall_001, TestSize.Level1)
{
    auto testIsSAOrSystemAppCall = UPMSUtils::IsSAOrSystemAppCall();
    EXPECT_EQ(testIsSAOrSystemAppCall, false);
}

/*
 * Feature: UPMSUtils
 * Function: IsSystemAppCall
 * SubFunction: NA
 * FunctionPoints: UPMSUtils IsSystemAppCall
 */
HWTEST_F(UriPermissionUtilsTest, Upms_IsSystemAppCall_001, TestSize.Level1)
{
    uint32_t tokenId = 1001;
    auto testIsSystemAppCall = UPMSUtils::IsSystemAppCall(tokenId);
    EXPECT_EQ(testIsSystemAppCall, false);
}

/*
 * Feature: UPMSUtils
 * Function: CheckIsSystemAppByBundleName
 * SubFunction: NA
 * FunctionPoints: UPMSUtils CheckIsSystemAppByBundleName
 */
HWTEST_F(UriPermissionUtilsTest, Upms_CheckIsSystemAppByBundleName_001, TestSize.Level1)
{
    std::string bundleName = "";
    auto testIsSystemApp = UPMSUtils::CheckIsSystemAppByBundleName(bundleName);
    EXPECT_EQ(testIsSystemApp, false);
    bundleName = "com.example.test";
    testIsSystemApp = UPMSUtils::CheckIsSystemAppByBundleName(bundleName);
    EXPECT_EQ(testIsSystemApp, false);
}

/*
 * Feature: UPMSUtils
 * Function: CheckIsSystemAppByTokenId
 * SubFunction: NA
 * FunctionPoints: UPMSUtils CheckIsSystemAppByTokenId
 */
HWTEST_F(UriPermissionUtilsTest, Upms_CheckIsSystemAppByTokenId_001, TestSize.Level1)
{
    uint32_t tokenId = 1001;
    auto testIsSystemApp = UPMSUtils::CheckIsSystemAppByTokenId(tokenId);
    EXPECT_EQ(testIsSystemApp, false);
}

/*
 * Feature: UPMSUtils
 * Function: GetBundleNameByTokenId
 * SubFunction: NA
 * FunctionPoints: UPMSUtils GetBundleNameByTokenId
 */
HWTEST_F(UriPermissionUtilsTest, Upms_GetBundleNameByTokenId_001, TestSize.Level1)
{
    uint32_t tokenId = 1001;
    std::string bundleName = "";
    auto testGetBundleNameByTokenIdFlag = UPMSUtils::GetBundleNameByTokenId(tokenId, bundleName);
    EXPECT_EQ (testGetBundleNameByTokenIdFlag, false);
}

/*
 * Feature: UPMSUtils
 * Function: GetTokenIdByBundleName
 * SubFunction: NA
 * FunctionPoints: UPMSUtils GetTokenIdByBundleName
 */
HWTEST_F(UriPermissionUtilsTest, Upms_GetTokenIdByBundleName_001, TestSize.Level1)
{
    std::string bundleName = "com.example.test";
    int32_t appIndex = 10;
    uint32_t tokenId;
    auto testTokenId = UPMSUtils::GetTokenIdByBundleName(bundleName, appIndex, tokenId);
    EXPECT_EQ(testTokenId, 2097183);
}

}  // namespace AAFwk
}  // namespace OHOS