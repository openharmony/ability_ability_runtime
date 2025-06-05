/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "mock_media_permission_manager.h"
#include "mock_ability_manager_client.h"
#include "mock_accesstoken_kit.h"
#include "mock_app_mgr_service.h"
#include "mock_app_utils.h"
#include "mock_bundle_mgr_helper.h"
#include "mock_ipc_skeleton.h"
#include "mock_my_flag.h"
#include "mock_native_token.h"
#include "mock_permission_verification.h"
#include "mock_system_ability_manager_client.h"

#include "ability_manager_errors.h"
#include "event_report.h"
#include "system_ability_definition.h"
#include "tokenid_kit.h"
#define private public
#include "uri_permission_manager_client.h"
#include "uri_permission_manager_stub_impl.h"
#include "uri_permission_utils.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class UriPermissionImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void UriPermissionImplTest::SetUpTestCase()
{
    AppExecFwk::MockNativeToken::SetNativeToken();
}

void UriPermissionImplTest::TearDownTestCase() {}

void UriPermissionImplTest::SetUp() {
    AbilityManagerClient::collaborator_ = nullptr;
    AbilityManagerClient::isNullInstance = false;
    AppUtils::Init();
    MyFlag::Init();
}

void UriPermissionImplTest::TearDown() {}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_001, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    Uri uri(uriStr);
    unsigned int flag = 0;
    std::string targetBundleName = "name2";
    int32_t funcResult = -1;
    upms->GrantUriPermission(uri, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_002, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    Uri uri(uriStr);
    unsigned int flag = 1;
    std::string targetBundleName = "name2";
    int32_t funcResult = -1;
    upms->GrantUriPermission(uri, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_003, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    Uri uri(uriStr);
    unsigned int flag = 2;
    MockSystemAbilityManager::isNullptr = false;
    std::string targetBundleName = "name2";
    int32_t funcResult = -1;
    upms->GrantUriPermission(uri, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
    MockSystemAbilityManager::isNullptr = true;
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_004, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    Uri uri(uriStr);
    unsigned int flag = 2;
    std::string targetBundleName = "name2";
    MockSystemAbilityManager::isNullptr = false;
    StorageManager::StorageManagerServiceMock::isZero = false;
    int32_t funcResult = -1;
    upms->GrantUriPermission(uri, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
    MockSystemAbilityManager::isNullptr = true;
    StorageManager::StorageManagerServiceMock::isZero = true;
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_005, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    unsigned int tmpFlag = 1;
    uint32_t fromTokenId = 2;
    uint32_t targetTokenId = 3;
    std::string targetBundleName = "name2";
    GrantInfo info = { tmpFlag, fromTokenId, targetTokenId };
    std::list<GrantInfo> infoList = { info };
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    upms->uriMap_.emplace(uriStr, infoList);
    Uri uri(uriStr);
    MockSystemAbilityManager::isNullptr = false;
    int32_t funcResult = -1;
    upms->GrantUriPermission(uri, tmpFlag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
    MockSystemAbilityManager::isNullptr = true;
}

/*
 * Feature: GrantUriPermission
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_006, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    unsigned int tmpFlag = 1;
    uint32_t fromTokenId = 2;
    uint32_t targetTokenId = 3;
    std::string targetBundleName = "name2";
    GrantInfo info = { tmpFlag, fromTokenId, targetTokenId };
    std::list<GrantInfo> infoList = { info };
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    upms->uriMap_.emplace(uriStr, infoList);
    Uri uri(uriStr);
    MockSystemAbilityManager::isNullptr = false;
    unsigned int flag = 2;
    int32_t funcResult = -1;
    upms->GrantUriPermission(uri, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
    MockSystemAbilityManager::isNullptr = true;
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_007, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    unsigned int tmpFlag = 1;
    uint32_t fromTokenId = 2;
    uint32_t targetTokenId = 3;
    std::string targetBundleName = "name2";
    GrantInfo info = { tmpFlag, fromTokenId, targetTokenId };
    std::list<GrantInfo> infoList = { info };
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    upms->uriMap_.emplace(uriStr, infoList);
    Uri uri(uriStr);
    MockSystemAbilityManager::isNullptr = false;
    unsigned int flag = 2;
    int32_t funcResult = -1;
    upms->GrantUriPermission(uri, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
    MockSystemAbilityManager::isNullptr = true;
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_008, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ &= (~MyFlag::IS_SA_CALL);
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    Uri uri(uriStr);
    uint32_t flag = 1;
    std::string targetBundleName = "name1001";
    int32_t funcResult = -1;
    upms->GrantUriPermission(uri, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_009, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    std::vector<std::string> uriStrVec = { uriStr };

    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uriStrVec, rawData);
    UriPermissionRawData stubRawData;
    stubRawData.size = rawData.size;
    EXPECT_EQ(stubRawData.RawDataCpy(rawData.data), ERR_NONE);

    unsigned int flag = 0;
    std::string targetBundleName = "name2";
    int32_t funcResult = -1;
    upms->GrantUriPermission(stubRawData, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_010, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    std::vector<std::string> uriStrVec = { uriStr };

    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uriStrVec, rawData);
    UriPermissionRawData stubRawData;
    stubRawData.size = rawData.size;
    EXPECT_EQ(stubRawData.RawDataCpy(rawData.data), ERR_NONE);

    unsigned int flag = 1;
    std::string targetBundleName = "name2";
    int32_t funcResult = -1;
    upms->GrantUriPermission(stubRawData, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_011, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    std::vector<std::string> uriStrVec = { uriStr };

    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uriStrVec, rawData);
    UriPermissionRawData stubRawData;
    stubRawData.size = rawData.size;
    EXPECT_EQ(stubRawData.RawDataCpy(rawData.data), ERR_NONE);

    unsigned int flag = 2;
    MockSystemAbilityManager::isNullptr = false;
    std::string targetBundleName = "name2";
    int32_t funcResult = -1;
    upms->GrantUriPermission(stubRawData, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
    MockSystemAbilityManager::isNullptr = true;
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_012, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    std::vector<std::string> uriStrVec = { uriStr };

    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uriStrVec, rawData);
    UriPermissionRawData stubRawData;
    stubRawData.size = rawData.size;
    EXPECT_EQ(stubRawData.RawDataCpy(rawData.data), ERR_NONE);

    unsigned int flag = 2;
    std::string targetBundleName = "name2";
    MockSystemAbilityManager::isNullptr = false;
    StorageManager::StorageManagerServiceMock::isZero = false;
    int32_t funcResult = -1;
    upms->GrantUriPermission(stubRawData, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
    MockSystemAbilityManager::isNullptr = true;
    StorageManager::StorageManagerServiceMock::isZero = true;
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_013, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    unsigned int tmpFlag = 1;
    uint32_t fromTokenId = 2;
    uint32_t targetTokenId = 3;
    std::string targetBundleName = "name2";
    GrantInfo info = { tmpFlag, fromTokenId, targetTokenId };
    std::list<GrantInfo> infoList = { info };
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    upms->uriMap_.emplace(uriStr, infoList);
    std::vector<std::string> uriStrVec = { uriStr };

    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uriStrVec, rawData);
    UriPermissionRawData stubRawData;
    stubRawData.size = rawData.size;
    EXPECT_EQ(stubRawData.RawDataCpy(rawData.data), ERR_NONE);

    MockSystemAbilityManager::isNullptr = false;
    int32_t funcResult = -1;
    upms->GrantUriPermission(stubRawData, tmpFlag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
    MockSystemAbilityManager::isNullptr = true;
}

/*
 * Feature: GrantUriPermission
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_014, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    unsigned int tmpFlag = 1;
    uint32_t fromTokenId = 2;
    uint32_t targetTokenId = 3;
    std::string targetBundleName = "name2";
    GrantInfo info = { tmpFlag, fromTokenId, targetTokenId };
    std::list<GrantInfo> infoList = { info };
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    upms->uriMap_.emplace(uriStr, infoList);
    std::vector<std::string> uriStrVec = { uriStr };

    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uriStrVec, rawData);
    UriPermissionRawData stubRawData;
    stubRawData.size = rawData.size;
    EXPECT_EQ(stubRawData.RawDataCpy(rawData.data), ERR_NONE);

    MockSystemAbilityManager::isNullptr = false;
    unsigned int flag = 2;
    int32_t funcResult = -1;
    upms->GrantUriPermission(stubRawData, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
    MockSystemAbilityManager::isNullptr = true;
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_015, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    unsigned int tmpFlag = 1;
    uint32_t fromTokenId = 2;
    uint32_t targetTokenId = 3;
    std::string targetBundleName = "name2";
    GrantInfo info = { tmpFlag, fromTokenId, targetTokenId };
    std::list<GrantInfo> infoList = { info };
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    upms->uriMap_.emplace(uriStr, infoList);
    std::vector<std::string> uriStrVec = { uriStr };

    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uriStrVec, rawData);
    UriPermissionRawData stubRawData;
    stubRawData.size = rawData.size;
    EXPECT_EQ(stubRawData.RawDataCpy(rawData.data), ERR_NONE);

    MockSystemAbilityManager::isNullptr = false;
    unsigned int flag = 2;
    int32_t funcResult = -1;
    upms->GrantUriPermission(stubRawData, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
    MockSystemAbilityManager::isNullptr = true;
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_016, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    MyFlag::flag_ &= (~MyFlag::IS_SA_CALL);
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    std::vector<std::string> uriStrVec = { uriStr };

    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uriStrVec, rawData);
    UriPermissionRawData stubRawData;
    stubRawData.size = rawData.size;
    EXPECT_EQ(stubRawData.RawDataCpy(rawData.data), ERR_NONE);

    uint32_t flag = 1;
    std::string targetBundleName = "name1001";
    int32_t funcResult = -1;
    upms->GrantUriPermission(stubRawData, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_017, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    MyFlag::flag_ &= (~MyFlag::IS_SA_CALL);
    auto uriStr = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    std::vector<std::string> uriStrVec(200000 + 1, uriStr);

    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uriStrVec, rawData);
    UriPermissionRawData stubRawData;
    stubRawData.size = rawData.size;
    EXPECT_EQ(stubRawData.RawDataCpy(rawData.data), ERR_NONE);

    uint32_t flag = 1;
    std::string targetBundleName = "name1001";
    int32_t funcResult = -1;
    upms->GrantUriPermission(stubRawData, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, ERR_URI_LIST_OUT_OF_RANGE);
}

/*
 * Feature: URIPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_GrantUriPermission_018, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    MyFlag::flag_ &= (~MyFlag::IS_SA_CALL);
    std::vector<std::string> uriStrVec;

    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uriStrVec, rawData);
    UriPermissionRawData stubRawData;
    stubRawData.size = rawData.size;
    EXPECT_EQ(stubRawData.RawDataCpy(rawData.data), ERR_NONE);

    uint32_t flag = 1;
    std::string targetBundleName = "name1001";
    int32_t funcResult = -1;
    upms->GrantUriPermission(stubRawData, flag, targetBundleName, 0, 0, funcResult);
    EXPECT_EQ(funcResult, ERR_URI_LIST_OUT_OF_RANGE);
}

/*
 * Feature: URIPermissionManagerService
 * Function: RevokeUriPermissionManually
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService RevokeUriPermissionManually
 */
HWTEST_F(UriPermissionImplTest, Upms_RevokeUriPermissionManually_001, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    uint32_t flagRead = 1;
    uint32_t fromTokenId = 1001;
    uint32_t targetTokenId = 1002;
    int32_t appIndex = 0;
    std::string targetBundleName = "com.example.testB1002";
    GrantInfo info = { flagRead, fromTokenId, targetTokenId };
    std::list<GrantInfo> infoList = { info };
    auto uriStr = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_A.txt";
    auto uri = Uri(uriStr);
    upms->uriMap_.emplace(uriStr, infoList);
    IPCSkeleton::callerTokenId = fromTokenId;
    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_HAP, "", "com.example.app1001");
    int32_t funcResult1 = -1;
    bool funcResult2 = false;
    MyFlag::isUriTypeValid_ = true;
    MyFlag::getTokenIdByBundleNameStatus_ = 0;
    MyFlag::upmsUtilsTokenId_ = 1002;
    upms->RevokeUriPermissionManually(uri, targetBundleName, appIndex, funcResult1);
    upms->VerifyUriPermission(uri, flagRead, targetTokenId, funcResult2);
    ASSERT_EQ(funcResult2, false);
}

/*
 * Feature: URIPermissionManagerService
 * Function: RevokeUriPermissionManually
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService RevokeUriPermissionManually
 */
HWTEST_F(UriPermissionImplTest, Upms_RevokeUriPermissionManually_002, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    uint32_t flagRead = 1;
    uint32_t fromTokenId = 1001;
    uint32_t targetTokenId = 1002;
    // sandbox application appIndex
    int32_t appIndex = 1001;
    std::string targetBundleName = "com.example.testB1003";
    GrantInfo info = { flagRead, fromTokenId, targetTokenId };
    std::list<GrantInfo> infoList = { info };
    auto uriStr = "file://com.example.testA/data/storage/el2/base/haps/entry/files/test_A.txt";
    auto uri = Uri(uriStr);
    upms->uriMap_.emplace(uriStr, infoList);
    int32_t funcResult1 = -1;
    bool funcResult2 = false;
    upms->RevokeUriPermissionManually(uri, targetBundleName, appIndex, funcResult1);
    upms->VerifyUriPermission(uri, flagRead, targetTokenId, funcResult2);
    ASSERT_EQ(funcResult2, true);
}

/*
 * Feature: URIPermissionManagerService
 * Function: RevokeUriPermissionManually
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService RevokeUriPermissionManually
 */
HWTEST_F(UriPermissionImplTest, Upms_RevokeUriPermissionManually_003, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    uint32_t flagRead = 1;
    uint32_t fromTokenId = 1001;
    uint32_t targetTokenId = 1002;
    // clone application appIndex
    int32_t appIndex = 1;
    std::string targetBundleName = "com.example.testB1003";
    GrantInfo info = { flagRead, fromTokenId, targetTokenId };
    std::list<GrantInfo> infoList = { info };
    auto uriStr = "file://com.example.testA/data/storage/el2/base/haps/entry/files/test_A.txt";
    auto uri = Uri(uriStr);
    upms->uriMap_.emplace(uriStr, infoList);
    int32_t funcResult1 = -1;
    bool funcResult2 = false;
    upms->RevokeUriPermissionManually(uri, targetBundleName, appIndex, funcResult1);
    upms->VerifyUriPermission(uri, flagRead, targetTokenId, funcResult2);
    ASSERT_EQ(funcResult2, true);
}

/*
 * Feature: URIPermissionManagerService
 * Function: ConnectManager
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService ConnectManager
 */
HWTEST_F(UriPermissionImplTest, Upms_ConnectManager_001, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    SystemAbilityManagerClient::nullptrFlag = true;
    sptr<StorageManager::IStorageManager> storageManager = nullptr;
    upms->ConnectManager(storageManager, -1);
    SystemAbilityManagerClient::nullptrFlag = false;
    ASSERT_EQ(storageManager, nullptr);
}

/*
 * Feature: URIPermissionManagerService
 * Function: ConnectManager
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService ConnectManager
 */
HWTEST_F(UriPermissionImplTest, Upms_ConnectManager_002, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    MockSystemAbilityManager::isNullptr = true;
    sptr<StorageManager::IStorageManager> storageManager = nullptr;
    upms->ConnectManager(storageManager, -1);
    MockSystemAbilityManager::isNullptr = false;
    ASSERT_EQ(storageManager, nullptr);
}

/*
 * Feature: URIPermissionManagerService
 * Function: VerifyUriPermission
 * SubFunction: NA
 * FunctionPoints: URIPermissionManagerService VerifyUriPermission
 */
HWTEST_F(UriPermissionImplTest, Upms_VerifyUriPermission_001, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    auto callerTokenId = 1001;
    auto targetTokenId = 1002;
    auto invalidTokenId = 1003;
    std::string uri = "file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt";
    auto flagRead = 1;
    auto flagWrite = 2;
    auto flagReadWrite = 3;

    // read
    upms->uriMap_.clear();
    upms->AddTempUriPermission(uri, flagRead, callerTokenId, targetTokenId);
    bool funcResult = false;
    upms->VerifyUriPermission(Uri(uri), flagRead, targetTokenId, funcResult);
    ASSERT_EQ(funcResult, true);
    upms->VerifyUriPermission(Uri(uri), flagWrite, targetTokenId, funcResult);
    ASSERT_EQ(funcResult, false);
    upms->VerifyUriPermission(Uri(uri), flagReadWrite, targetTokenId, funcResult);
    ASSERT_EQ(funcResult, false);
    
    // write
    upms->uriMap_.clear();
    upms->AddTempUriPermission(uri, flagWrite, callerTokenId, targetTokenId);
    upms->VerifyUriPermission(Uri(uri), flagRead, targetTokenId, funcResult);
    ASSERT_EQ(funcResult, true);
    upms->VerifyUriPermission(Uri(uri), flagWrite, targetTokenId, funcResult);
    ASSERT_EQ(funcResult, true);
    upms->VerifyUriPermission(Uri(uri), flagReadWrite, targetTokenId, funcResult);
    ASSERT_EQ(funcResult, true);

    // flagReadWrite
    upms->uriMap_.clear();
    upms->AddTempUriPermission(uri, flagReadWrite, callerTokenId, targetTokenId);
    upms->VerifyUriPermission(Uri(uri), flagRead, targetTokenId, funcResult);
    ASSERT_EQ(funcResult, true);
    upms->VerifyUriPermission(Uri(uri), flagWrite, targetTokenId, funcResult);
    ASSERT_EQ(funcResult, true);
    upms->VerifyUriPermission(Uri(uri), flagReadWrite, targetTokenId, funcResult);
    ASSERT_EQ(funcResult, true);
    
    // no permission record
    upms->VerifyUriPermission(Uri(uri), flagRead, invalidTokenId, funcResult);
    ASSERT_EQ(funcResult, false);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckUriPermission
 * SubFunction: NA
 * FunctionPoints: Check uri permission of media\photo uri.
*/
HWTEST_F(UriPermissionImplTest, Upms_CheckUriPermission_001, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    std::string mediaPhotoUri = "file://media/Photo/1/IMG_001/test_001.jpg";
    uint32_t callerTokenId = 1001;
    uint32_t flagRead = 1;

    TokenIdPermission tokenIdPermission(callerTokenId);
    std::vector<std::string> mediaPhotoUris = { mediaPhotoUri };
    auto ret = upms->CheckUriPermission(tokenIdPermission, mediaPhotoUris, flagRead)[0];
    ASSERT_EQ(ret, false);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckUriPermission
 * SubFunction: NA
 * FunctionPoints: Check uri permission of media\audio uri.
*/
HWTEST_F(UriPermissionImplTest, Upms_CheckUriPermission_002, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    std::string mediaAudioUri = "file://media/Audio/1/Record_001/test_001.mp3";
    uint32_t callerTokenId = 1001;
    uint32_t flagRead = 1;

    TokenIdPermission tokenIdPermission(callerTokenId);
    std::vector<std::string> mediaAudioUris = { mediaAudioUri };
    auto ret = upms->CheckUriPermission(tokenIdPermission, mediaAudioUris, flagRead)[0];
    ASSERT_EQ(ret, false);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckUriPermission
 * SubFunction: NA
 * FunctionPoints: Check uri permission of docs uri.
*/
HWTEST_F(UriPermissionImplTest, Upms_CheckUriPermission_003, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    MyFlag::isSAOrSystemAppCall_ = true;
    std::vector<std::string> docsUri = { "file://docs/DestTop/Text/test_001.txt" };
    uint32_t callerTokenId = 1001;
    uint32_t targetTokenId = 1002;
    uint32_t flagRead = 1;
    uint32_t flagWrite = 2;

    TokenIdPermission tokenIdPermission(callerTokenId);
    auto ret = upms->CheckUriPermission(tokenIdPermission, docsUri, flagRead)[0];
    ASSERT_EQ(ret, false);
    
    // have FILE_ACCESS_MANAGER permission
    MyFlag::permissionFileAccessManager_ = true;
    tokenIdPermission = TokenIdPermission(targetTokenId);
    ret = upms->CheckUriPermission(tokenIdPermission, docsUri, flagRead)[0];
    ASSERT_EQ(ret, true);
    ret = upms->CheckUriPermission(tokenIdPermission, docsUri, flagWrite)[0];
    ASSERT_EQ(ret, true);
    MyFlag::permissionFileAccessManager_ = false;
    
    // proxy uri permision
    MyFlag::permissionProxyAuthorization_ = true;
    tokenIdPermission = TokenIdPermission(targetTokenId);
    // no record
    ret = upms->CheckUriPermission(tokenIdPermission, docsUri, flagRead)[0];
    ASSERT_EQ(ret, false);
    ret = upms->CheckUriPermission(tokenIdPermission, docsUri, flagWrite)[0];
    ASSERT_EQ(ret, false);

    // read
    upms->AddTempUriPermission(docsUri[0], flagRead, callerTokenId, targetTokenId);
    ret = upms->CheckUriPermission(tokenIdPermission, docsUri, flagRead)[0];
    ASSERT_EQ(ret, true);
    ret = upms->CheckUriPermission(tokenIdPermission, docsUri, flagWrite)[0];
    ASSERT_EQ(ret, false);
    
    // write
    upms->AddTempUriPermission(docsUri[0], flagWrite, callerTokenId, targetTokenId);
    ret = upms->CheckUriPermission(tokenIdPermission, docsUri, flagWrite)[0];
    ASSERT_EQ(ret, true);
    MyFlag::permissionProxyAuthorization_ = false;
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckUriPermission
 * SubFunction: NA
 * FunctionPoints: Check uri permission of bunldename uri.
*/
HWTEST_F(UriPermissionImplTest, Upms_CheckUriPermission_004, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::isSAOrSystemAppCall_ = true;
    MyFlag::upmsUtilsAlterBundleName_ = "com.example.app1001";
    std::vector<std::string> uri1 = { "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test1.txt" };
    std::vector<std::string> uri2 = { "file://com.example.app1002/data/storage/el2/base/haps/entry/files/test2.txt" };
    uint32_t callerTokenId = 1001;
    uint32_t targetTokenId = 1002;
    uint32_t flagRead = 1;
    uint32_t flagWrite = 2;

    TokenIdPermission tokenIdPermission(callerTokenId);
    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_HAP, "", "com.example.app1001");
    auto ret = upms->CheckUriPermission(tokenIdPermission, uri1, flagRead)[0];
    ASSERT_EQ(ret, true);
    ret = upms->CheckUriPermission(tokenIdPermission, uri1, flagWrite)[0];
    ASSERT_EQ(ret, true);

    ret = upms->CheckUriPermission(tokenIdPermission, uri2, flagRead)[0];
    ASSERT_EQ(ret, false);
    ret = upms->CheckUriPermission(tokenIdPermission, uri2, flagWrite)[0];
    ASSERT_EQ(ret, false);

    // proxy uri permision
    MyFlag::permissionProxyAuthorization_ = true;
    tokenIdPermission = TokenIdPermission(targetTokenId);
    MyFlag::upmsUtilsAlterBundleName_ = "";
    // no record
    ret = upms->CheckUriPermission(tokenIdPermission, uri1, flagRead)[0];
    ASSERT_EQ(ret, false);
    ret = upms->CheckUriPermission(tokenIdPermission, uri1, flagWrite)[0];
    ASSERT_EQ(ret, false);
    
    // read
    upms->AddTempUriPermission(uri1[0], flagRead, callerTokenId, targetTokenId);
    ret = upms->CheckUriPermission(tokenIdPermission, uri1, flagRead)[0];
    ASSERT_EQ(ret, true);
    ret = upms->CheckUriPermission(tokenIdPermission, uri1, flagWrite)[0];
    ASSERT_EQ(ret, false);
    
    // write
    upms->AddTempUriPermission(uri1[0], flagWrite, callerTokenId, targetTokenId);
    ret = upms->CheckUriPermission(tokenIdPermission, uri1, flagRead)[0];
    ASSERT_EQ(ret, true);
    ret = upms->CheckUriPermission(tokenIdPermission, uri1, flagWrite)[0];
    ASSERT_EQ(ret, true);
    MyFlag::permissionProxyAuthorization_ = false;
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: RevokeAllUriPermission
 * SubFunction: NA
 * FunctionPoints: RevokeAllUriPermission called by SA or SystemApp.
*/
HWTEST_F(UriPermissionImplTest, RevokeAllUriPermission_001, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    // mock foundation call
    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    IPCSkeleton::callerUId = 5523;
    int32_t funcResult = -1;
    upms->RevokeAllUriPermissions(1002, funcResult);
    IPCSkeleton::callerUId = 0;
    EXPECT_EQ(funcResult, ERR_OK);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: RevokeAllUriPermission
 * SubFunction: NA
 * FunctionPoints: RevokeAllUriPermission not called by SA or SystemApp.
*/
HWTEST_F(UriPermissionImplTest, RevokeAllUriPermission_002, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    IPCSkeleton::callerUId = 0;
    int32_t funcResult = -1;
    upms->RevokeAllUriPermissions(1002, funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: Active
 * SubFunction: NA
 * FunctionPoints: Active Uri permission without FILE_ACCESS_PERSIST permission.
*/
HWTEST_F(UriPermissionImplTest, UPMS_Active_001, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    constexpr int32_t SANDBOX_MANAGER_PERMISSION_DENIED = 1;
    // get policy data
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    PolicyInfo policyInfo;
    policyInfo.path = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    policyInfo.mode = 1;
    std::vector<PolicyInfo> policyInfoArray = { policyInfo };
    UriPermissionRawData policyRawData;
    upmc.PolicyInfoToRawData(policyInfoArray, policyRawData);
    // make param
    std::vector<uint32_t> result;
    int32_t funcResult = -1;
    // call Active
    auto ret = upms->Active(policyRawData, result, funcResult);
    EXPECT_EQ(funcResult, SANDBOX_MANAGER_PERMISSION_DENIED);
    EXPECT_EQ(ret, ERR_OK);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: Active
 * SubFunction: NA
 * FunctionPoints: Active Uri permission with FILE_ACCESS_PERSIST permission.
*/
HWTEST_F(UriPermissionImplTest, UPMS_Active_002, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    // get policy data
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    PolicyInfo policyInfo;
    policyInfo.path = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    policyInfo.mode = 1;
    std::vector<PolicyInfo> policyInfoArray = { policyInfo };
    UriPermissionRawData policyRawData;
    upmc.PolicyInfoToRawData(policyInfoArray, policyRawData);
    // make param
    std::vector<uint32_t> result;
    int32_t funcResult = -1;
    // call Active
    MyFlag::permissionFileAccessPersist_ = true;
    upms->Active(policyRawData, result, funcResult);
    MyFlag::permissionFileAccessPersist_ = false;
    EXPECT_NE(funcResult, ERR_OK);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: Active
 * SubFunction: NA
 * FunctionPoints: policy vector is empty.
*/
HWTEST_F(UriPermissionImplTest, UPMS_Active_003, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    // get policy data
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    std::vector<PolicyInfo> policyInfoArray;
    UriPermissionRawData policyRawData;
    upmc.PolicyInfoToRawData(policyInfoArray, policyRawData);
    // make param
    std::vector<uint32_t> result;
    int32_t funcResult = -1;
    // call Active
    MyFlag::permissionFileAccessPersist_ = true;
    auto ret = upms->Active(policyRawData, result, funcResult);
    MyFlag::permissionFileAccessPersist_ = false;
    EXPECT_EQ(ret, ERR_URI_LIST_OUT_OF_RANGE);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: GrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: do not have permission to call GrantUriPermissionPrivileged.
*/
HWTEST_F(UriPermissionImplTest, GrantUriPermissionPrivileged_001, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);

    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_NATIVE, "tempProcess");
    IPCSkeleton::callerTokenId = 1001;
    MyFlag::permissionPrivileged_ = false;

    auto uri1 = Uri("file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt");
    std::string targetBundleName = "com.example.app1002";
    uint32_t flag = 1;
    const std::vector<Uri> uris = { uri1 };
    std::vector<std::string> stringUris;
    for (const Uri& uri : uris) {
        stringUris.push_back(uri.ToString());
    }
    const std::vector<std::string> stringUriVec = stringUris;
    int32_t funcResult = -1;
    upms->GrantUriPermissionPrivileged(stringUriVec, flag, targetBundleName, 0, 0, 0, funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: GrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: flag is 0.
*/
HWTEST_F(UriPermissionImplTest, GrantUriPermissionPrivileged_002, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);

    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_NATIVE, "foundation");
    IPCSkeleton::callerTokenId = 1001;
    MyFlag::permissionPrivileged_ = true;

    auto uri1 = Uri("file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt");
    std::string targetBundleName = "com.example.app1002";
    uint32_t flag = 0;
    const std::vector<Uri> uris = { uri1 };
    std::vector<std::string> stringUris;
    for (const Uri& uri : uris) {
        stringUris.push_back(uri.ToString());
    }
    const std::vector<std::string> stringUriVec = stringUris;
    int32_t funcResult = -1;
    upms->GrantUriPermissionPrivileged(stringUriVec, flag, targetBundleName, 0, 0, 0, funcResult);
    MyFlag::permissionPrivileged_ = false;
    EXPECT_EQ(funcResult, ERR_CODE_INVALID_URI_FLAG);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: GrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: targetBundleName is invalid.
*/
HWTEST_F(UriPermissionImplTest, GrantUriPermissionPrivileged_003, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::isUriTypeValid_ = true;
    MyFlag::getTokenIdByBundleNameStatus_ = ERR_GET_TARGET_BUNDLE_INFO_FAILED;
    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_NATIVE, "foundation");
    IPCSkeleton::callerTokenId = 1001;
    MyFlag::permissionPrivileged_ = true;

    auto uri1 = Uri("file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt");
    std::string targetBundleName = "com.example.invalid";
    uint32_t flag = 1;
    const std::vector<Uri> uris = { uri1 };
    std::vector<std::string> stringUris;
    for (const Uri& uri : uris) {
        stringUris.push_back(uri.ToString());
    }
    const std::vector<std::string> stringUriVec = stringUris;
    int32_t funcResult = -1;
    upms->GrantUriPermissionPrivileged(stringUriVec, flag, targetBundleName, 0, 0, 0, funcResult);
    MyFlag::permissionPrivileged_ = false;
    EXPECT_EQ(funcResult, ERR_GET_TARGET_BUNDLE_INFO_FAILED);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: GrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: type of uri is invalid.
*/
HWTEST_F(UriPermissionImplTest, GrantUriPermissionPrivileged_004, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);

    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_NATIVE, "foundation");
    IPCSkeleton::callerTokenId = 1001;
    MyFlag::permissionPrivileged_ = true;

    auto uri1 = Uri("http://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt");
    std::string targetBundleName = "com.example.app1002";
    uint32_t flag = 1;
    const std::vector<Uri> uris = { uri1 };
    std::vector<std::string> stringUris;
    for (const Uri& uri : uris) {
        stringUris.push_back(uri.ToString());
    }
    const std::vector<std::string> stringUriVec = stringUris;
    int32_t funcResult = -1;
    upms->GrantUriPermissionPrivileged(stringUriVec, flag, targetBundleName, 0, 0, 0, funcResult);
    MyFlag::permissionPrivileged_ = false;
    EXPECT_EQ(funcResult, ERR_CODE_INVALID_URI_TYPE);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: GrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: Create Share File failed.
*/
HWTEST_F(UriPermissionImplTest, GrantUriPermissionPrivileged_005, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::isUriTypeValid_ = true;
    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_NATIVE, "foundation");
    IPCSkeleton::callerTokenId = 1001;
    MyFlag::permissionPrivileged_ = true;

    auto uri1 = Uri("file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt");
    std::string targetBundleName = "com.example.app1002";
    uint32_t flag = 1;
    const std::vector<Uri> uris = { uri1 };
    std::vector<std::string> stringUris;
    for (const Uri& uri : uris) {
        stringUris.push_back(uri.ToString());
    }
    const std::vector<std::string> stringUriVec = stringUris;
    upms->storageManager_ = new StorageManager::StorageManagerServiceMock();
    StorageManager::StorageManagerServiceMock::isZero = false;
    int32_t funcResult = -1;
    upms->GrantUriPermissionPrivileged(stringUriVec, flag, targetBundleName, 0, 0, -1, funcResult);
    MyFlag::permissionPrivileged_ = false;
    EXPECT_EQ(funcResult, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: GrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: Grant Uri permission success.
*/
HWTEST_F(UriPermissionImplTest, GrantUriPermissionPrivileged_006, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::isUriTypeValid_ = true;
    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_NATIVE, "foundation");
    IPCSkeleton::callerTokenId = 1001;
    MyFlag::permissionPrivileged_ = true;

    auto uri1 = Uri("file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt");
    std::string targetBundleName = "com.example.app1002";
    uint32_t flag = 1;
    const std::vector<Uri> uris = { uri1 };
    std::vector<std::string> stringUris;
    for (const Uri& uri : uris) {
        stringUris.push_back(uri.ToString());
    }
    const std::vector<std::string> stringUriVec = stringUris;
    upms->storageManager_ = new StorageManager::StorageManagerServiceMock();
    StorageManager::StorageManagerServiceMock::isZero = true;
    int32_t funcResult = -1;
    upms->GrantUriPermissionPrivileged(stringUriVec, flag, targetBundleName, 0, 0, -1, funcResult);
    MyFlag::permissionPrivileged_ = false;
    EXPECT_EQ(funcResult, ERR_OK);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: GrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: do not have permission to call GrantUriPermissionPrivileged.
*/
HWTEST_F(UriPermissionImplTest, GrantUriPermissionPrivileged_007, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();

    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_NATIVE, "tempProcess");
    IPCSkeleton::callerTokenId = 1001;
    MyFlag::permissionPrivileged_ = false;

    auto uri1 = Uri("file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt");
    std::string targetBundleName = "com.example.app1002";
    uint32_t flag = 1;
    const std::vector<Uri> uris = { uri1 };
    std::vector<std::string> stringUris;
    for (const Uri& uri : uris) {
        stringUris.push_back(uri.ToString());
    }
    UriPermissionRawData rawData;
    upmc.StringVecToRawData(stringUris, rawData);
    int32_t funcResult = -1;
    upms->GrantUriPermissionPrivileged(rawData, flag, targetBundleName, 0, 0, 0, funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: GrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: flag is 0.
*/
HWTEST_F(UriPermissionImplTest, GrantUriPermissionPrivileged_008, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();

    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_NATIVE, "foundation");
    IPCSkeleton::callerTokenId = 1001;
    MyFlag::permissionPrivileged_ = true;

    auto uri1 = Uri("file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt");
    std::string targetBundleName = "com.example.app1002";
    uint32_t flag = 0;
    const std::vector<Uri> uris = { uri1 };
    std::vector<std::string> stringUris;
    for (const Uri& uri : uris) {
        stringUris.push_back(uri.ToString());
    }
    UriPermissionRawData rawData;
    upmc.StringVecToRawData(stringUris, rawData);
    int32_t funcResult = -1;
    upms->GrantUriPermissionPrivileged(rawData, flag, targetBundleName, 0, 0, 0, funcResult);
    MyFlag::permissionPrivileged_ = false;
    EXPECT_EQ(funcResult, ERR_CODE_INVALID_URI_FLAG);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: GrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: targetBundleName is invalid.
*/
HWTEST_F(UriPermissionImplTest, GrantUriPermissionPrivileged_009, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    MyFlag::isUriTypeValid_ = true;
    MyFlag::getTokenIdByBundleNameStatus_ = ERR_GET_TARGET_BUNDLE_INFO_FAILED;
    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_NATIVE, "foundation");
    IPCSkeleton::callerTokenId = 1001;
    MyFlag::permissionPrivileged_ = true;

    auto uri1 = Uri("file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt");
    std::string targetBundleName = "com.example.invalid";
    uint32_t flag = 1;
    const std::vector<Uri> uris = { uri1 };
    std::vector<std::string> stringUris;
    for (const Uri& uri : uris) {
        stringUris.push_back(uri.ToString());
    }
    UriPermissionRawData rawData;
    upmc.StringVecToRawData(stringUris, rawData);
    int32_t funcResult = -1;
    upms->GrantUriPermissionPrivileged(rawData, flag, targetBundleName, 0, 0, 0, funcResult);
    MyFlag::permissionPrivileged_ = false;
    EXPECT_EQ(funcResult, ERR_GET_TARGET_BUNDLE_INFO_FAILED);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: GrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: type of uri is invalid.
*/
HWTEST_F(UriPermissionImplTest, GrantUriPermissionPrivileged_010, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();

    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_NATIVE, "foundation");
    IPCSkeleton::callerTokenId = 1001;
    MyFlag::permissionPrivileged_ = true;

    auto uri1 = Uri("http://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt");
    std::string targetBundleName = "com.example.app1002";
    uint32_t flag = 1;
    const std::vector<Uri> uris = { uri1 };
    std::vector<std::string> stringUris;
    for (const Uri& uri : uris) {
        stringUris.push_back(uri.ToString());
    }
    UriPermissionRawData rawData;
    upmc.StringVecToRawData(stringUris, rawData);
    int32_t funcResult = -1;
    upms->GrantUriPermissionPrivileged(rawData, flag, targetBundleName, 0, 0, 0, funcResult);
    MyFlag::permissionPrivileged_ = false;
    EXPECT_EQ(funcResult, ERR_CODE_INVALID_URI_TYPE);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: GrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: Create Share File failed.
*/
HWTEST_F(UriPermissionImplTest, GrantUriPermissionPrivileged_011, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::isUriTypeValid_ = true;
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();

    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_NATIVE, "foundation");
    IPCSkeleton::callerTokenId = 1001;
    MyFlag::permissionPrivileged_ = true;

    auto uri1 = Uri("file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt");
    std::string targetBundleName = "com.example.app1002";
    uint32_t flag = 1;
    const std::vector<Uri> uris = { uri1 };
    std::vector<std::string> stringUris;
    for (const Uri& uri : uris) {
        stringUris.push_back(uri.ToString());
    }
    UriPermissionRawData rawData;
    upmc.StringVecToRawData(stringUris, rawData);
    upms->storageManager_ = new StorageManager::StorageManagerServiceMock();
    StorageManager::StorageManagerServiceMock::isZero = false;
    int32_t funcResult = -1;
    upms->GrantUriPermissionPrivileged(rawData, flag, targetBundleName, 0, 0, -1, funcResult);
    MyFlag::permissionPrivileged_ = false;
    EXPECT_EQ(funcResult, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: GrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: Grant Uri permission success.
*/
HWTEST_F(UriPermissionImplTest, GrantUriPermissionPrivileged_012, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_NATIVE, "foundation");
    IPCSkeleton::callerTokenId = 1001;
    MyFlag::permissionPrivileged_ = true;
    MyFlag::isUriTypeValid_ = true;

    auto uri1 = Uri("file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt");
    std::string targetBundleName = "com.example.app1002";
    uint32_t flag = 1;
    const std::vector<Uri> uris = { uri1 };
    std::vector<std::string> stringUris;
    for (const Uri& uri : uris) {
        stringUris.push_back(uri.ToString());
    }
    UriPermissionRawData rawData;
    upmc.StringVecToRawData(stringUris, rawData);
    upms->storageManager_ = new StorageManager::StorageManagerServiceMock();
    StorageManager::StorageManagerServiceMock::isZero = true;
    int32_t funcResult = -1;
    upms->GrantUriPermissionPrivileged(rawData, flag, targetBundleName, 0, 0, -1, funcResult);
    MyFlag::permissionPrivileged_ = false;
    EXPECT_EQ(funcResult, ERR_OK);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckUriAuthorization
 * SubFunction: NA
 * FunctionPoints: CheckUriAuthorization not called by SA or SystemApp.
*/
HWTEST_F(UriPermissionImplTest, CheckUriAuthorization_001, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ &= (~MyFlag::IS_SA_CALL);
    std::string uri = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    const std::vector<std::string> uris = { uri };
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uris, rawData);

    UriPermissionRawData stubPolicyRawData;
    stubPolicyRawData.size = rawData.size;
    EXPECT_EQ(stubPolicyRawData.RawDataCpy(rawData.data), ERR_NONE);

    uint32_t flag = 1;
    uint32_t tokenId = 1001;
    std::vector<bool> expectRes(1, false);
    UriPermissionRawData funcResult;
    upms->CheckUriAuthorization(stubPolicyRawData, flag, tokenId, funcResult);

    std::vector<bool> expectResVec(1, true);
    upmc.RawDataToBoolVec(funcResult, expectResVec);
    EXPECT_EQ(expectResVec, expectRes);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckUriAuthorization
 * SubFunction: NA
 * FunctionPoints: flag is 0.
*/
HWTEST_F(UriPermissionImplTest, CheckUriAuthorization_002, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    std::string uri = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    const std::vector<std::string> uris = { uri };
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uris, rawData);

    UriPermissionRawData stubPolicyRawData;
    stubPolicyRawData.size = rawData.size;
    EXPECT_EQ(stubPolicyRawData.RawDataCpy(rawData.data), ERR_NONE);

    uint32_t flag = 0;
    uint32_t tokenId = 1001;
    std::vector<bool> expectRes(1, false);
    UriPermissionRawData funcResult;
    upms->CheckUriAuthorization(stubPolicyRawData, flag, tokenId, funcResult);

    std::vector<bool> expectResVec(1, true);
    upmc.RawDataToBoolVec(funcResult, expectResVec);
    EXPECT_EQ(expectResVec, expectRes);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckUriAuthorization
 * SubFunction: NA
 * FunctionPoints: uri is invalid.
*/
HWTEST_F(UriPermissionImplTest, CheckUriAuthorization_003, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    std::string uri = "http://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    const std::vector<std::string> uris = { uri };
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uris, rawData);

    UriPermissionRawData stubPolicyRawData;
    stubPolicyRawData.size = rawData.size;
    EXPECT_EQ(stubPolicyRawData.RawDataCpy(rawData.data), ERR_NONE);

    uint32_t flag = 1;
    uint32_t tokenId = 1001;
    std::vector<bool> expectRes(1, false);
    UriPermissionRawData funcResult;
    upms->CheckUriAuthorization(stubPolicyRawData, flag, tokenId, funcResult);

    std::vector<bool> expectResVec(1, true);
    upmc.RawDataToBoolVec(funcResult, expectResVec);
    EXPECT_EQ(expectResVec, expectRes);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckUriAuthorization
 * SubFunction: NA
 * FunctionPoints: check uri authorization failed, have no permission.
*/
HWTEST_F(UriPermissionImplTest, CheckUriAuthorization_004, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    std::string uri = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    const std::vector<std::string> uris = { uri };
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uris, rawData);

    UriPermissionRawData stubPolicyRawData;
    stubPolicyRawData.size = rawData.size;
    EXPECT_EQ(stubPolicyRawData.RawDataCpy(rawData.data), ERR_NONE);

    uint32_t flag = 1;
    uint32_t tokenId = 1002;
    std::vector<bool> expectRes(1, false);
    UriPermissionRawData funcResult;
    upms->CheckUriAuthorization(stubPolicyRawData, flag, tokenId, funcResult);

    std::vector<bool> expectResVec(1, true);
    upmc.RawDataToBoolVec(funcResult, expectResVec);
    EXPECT_EQ(expectResVec, expectRes);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckUriAuthorization
 * SubFunction: NA
 * FunctionPoints: check uri authorization success.
*/
HWTEST_F(UriPermissionImplTest, CheckUriAuthorization_005, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    std::string uri = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    const std::vector<std::string> uris = { uri };
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uris, rawData);

    UriPermissionRawData stubPolicyRawData;
    stubPolicyRawData.size = rawData.size;
    EXPECT_EQ(stubPolicyRawData.RawDataCpy(rawData.data), ERR_NONE);

    uint32_t flag = 1;
    uint32_t tokenId = 1001;
    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_HAP, "", "com.example.app1001");
    std::vector<bool> expectRes(1, true);
    UriPermissionRawData funcResult;
    MyFlag::upmsUtilsAlterBundleName_ = "com.example.app1001";
    MyFlag::upmsUtilsGetAlterBundleNameByTokenIdRet_ = true;
    upms->CheckUriAuthorization(stubPolicyRawData, flag, tokenId, funcResult);

    std::vector<bool> expectResVec(1, false);
    upmc.RawDataToBoolVec(funcResult, expectResVec);
    EXPECT_EQ(expectResVec, expectRes);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckUriAuthorization
 * SubFunction: NA
 * FunctionPoints: CheckUriAuthorization not called by SA or SystemApp.
*/
HWTEST_F(UriPermissionImplTest, CheckUriAuthorization_006, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ &= (~MyFlag::IS_SA_CALL);
    std::string uri = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    const std::vector<std::string> uris = { uri };
    std::vector<bool> funcResult(1, false);
    uint32_t flag = 1;
    uint32_t tokenId = 1001;
    upms->CheckUriAuthorization(uris, flag, tokenId, funcResult);

    std::vector<bool> expectRes(1, false);
    EXPECT_EQ(expectRes, funcResult);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckUriAuthorization
 * SubFunction: NA
 * FunctionPoints: flag is 0.
*/
HWTEST_F(UriPermissionImplTest, CheckUriAuthorization_007, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    std::string uri = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    const std::vector<std::string> uris = { uri };
    std::vector<bool> funcResult(1, false);
    uint32_t flag = 0;
    uint32_t tokenId = 1001;
    upms->CheckUriAuthorization(uris, flag, tokenId, funcResult);

    std::vector<bool> expectRes(1, false);
    EXPECT_EQ(expectRes, funcResult);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckUriAuthorization
 * SubFunction: NA
 * FunctionPoints: uri is invalid.
*/
HWTEST_F(UriPermissionImplTest, CheckUriAuthorization_008, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    std::string uri = "http://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    const std::vector<std::string> uris = { uri };
    std::vector<bool> funcResult(1, false);
    uint32_t flag = 1;
    uint32_t tokenId = 1001;
    upms->CheckUriAuthorization(uris, flag, tokenId, funcResult);

    std::vector<bool> expectRes(1, false);
    EXPECT_EQ(expectRes, funcResult);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckUriAuthorization
 * SubFunction: NA
 * FunctionPoints: check uri authorization failed, have no permission.
*/
HWTEST_F(UriPermissionImplTest, CheckUriAuthorization_009, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    std::string uri = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    const std::vector<std::string> uris = { uri };
    std::vector<bool> funcResult(1, false);
    uint32_t flag = 1;
    uint32_t tokenId = 1002;
    upms->CheckUriAuthorization(uris, flag, tokenId, funcResult);

    std::vector<bool> expectRes(1, false);
    EXPECT_EQ(expectRes, funcResult);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckUriAuthorization
 * SubFunction: NA
 * FunctionPoints: check uri authorization success.
*/
HWTEST_F(UriPermissionImplTest, CheckUriAuthorization_010, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::flag_ |= MyFlag::IS_SA_CALL;
    std::string uri = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    const std::vector<std::string> uris = { uri };
    std::vector<bool> funcResult(1, false);
    uint32_t flag = 1;
    uint32_t tokenId = 1001;
    MyFlag::tokenInfos[1001] = TokenInfo(1001, MyATokenTypeEnum::TOKEN_HAP, "", "com.example.app1001");
    MyFlag::upmsUtilsAlterBundleName_ = "com.example.app1001";
    MyFlag::upmsUtilsGetAlterBundleNameByTokenIdRet_ = true;
    upms->CheckUriAuthorization(uris, flag, tokenId, funcResult);

    std::vector<bool> expectRes(1, true);
    EXPECT_EQ(expectRes, funcResult);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: RawDataToPolicyInfo
 * SubFunction: NA
 * FunctionPoints: call PolicyInfoToRawData and RawDataToPolicyInfo sucess.
*/
HWTEST_F(UriPermissionImplTest, RawDataToPolicyInfo_001, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    PolicyInfo policyInfo1;
    policyInfo1.path = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    policyInfo1.mode = 1;
    PolicyInfo policyInfo2;
    policyInfo2.path = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_002.txt";
    policyInfo2.mode = 2;
    std::vector<PolicyInfo> policyInfoArray;
    policyInfoArray.push_back(policyInfo1);
    policyInfoArray.push_back(policyInfo2);
    UriPermissionRawData policyRawData;
    upmc.PolicyInfoToRawData(policyInfoArray, policyRawData);

    UriPermissionRawData stubPolicyRawData;
    stubPolicyRawData.size = policyRawData.size;
    EXPECT_EQ(stubPolicyRawData.RawDataCpy(policyRawData.data), ERR_NONE);

    std::vector<PolicyInfo> resultPolicyInfo;
    upms->RawDataToPolicyInfo(stubPolicyRawData, resultPolicyInfo);
    EXPECT_EQ(policyInfoArray.size(), resultPolicyInfo.size());
    bool result = true;
    for (int32_t i = 0; i < policyInfoArray.size(); ++i) {
        if (policyInfoArray[i].path != resultPolicyInfo[i].path ||
            policyInfoArray[i].mode != resultPolicyInfo[i].mode) {
            result = false;
            break;
        }
    }
    EXPECT_TRUE(result);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: RawDataToStringVec
 * SubFunction: NA
 * FunctionPoints: call StringVecToRawData and RawDataToStringVec sucess.
*/
HWTEST_F(UriPermissionImplTest, RawDataToStringVec_001, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    std::string uri = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    const std::vector<std::string> uris = { uri };
    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uris, rawData);

    UriPermissionRawData stubRawData;
    stubRawData.size = rawData.size;
    EXPECT_EQ(stubRawData.RawDataCpy(rawData.data), ERR_NONE);

    std::vector<std::string> resultStringVec;
    upms->RawDataToStringVec(stubRawData, resultStringVec);
    EXPECT_EQ(uris.size(), resultStringVec.size());
    bool result = true;
    for (int32_t i = 0; i < uris.size(); ++i) {
        if (uris[i].compare(resultStringVec[i]) != 0) {
            result = false;
            break;
        }
    }
    EXPECT_TRUE(result);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: RawDataToStringVec
 * SubFunction: NA
 * FunctionPoints: call StringVecToRawData and RawDataToStringVec fail.
*/
HWTEST_F(UriPermissionImplTest, RawDataToStringVec_002, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    std::string uri = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
    const std::vector<std::string> uris(300000, uri);
    UriPermissionRawData rawData;
    upmc.StringVecToRawData(uris, rawData);

    UriPermissionRawData stubRawData;
    stubRawData.size = rawData.size;
    EXPECT_EQ(stubRawData.RawDataCpy(rawData.data), ERR_NONE);

    std::vector<std::string> resultStringVec;
    auto result = upms->RawDataToStringVec(stubRawData, resultStringVec);
    EXPECT_EQ(result, ERR_URI_LIST_OUT_OF_RANGE);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: BoolVecToRawData
 * SubFunction: NA
 * FunctionPoints: call BoolVecToRawData and RawDataToBoolVec sucess.
*/
HWTEST_F(UriPermissionImplTest, BoolVecToRawData_001, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    auto& upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    std::vector<bool> boolVec(1, true);
    UriPermissionRawData rawData;
    std::vector<char> boolVecToCharVec;
    upms->BoolVecToRawData(boolVec, rawData, boolVecToCharVec);

    UriPermissionRawData stubRawData;
    stubRawData.size = rawData.size;
    EXPECT_EQ(stubRawData.RawDataCpy(rawData.data), ERR_NONE);

    std::vector<bool> resultBoolVec(1, false);
    upmc.RawDataToBoolVec(stubRawData, resultBoolVec);
    EXPECT_EQ(boolVec.size(), resultBoolVec.size());
    bool result = true;
    for (int32_t i = 0; i < boolVec.size(); ++i) {
        if (boolVec[i] != resultBoolVec[i]) {
            result = false;
            break;
        }
    }
    EXPECT_TRUE(result);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: GrantBatchContentUriPermissionImpl
 * SubFunction: NA
 * FunctionPoints: GrantBatchContentUriPermissionImpl
 */
HWTEST_F(UriPermissionImplTest, GrantBatchContentUriPermissionImpl_001, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    AbilityManagerClient::isNullInstance = true;
    uint32_t flag = 1;
    uint32_t tokenId = 1001;
    std::string targetBundleName = "com.example.test";
    std::vector<std::string> contentUris;
    auto ret = upms->GrantBatchContentUriPermissionImpl(contentUris, flag, tokenId, targetBundleName);
    EXPECT_EQ(ret, INNER_ERR);
    
    contentUris.emplace_back("content://temp.txt");
    ret = upms->GrantBatchContentUriPermissionImpl(contentUris, flag, tokenId, targetBundleName);
    EXPECT_EQ(ret, INNER_ERR);

    AbilityManagerClient::isNullInstance = false;
    ret = upms->GrantBatchContentUriPermissionImpl(contentUris, flag, tokenId, targetBundleName);
    EXPECT_EQ(ret, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: RevokeContentUriPermission
 * SubFunction: NA
 * FunctionPoints: RevokeContentUriPermission
 */
HWTEST_F(UriPermissionImplTest, RevokeContentUriPermission_001, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    AbilityManagerClient::isNullInstance = true;
    uint32_t tokenId = 1001;
    auto ret = upms->RevokeContentUriPermission(tokenId);
    EXPECT_EQ(ret, ERR_OK);

    upms->AddContentTokenIdRecord(tokenId);
    ret = upms->RevokeContentUriPermission(tokenId);
    EXPECT_EQ(ret, INNER_ERR);
    
    upms->AddContentTokenIdRecord(tokenId);
    AbilityManagerClient::isNullInstance = false;
    ret = upms->RevokeContentUriPermission(tokenId);
    EXPECT_EQ(ret, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: UriPermissionImplTest
 * SubFunction: NA
 * FunctionPoints: capacity not support
 */
HWTEST_F(UriPermissionImplTest, Upmsi_CheckGrantUriPermissionByKeyAsCaller_001, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    AppUtils::isSupportGrantUriPermission_ = false;
    auto result = upms->CheckGrantUriPermissionByKeyAsCaller();
    EXPECT_EQ(result, ERR_CAPABILITY_NOT_SUPPORT);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckGrantUriPermissionByKeyAsCaller
 * SubFunction: NA
 * FunctionPoints: not system app call
 */
HWTEST_F(UriPermissionImplTest, Upmsi_CheckGrantUriPermissionByKeyAsCaller_002, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::isSystemAppCall_ = false;
    auto result = upms->CheckGrantUriPermissionByKeyAsCaller();
    EXPECT_EQ(result, ERR_NOT_SYSTEM_APP);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckGrantUriPermissionByKeyAsCaller
 * SubFunction: NA
 * FunctionPoints: no grantUriPermissonByKeyAsCaller permission
 */
HWTEST_F(UriPermissionImplTest, Upmsi_CheckGrantUriPermissionByKeyAsCaller_003, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::isSystemAppCall_ = true;
    MyFlag::permissionGrantUriPermissionAsCaller_ = false;
    auto result = upms->CheckGrantUriPermissionByKeyAsCaller();
    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckGrantUriPermissionByKeyAsCaller
 * SubFunction: NA
 * FunctionPoints: CheckCalledBySandBox failed
 */
HWTEST_F(UriPermissionImplTest, Upmsi_CheckGrantUriPermissionByKeyAsCaller_004, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::isSystemAppCall_ = true;
    MyFlag::permissionGrantUriPermissionAsCaller_ = true;
    auto mockAppMgr = new AppExecFwk::MockAppMgrService();
    mockAppMgr->judgeSandboxByPidRet_ = 0;
    mockAppMgr->isSandbox_ = true;
    upms->appMgr_ = mockAppMgr;
    auto result = upms->CheckGrantUriPermissionByKeyAsCaller();
    EXPECT_EQ(result, ERR_CODE_GRANT_URI_PERMISSION);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckGrantUriPermissionByKeyAsCaller
 * SubFunction: NA
 * FunctionPoints: success
 */
HWTEST_F(UriPermissionImplTest, Upmsi_CheckGrantUriPermissionByKeyAsCaller_005, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::isSystemAppCall_ = true;
    MyFlag::permissionGrantUriPermissionAsCaller_ = true;
    auto mockAppMgr = new AppExecFwk::MockAppMgrService();
    mockAppMgr->judgeSandboxByPidRet_ = 0;
    mockAppMgr->isSandbox_ = false;
    upms->appMgr_ = mockAppMgr;
    auto result = upms->CheckGrantUriPermissionByKeyAsCaller();
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckGrantUriPermissionByKeyParams
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerStubImpl CheckGrantUriPermissionByKeyParams
 */
HWTEST_F(UriPermissionImplTest, Upmsi_CheckGrantUriPermissionByKeyParams_001, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    const std::string key = "";
    uint32_t flag = 0;
    UPMSAppInfo calerAppInfo = { .tokenId = 1001 };
    UPMSAppInfo targetAppInfo = { .tokenId = 1002 };
    std::vector<std::string> uris;
    auto ret = upms->CheckGrantUriPermissionByKeyParams(key, flag, calerAppInfo, targetAppInfo, uris);
    EXPECT_EQ(ret, ERR_CODE_INVALID_URI_FLAG);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckGrantUriPermissionByKeyParams
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerStubImpl CheckGrantUriPermissionByKeyParams
 */
HWTEST_F(UriPermissionImplTest, Upmsi_CheckGrantUriPermissionByKeyParams_002, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    const std::string key = "";
    uint32_t flag = 1;
    UPMSAppInfo calerAppInfo = { .tokenId = 1001 };
    UPMSAppInfo targetAppInfo = { .tokenId = 1001 };
    std::vector<std::string> uris;
    auto ret = upms->CheckGrantUriPermissionByKeyParams(key, flag, calerAppInfo, targetAppInfo, uris);
    EXPECT_EQ(ret, ERR_UPMS_INVALID_TARGET_TOKENID);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckGrantUriPermissionByKeyParams
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerStubImpl CheckGrantUriPermissionByKeyParams
 */
HWTEST_F(UriPermissionImplTest, Upmsi_CheckGrantUriPermissionByKeyParams_003, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    const std::string key = "";
    uint32_t flag = 1;
    UPMSAppInfo calerAppInfo = { .tokenId = 1001 };
    UPMSAppInfo targetAppInfo = { .tokenId = 1002 };
    std::vector<std::string> uris;
    MyFlag::upmsUtilsGetAlterBundleNameByTokenIdRet_ = false;
    auto ret = upms->CheckGrantUriPermissionByKeyParams(key, flag, calerAppInfo, targetAppInfo, uris);
    EXPECT_EQ(ret, ERR_UPMS_INVALID_CALLER_TOKENID);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckGrantUriPermissionByKeyParams
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerStubImpl CheckGrantUriPermissionByKeyParams
 */
HWTEST_F(UriPermissionImplTest, Upmsi_CheckGrantUriPermissionByKeyParams_004, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    const std::string key = "";
    uint32_t flag = 1;
    UPMSAppInfo calerAppInfo = { .tokenId = 1001 };
    UPMSAppInfo targetAppInfo = { .tokenId = 1002 };
    std::vector<std::string> uris;
    MyFlag::processUdmfKeyRet_ = INNER_ERR;
    auto ret = upms->CheckGrantUriPermissionByKeyParams(key, flag, calerAppInfo, targetAppInfo, uris);
    EXPECT_EQ(ret, ERR_UPMS_GET_FILE_URIS_BY_KEY_FAILED);
}

/*
 * Feature: UriPermissionManagerStubImpl
 * Function: CheckGrantUriPermissionByKeyParams
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerStubImpl CheckGrantUriPermissionByKeyParams
 */
HWTEST_F(UriPermissionImplTest, Upmsi_CheckGrantUriPermissionByKeyParams_005, TestSize.Level1)
{
    auto upms = std::make_shared<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    const std::string key = "";
    uint32_t flag = 1;
    UPMSAppInfo calerAppInfo = { .tokenId = 1001 };
    UPMSAppInfo targetAppInfo = { .tokenId = 1002 };
    std::vector<std::string> uris;
    MyFlag::processUdmfKeyRet_ = ERR_OK;
    auto ret = upms->CheckGrantUriPermissionByKeyParams(key, flag, calerAppInfo, targetAppInfo, uris);
    EXPECT_EQ(ret, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionByKey
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionByKey
 */
HWTEST_F(UriPermissionImplTest, GrantUriPermissionByKey_001, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    std::string key = "testKey";
    uint32_t flag = 1;
    uint32_t targetTokenId = 100002;
    int32_t funcResult = -1;
    auto ret = upms->GrantUriPermissionByKey(key, flag, targetTokenId, funcResult);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(funcResult, ERR_NOT_SYSTEM_APP);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionByKey
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionByKey
 */
HWTEST_F(UriPermissionImplTest, GrantUriPermissionByKey_002, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::isSystemAppCall_ = true;
    std::string key = "testKey";
    uint32_t flag = 1;
    uint32_t targetTokenId = 100002;
    int32_t funcResult = -1;
    auto ret = upms->GrantUriPermissionByKey(key, flag, targetTokenId, funcResult);
    MyFlag::isSystemAppCall_ = false;
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(funcResult, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionByKey
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionByKey
 */
HWTEST_F(UriPermissionImplTest, GrantUriPermissionByKey_003, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::isSystemAppCall_ = true;
    sptr<AppExecFwk::MockAppMgrService> mockAppMgr(new AppExecFwk::MockAppMgrService());
    ASSERT_NE(mockAppMgr, nullptr);
    mockAppMgr->judgeSandboxByPidRet_ = 0;
    mockAppMgr->isSandbox_ = true;
    upms->appMgr_ = iface_cast<AppExecFwk::IAppMgr>(mockAppMgr);
    std::string key = "testKey";
    uint32_t flag = 1;
    uint32_t targetTokenId = 100002;
    int32_t funcResult = -1;
    auto ret = upms->GrantUriPermissionByKey(key, flag, targetTokenId, funcResult);
    MyFlag::isSystemAppCall_ = false;
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(funcResult, ERR_CODE_GRANT_URI_PERMISSION);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionByKey
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionByKey
 */
HWTEST_F(UriPermissionImplTest, GrantUriPermissionByKey_004, TestSize.Level1)
{
    auto upms = std::make_unique<UriPermissionManagerStubImpl>();
    ASSERT_NE(upms, nullptr);
    MyFlag::isSystemAppCall_ = true;
    sptr<AppExecFwk::MockAppMgrService> mockAppMgr(new AppExecFwk::MockAppMgrService());
    ASSERT_NE(mockAppMgr, nullptr);
    mockAppMgr->judgeSandboxByPidRet_ = 0;
    mockAppMgr->isSandbox_ = false;
    upms->appMgr_ = iface_cast<AppExecFwk::IAppMgr>(mockAppMgr);
    std::string key = "testKey";
    uint32_t flag = 1;
    uint32_t targetTokenId = 100002;
    int32_t funcResult = -1;
    auto ret = upms->GrantUriPermissionByKey(key, flag, targetTokenId, funcResult);
    MyFlag::isSystemAppCall_ = false;
    EXPECT_EQ(ret, ERR_OK);
}
}  // namespace AAFwk
}  // namespace OHOS
