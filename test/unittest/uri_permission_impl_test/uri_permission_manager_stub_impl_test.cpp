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

#include "ability_manager_client.h"
#include "mock_my_flag.h"

#define private public
#define protected public
#include "uri_permission_manager_client.h"
#include "uri_permission_manager_stub_impl.h"
#include "ability_manager_errors.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
namespace {
constexpr int OFFSET = 30;
const std::string POLICY_INFO_PATH = "file://com.example.app1001/data/storage/el2/base/haps/entry/files/test_001.txt";
}
class UriPermissionManagerStubImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void UriPermissionManagerStubImplTest::SetUpTestCase() {}

void UriPermissionManagerStubImplTest::TearDownTestCase() {}

void UriPermissionManagerStubImplTest::SetUp() {}

void UriPermissionManagerStubImplTest::TearDown() {}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifyUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifyUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifyUriPermission_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    MyFlag::isDFSCallRet_ = false;
    std::string uri = "uri";
    uint32_t flag = 1;
    uint32_t tokenId = 1;
    bool funcResult = true;
    auto result = upmsi->VerifyUriPermission(Uri(uri), flag, tokenId, funcResult);
    EXPECT_FALSE(funcResult);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifyUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifyUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifyUriPermission_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    MyFlag::isDFSCallRet_ = true;
    std::string uri = "uri";
    uint32_t flag = 0;
    uint32_t tokenId = 1;
    bool funcResult = true;
    auto result = upmsi->VerifyUriPermission(Uri(uri), flag, tokenId, funcResult);
    EXPECT_FALSE(funcResult);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifyUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifyUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifyUriPermission_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    MyFlag::isDFSCallRet_ = true;
    MyFlag::isUriTypeValid_ = false;
    std::string uri = "uri";
    uint32_t flag = 1;
    uint32_t tokenId = 1;
    bool funcResult = true;
    auto result = upmsi->VerifyUriPermission(Uri(uri), flag, tokenId, funcResult);
    EXPECT_FALSE(funcResult);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifySubDirUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifySubDirUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifySubDirUriPermission_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    upmsi->uriMap_.clear();
    std::string uriStr = "?networkid=";
    uint32_t newFlag = 1;
    uint32_t tokenId = 1;
    auto result = upmsi->VerifySubDirUriPermission(uriStr, newFlag, tokenId);
    EXPECT_FALSE(result);
}

/*
 * Feature: UriPermissionManagerService
 * Function: IsDistributedSubDirUri
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService IsDistributedSubDirUri
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_IsDistributedSubDirUri_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    std::string inputUri = "";
    std::string cachedUri = "";
    auto result = upmsi->IsDistributedSubDirUri(inputUri, cachedUri);
    EXPECT_FALSE(result);
}

/*
 * Feature: UriPermissionManagerService
 * Function: IsDistributedSubDirUri
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService IsDistributedSubDirUri
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_IsDistributedSubDirUri_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    std::string inputUri = "file://home/user/shared_folder?networkid=12345";
    std::string cachedUri = "file://home/user?networkid=12345";
    auto result = upmsi->IsDistributedSubDirUri(inputUri, cachedUri);
    EXPECT_TRUE(result);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermission_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    MyFlag::isSystemAppCall_ = true;
    Uri uri("uri");
    uint32_t flag = 1;
    std::string targetBundleName = "targetBundleName";
    int32_t appIndex = 1;
    uint32_t initiatorTokenId = 1;
    int32_t funcResult;
    auto result = upmsi->GrantUriPermission(uri, flag, targetBundleName, appIndex, initiatorTokenId, funcResult);
    EXPECT_EQ(funcResult, ERR_CODE_INVALID_URI_TYPE);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermission_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    MyFlag::isSystemAppCall_ = false;
    Uri uri("file");
    uint32_t flag = 1;
    std::string targetBundleName = "targetBundleName";
    int32_t appIndex = 1;
    uint32_t initiatorTokenId = 1;
    int32_t funcResult = 0;
    auto result = upmsi->GrantUriPermission(uri, flag, targetBundleName, appIndex, initiatorTokenId, funcResult);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermission_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    std::vector<std::string> uriVec;
    uint32_t flag = 1;
    std::string targetBundleName = "targetBundleName";
    int32_t appIndex = 1;
    uint32_t initiatorTokenId = 1;
    int32_t funcResult = 1;
    auto result = upmsi->GrantUriPermission(uriVec, flag, targetBundleName, appIndex, initiatorTokenId, funcResult);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermission_004, TestSize.Level1)
{
#define ABILITY_RUNTIME_MEDIA_LIBRARY_ENABLE
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    std::vector<std::string> mediaUris;
    mediaUris.push_back("media://test");
    uint32_t flag = 1;
    uint32_t callerTokenId = 1;
    uint32_t targetTokenId = 1;
    int32_t hideSensitiveType = 1;
    auto result = upmsi->GrantBatchMediaUriPermissionImpl(
        mediaUris, flag, callerTokenId, targetTokenId, hideSensitiveType);
    EXPECT_EQ(result, -1);
#undef ABILITY_RUNTIME_MEDIA_LIBRARY_ENABLE
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantBatchUriPermissionImpl
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantBatchUriPermissionImpl
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantBatchUriPermissionImpl_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    std::vector<std::string> uriVec;
    uriVec.push_back("file://test");
    uint32_t flag = 1;
    TokenId callerTokenId = 1;
    TokenId targetTokenId = 1;
    auto result = upmsi->GrantBatchUriPermissionImpl(uriVec, flag, callerTokenId, targetTokenId);
    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: AddTempUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService AddTempUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_AddTempUriPermission_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    std::string uri = "file://test";
    uint32_t flag = 1;
    TokenId fromTokenId = 1;
    TokenId targetTokenId = 1;
    GrantInfo info = { flag, fromTokenId, targetTokenId };
    upmsi->uriMap_.insert({ uri, { info } });
    auto result = upmsi->AddTempUriPermission(uri, flag, fromTokenId, targetTokenId);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: AddTempUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService AddTempUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_AddTempUriPermission_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    std::string uri = "file://test";
    uint32_t flag = 1;
    TokenId fromTokenId = 1;
    TokenId targetTokenId = 1;
    GrantInfo info = { 0, 0, 0 };
    upmsi->uriMap_.insert({ uri, { info } });
    auto result = upmsi->AddTempUriPermission(uri, flag, fromTokenId, targetTokenId);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionPrivileged
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionPrivileged_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    std::vector<std::string> uriVec;
    uint32_t flag = 1;
    const std::string targetBundleName = "targetBundleName";
    int32_t appIndex = 1;
    uint32_t initiatorTokenId = 1;
    int32_t hideSensitiveType = 1;
    int32_t funcResult = ERR_CODE_INVALID_URI_TYPE;
    auto result = upmsi->GrantUriPermissionPrivileged(uriVec, flag, targetBundleName, appIndex, initiatorTokenId,
        hideSensitiveType, funcResult);
    EXPECT_EQ(funcResult, ERR_URI_LIST_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_URI_LIST_OUT_OF_RANGE);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionPrivileged
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionPrivileged_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    UriPermissionRawData rawData;
    rawData.data = nullptr;
    uint32_t flag = 1;
    const std::string targetBundleName = "";
    int32_t appIndex = 1;
    uint32_t initiatorTokenId = 1;
    int32_t hideSensitiveType = 1;
    int32_t funcResult = ERR_CODE_INVALID_URI_TYPE;
    auto result = upmsi->GrantUriPermissionPrivileged(rawData, flag, targetBundleName, appIndex, initiatorTokenId,
        hideSensitiveType, funcResult);
    EXPECT_EQ(funcResult, ERR_DEAD_OBJECT);
    EXPECT_EQ(result, ERR_DEAD_OBJECT);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionPrivilegedInner
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionPrivilegedInner
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionPrivilegedInner_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    Uri uri("content");
    std::vector<Uri> uriVec;
    uriVec.push_back(uri);
    uint32_t flag = 1;
    uint32_t callerTokenId = 1;
    uint32_t targetTokenId = 1;
    std::string targetAlterBundleName = "targetAlterBundleName";
    int32_t hideSensitiveType = 1;
    MyFlag::isUriTypeValid_ = true;
    MyFlag::isDocsCloudUri_ = true;
    std::string bundleName = "bundleName";
    FUDAppInfo callerInfo = { callerTokenId, "caller", "callerAlterName" };
    FUDAppInfo targetAppInfo = { targetTokenId, bundleName, targetAlterBundleName };
    std::vector<int32_t> permissionTypes(uriVec.size(), 0);
    auto result = upmsi->GrantUriPermissionPrivilegedInner(uriVec, flag, callerInfo, targetAppInfo,
        hideSensitiveType, permissionTypes);
    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionPrivilegedInner
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionPrivilegedInner
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionPrivilegedInner_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    Uri uri("uri://targetAlterBundleName");
    std::vector<Uri> uriVec;
    uriVec.push_back(uri);
    uint32_t flag = 1;
    uint32_t callerTokenId = 1;
    uint32_t targetTokenId = 1;
    std::string targetAlterBundleName = "targetAlterBundleName";
    int32_t hideSensitiveType = 1;
    MyFlag::isUriTypeValid_ = true;
    MyFlag::isDocsCloudUri_ = false;
    std::string bundleName = "bundleName";
    FUDAppInfo callerInfo = { callerTokenId, "caller", "callerAlterName" };
    FUDAppInfo targetAppInfo = { targetTokenId, bundleName, targetAlterBundleName };
    std::vector<int32_t> permissionTypes(uriVec.size(), 0);
    auto result = upmsi->GrantUriPermissionPrivilegedInner(uriVec, flag, callerInfo, targetAppInfo,
        hideSensitiveType, permissionTypes);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionPrivilegedInner
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionPrivilegedInner
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionPrivilegedInner_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    Uri uri("uri://media");
    std::vector<Uri> uriVec;
    uriVec.push_back(uri);
    uint32_t flag = 1;
    uint32_t callerTokenId = 1;
    uint32_t targetTokenId = 1;
    std::string targetAlterBundleName = "targetAlterBundleName";
    int32_t hideSensitiveType = 1;
    MyFlag::isUriTypeValid_ = true;
    MyFlag::isDocsCloudUri_ = false;
    std::string bundleName = "bundleName";
    FUDAppInfo callerInfo = { callerTokenId, "caller", "callerAlterName" };
    FUDAppInfo targetAppInfo = { targetTokenId, bundleName, targetAlterBundleName };
    std::vector<int32_t> permissionTypes(uriVec.size(), 0);
    auto result = upmsi->GrantUriPermissionPrivilegedInner(uriVec, flag, callerInfo, targetAppInfo,
        hideSensitiveType, permissionTypes);
    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckUriAuthorization
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckUriAuthorization
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckUriAuthorization_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    std::vector<std::string> uriStrVec;
    uint32_t flag = 1;
    uint32_t tokenId = 1;
    std::vector<bool> funcResult;
    auto result = upmsi->CheckUriAuthorization(uriStrVec, flag, tokenId, funcResult);
    EXPECT_EQ(result, ERR_URI_LIST_OUT_OF_RANGE);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckUriAuthorization
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckUriAuthorization
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckUriAuthorization_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    UriPermissionRawData rawData;
    rawData.data = nullptr;
    uint32_t flag = 1;
    uint32_t tokenId = 1;
    UriPermissionRawData funcResult;
    auto result = upmsi->CheckUriAuthorization(rawData, flag, tokenId, funcResult);
    EXPECT_EQ(result, ERR_DEAD_OBJECT);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeAllMapUriPermissions
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeAllMapUriPermissions
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeAllMapUriPermissions_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    MyFlag::bundleName_ = "callerAuthority";
    GrantInfo info = { 1, 1, 1 };
    upmsi->uriMap_.insert({ "uri://callerAuthority", { info } });
    uint32_t tokenId = 1;
    auto result = upmsi->RevokeAllMapUriPermissions(tokenId);
    EXPECT_EQ(result, 0);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeAllMapUriPermissions
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeAllMapUriPermissions
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeAllMapUriPermissions_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    MyFlag::bundleName_ = "bundleName";
    GrantInfo info = { 1, 1, 1 };
    upmsi->uriMap_.insert({ "uri://callerAuthority", { info } });
    uint32_t tokenId = 1;
    auto result = upmsi->RevokeAllMapUriPermissions(tokenId);
    EXPECT_EQ(upmsi->uriMap_.size(), 0);
    EXPECT_EQ(result, 0);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeUriPermissionManually
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeUriPermissionManually
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeUriPermissionManually_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    MyFlag::isSystemAppCall_ = true;
    MyFlag::isUriTypeValid_ = true;
    MyFlag::getTokenIdByBundleNameStatus_ = -1;
    Uri uri("uri");
    std::string bundleName = "bundleName";
    int32_t appIndex = 1;
    int32_t funcResult = 1;
    auto result = upmsi->RevokeUriPermissionManually(uri, bundleName, appIndex, funcResult);
    EXPECT_EQ(funcResult, -1);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeUriPermissionManuallyInner
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeUriPermissionManuallyInner
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeUriPermissionManuallyInner_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    upmsi->uriMap_.clear();
    Uri uri("uri://content");
    uint32_t targetTokenId = 1;
    MyFlag::isDocsCloudUri_ = true;
    auto result = upmsi->RevokeUriPermissionManuallyInner(uri, targetTokenId);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeUriPermissionManuallyInner
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeUriPermissionManuallyInner
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeUriPermissionManuallyInner_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    upmsi->uriMap_.clear();
    Uri uri("uri://media");
    uint32_t targetTokenId = 1;
    MyFlag::isDocsCloudUri_ = false;
    auto result = upmsi->RevokeUriPermissionManuallyInner(uri, targetTokenId);
    EXPECT_EQ(result, -1);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeMapUriPermissionManually
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeMapUriPermissionManually
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeMapUriPermissionManually_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    uint32_t callerTokenId = 1;
    uint32_t targetTokenId = 1;
    Uri uri("uri");
    upmsi->uriMap_.clear();
    auto result = upmsi->RevokeMapUriPermissionManually(callerTokenId, targetTokenId, uri);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeMapUriPermissionManually
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeMapUriPermissionManually
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeMapUriPermissionManually_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    uint32_t callerTokenId = 1;
    uint32_t targetTokenId = 1;
    Uri uri("uri");
    GrantInfo info = { 1, 1, 1 };
    upmsi->uriMap_.clear();
    upmsi->uriMap_.insert({ uri.ToString(), { info } });
    auto result = upmsi->RevokeMapUriPermissionManually(callerTokenId, targetTokenId, uri);
    EXPECT_EQ(upmsi->uriMap_.size(), 0);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: ClearPermissionTokenByMap
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService ClearPermissionTokenByMap
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_ClearPermissionTokenByMap_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    uint32_t tokenId = 0;
    int32_t funcResult = 0;
    auto result = upmsi->ClearPermissionTokenByMap(tokenId, funcResult);
    EXPECT_EQ(funcResult, ERR_PERMISSION_DENIED);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: BoolVecToCharVec
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService BoolVecToCharVec
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_BoolVecToCharVec_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    std::vector<bool> boolVector;
    std::vector<char> charVector;
    upmsi->BoolVecToCharVec(boolVector, charVector);
    EXPECT_EQ(charVector.size(), 0);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RawDataToStringVec
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RawDataToStringVec
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RawDataToStringVec_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    UriPermissionRawData rawData;
    rawData.data = nullptr;
    std::vector<std::string> stringVec;
    auto result = upmsi->RawDataToStringVec(rawData, stringVec);
    EXPECT_EQ(result, ERR_DEAD_OBJECT);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RawDataToStringVec
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RawDataToStringVec
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RawDataToStringVec_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    UriPermissionRawData rawData;
    rawData.data = upmsi.get();
    rawData.size = 0;
    std::vector<std::string> stringVec;
    auto result = upmsi->RawDataToStringVec(rawData, stringVec);
    EXPECT_EQ(result, ERR_DEAD_OBJECT);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RawDataToStringVec
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RawDataToStringVec
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RawDataToStringVec_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    auto &upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    std::vector<std::string> strArray;
    strArray.emplace_back(POLICY_INFO_PATH);
    UriPermissionRawData rawData;
    upmc.StringVecToRawData(strArray, rawData);
    rawData.size -= OFFSET;
    UriPermissionRawData stubRawData;
    stubRawData.size = rawData.size;
    EXPECT_EQ(stubRawData.RawDataCpy(rawData.data), ERR_NONE);
    std::vector<std::string> stringVec;
    auto result = upmsi->RawDataToStringVec(stubRawData, stringVec);
    EXPECT_EQ(result, ERR_DEAD_OBJECT);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RawDataToPolicyInfo
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RawDataToPolicyInfo
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RawDataToPolicyInfo_001, TestSize.Level1)
{
#ifdef ABILITY_RUNTIME_FEATURE_SANDBOXMANAGER
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    auto &upmc = AAFwk::UriPermissionManagerClient::GetInstance();
    PolicyInfo policyInfo;
    policyInfo.path = POLICY_INFO_PATH;
    policyInfo.mode = 1;
    std::vector<PolicyInfo> policyInfoArray;
    policyInfoArray.push_back(policyInfo);
    UriPermissionRawData policyRawData;
    upmc.PolicyInfoToRawData(policyInfoArray, policyRawData);
    policyRawData.size -= OFFSET;
    UriPermissionRawData stubPolicyRawData;
    stubPolicyRawData.size = policyRawData.size;
    EXPECT_EQ(stubPolicyRawData.RawDataCpy(policyRawData.data), ERR_NONE);
    std::vector<PolicyInfo> policy;
    auto result = upmsi->RawDataToPolicyInfo(stubPolicyRawData, policy);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
#endif
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionWithType
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionWithType
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionWithType_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = false;
    std::vector<Uri> uriVec = { Uri("file://test.txt") };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    std::string targetBundleName = "com.example.app";
    int32_t appIndex = 0;
    uint32_t initiatorTokenId = 1000;
    int32_t hideSensitiveType = 0;
    std::vector<int32_t> permissionTypes = { 0 };
    int32_t funcResult = 0;

    auto result = upmsi->GrantUriPermissionWithType(uriVec, flag, targetBundleName, appIndex, initiatorTokenId,
        hideSensitiveType, permissionTypes, funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionWithType
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionWithType
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionWithType_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    std::vector<Uri> emptyUriVec;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    std::string targetBundleName = "com.example.app";
    int32_t appIndex = 0;
    uint32_t initiatorTokenId = 1000;
    int32_t hideSensitiveType = 0;
    std::vector<int32_t> permissionTypes;
    int32_t funcResult = 0;

    auto result = upmsi->GrantUriPermissionWithType(emptyUriVec, flag, targetBundleName, appIndex, initiatorTokenId,
        hideSensitiveType, permissionTypes, funcResult);
    EXPECT_EQ(funcResult, ERR_URI_LIST_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionWithType
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionWithType
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionWithType_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    std::vector<Uri> largeUriVec(200001, Uri("file://test.txt"));
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    std::string targetBundleName = "com.example.app";
    int32_t appIndex = 0;
    uint32_t initiatorTokenId = 1000;
    int32_t hideSensitiveType = 0;
    std::vector<int32_t> permissionTypes(200001, 0);
    int32_t funcResult = 0;

    auto result = upmsi->GrantUriPermissionWithType(largeUriVec, flag, targetBundleName, appIndex, initiatorTokenId,
        hideSensitiveType, permissionTypes, funcResult);
    EXPECT_EQ(funcResult, ERR_URI_LIST_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionWithType
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionWithType
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionWithType_004, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    std::vector<Uri> uriVec = { Uri("file://test1.txt"), Uri("file://test2.txt") };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    std::string targetBundleName = "com.example.app";
    int32_t appIndex = 0;
    uint32_t initiatorTokenId = 1000;
    int32_t hideSensitiveType = 0;
    std::vector<int32_t> permissionTypes = { 0 };
    int32_t funcResult = 0;

    auto result = upmsi->GrantUriPermissionWithType(uriVec, flag, targetBundleName, appIndex, initiatorTokenId,
        hideSensitiveType, permissionTypes, funcResult);
    EXPECT_EQ(funcResult, ERR_URI_LIST_OUT_OF_RANGE);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionWithType
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionWithType
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionWithType_005, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    std::vector<Uri> uriVec = { Uri("file://test.txt") };
    uint32_t flag = 0;
    std::string targetBundleName = "com.example.app";
    int32_t appIndex = 0;
    uint32_t initiatorTokenId = 1000;
    int32_t hideSensitiveType = 0;
    std::vector<int32_t> permissionTypes = { 0 };
    int32_t funcResult = 0;

    auto result = upmsi->GrantUriPermissionWithType(uriVec, flag, targetBundleName, appIndex, initiatorTokenId,
        hideSensitiveType, permissionTypes, funcResult);
    EXPECT_EQ(funcResult, ERR_CODE_INVALID_URI_FLAG);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionWithType
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionWithType
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionWithType_006, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    std::vector<Uri> uriVec = { Uri("file://test.txt") };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    std::string targetBundleName = "com.example.app";
    int32_t appIndex = 0;
    uint32_t initiatorTokenId = 0;
    int32_t hideSensitiveType = 0;
    std::vector<int32_t> permissionTypes = { 0 };
    int32_t funcResult = 0;

    auto result = upmsi->GrantUriPermissionWithType(uriVec, flag, targetBundleName, appIndex, initiatorTokenId,
        hideSensitiveType, permissionTypes, funcResult);
    EXPECT_EQ(funcResult, ERR_UPMS_INVALID_CALLER_TOKENID);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionWithType
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionWithType
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionWithType_007, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    std::vector<Uri> uriVec = { Uri("file://test.txt") };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    std::string targetBundleName = "com.example.app";
    int32_t appIndex = 0;
    uint32_t initiatorTokenId = 1000;
    int32_t hideSensitiveType = 0;
    std::vector<int32_t> permissionTypes = { 0 };
    int32_t funcResult = 0;

    MyFlag::getTokenIdByBundleNameStatus_ = -1;

    auto result = upmsi->GrantUriPermissionWithType(uriVec, flag, targetBundleName, appIndex, initiatorTokenId,
        hideSensitiveType, permissionTypes, funcResult);
    EXPECT_EQ(funcResult, -1);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionWithType
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionWithType
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionWithType_008, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    MyFlag::getTokenIdByBundleNameStatus_ = 0;
    MyFlag::isUriTypeValid_ = true;

    std::vector<Uri> uriVec = { Uri("file://targetAlterBundleName/test.txt") };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    std::string targetBundleName = "com.example.app";
    int32_t appIndex = 0;
    uint32_t initiatorTokenId = 1000;
    int32_t hideSensitiveType = 0;
    std::vector<int32_t> permissionTypes = { 0 };
    int32_t funcResult = 0;

    MyFlag::upmsUtilsGetDirByBundleNameAndAppIndexRet_ = true;

    auto result = upmsi->GrantUriPermissionWithType(uriVec, flag, targetBundleName, appIndex, initiatorTokenId,
        hideSensitiveType, permissionTypes, funcResult);

    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionByKeyAsCaller
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionByKeyAsCaller
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionByKeyAsCaller_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::string key = "test_key";
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t callerTokenId = 1000;
    uint32_t targetTokenId = 1001;
    int32_t funcResult = 0;

    MyFlag::isSystemAppCall_ = false;

    auto result = upmsi->GrantUriPermissionByKeyAsCaller(key, flag, callerTokenId, targetTokenId, funcResult);
    EXPECT_EQ(funcResult, ERR_NOT_SYSTEM_APP);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionByKeyAsCaller
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionByKeyAsCaller
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionByKeyAsCaller_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::string key = "test_key";
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t callerTokenId = 1000;
    uint32_t targetTokenId = 1001;
    int32_t funcResult = 0;

    MyFlag::isSystemAppCall_ = true;
    MyFlag::permissionGrantUriPermissionAsCaller_ = false;

    auto result = upmsi->GrantUriPermissionByKeyAsCaller(key, flag, callerTokenId, targetTokenId, funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionByKeyAsCaller
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionByKeyAsCaller
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionByKeyAsCaller_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::string key = "test_key";
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t callerTokenId = 1000;
    uint32_t targetTokenId = 1001;
    int32_t funcResult = 0;

    MyFlag::isSystemAppCall_ = true;
    MyFlag::permissionGrantUriPermissionAsCaller_ = true;
    MyFlag::isSandboxAppRet_ = true;

    auto result = upmsi->GrantUriPermissionByKeyAsCaller(key, flag, callerTokenId, targetTokenId, funcResult);

    EXPECT_NE(funcResult, ERR_OK);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionByKey
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionByKey
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionByKey_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::string key = "test_key";
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t targetTokenId = 1001;
    int32_t funcResult = 0;

    MyFlag::isSystemAppCall_ = false;

    auto result = upmsi->GrantUriPermissionByKey(key, flag, targetTokenId, funcResult);
    EXPECT_EQ(funcResult, ERR_NOT_SYSTEM_APP);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionByKey
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionByKey
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionByKey_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::string key = "test_key";
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t targetTokenId = 1001;
    int32_t funcResult = 0;

    MyFlag::isSystemAppCall_ = true;
    MyFlag::isSandboxAppRet_ = true;

    auto result = upmsi->GrantUriPermissionByKey(key, flag, targetTokenId, funcResult);
    EXPECT_EQ(funcResult, ERR_CODE_GRANT_URI_PERMISSION);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionByKey
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionByKey
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionByKey_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::string key = "test_key";
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t targetTokenId = 1001;
    int32_t funcResult = 0;

    MyFlag::isSystemAppCall_ = true;
    MyFlag::isSandboxAppRet_ = false;
    MyFlag::fudUtilsGenerateFUDAppInfoRet_ = false;

    auto result = upmsi->GrantUriPermissionByKey(key, flag, targetTokenId, funcResult);
    EXPECT_EQ(funcResult, INNER_ERR);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckUriAuthorizationWithType
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckUriAuthorizationWithType
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckUriAuthorizationWithType_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = false;
    std::vector<std::string> uriVec = { "file://test.txt" };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;
    std::vector<CheckResult> funcResult;

    auto result = upmsi->CheckUriAuthorizationWithType(uriVec, flag, tokenId, funcResult);
    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckUriAuthorizationWithType
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckUriAuthorizationWithType
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckUriAuthorizationWithType_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    std::vector<std::string> emptyVec;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;
    std::vector<CheckResult> funcResult;

    auto result = upmsi->CheckUriAuthorizationWithType(emptyVec, flag, tokenId, funcResult);
    EXPECT_EQ(result, ERR_URI_LIST_OUT_OF_RANGE);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckUriAuthorizationWithType
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckUriAuthorizationWithType
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckUriAuthorizationWithType_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    std::vector<std::string> largeVec(200001, "file://test.txt");
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;
    std::vector<CheckResult> funcResult;

    auto result = upmsi->CheckUriAuthorizationWithType(largeVec, flag, tokenId, funcResult);
    EXPECT_EQ(result, ERR_URI_LIST_OUT_OF_RANGE);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckUriAuthorizationWithType
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckUriAuthorizationWithType
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckUriAuthorizationWithType_004, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    std::vector<std::string> uriVec = { "file://test.txt" };
    uint32_t flag = 0;
    uint32_t tokenId = 1000;
    std::vector<CheckResult> funcResult;

    auto result = upmsi->CheckUriAuthorizationWithType(uriVec, flag, tokenId, funcResult);
    EXPECT_EQ(result, ERR_CODE_INVALID_URI_FLAG);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckUriAuthorizationWithType
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckUriAuthorizationWithType
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckUriAuthorizationWithType_005, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    std::vector<std::string> uriVec = { "file://test.txt" };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 0;
    std::vector<CheckResult> funcResult;

    auto result = upmsi->CheckUriAuthorizationWithType(uriVec, flag, tokenId, funcResult);
    EXPECT_EQ(result, ERR_UPMS_INVALID_CALLER_TOKENID);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckUriAuthorizationWithType
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckUriAuthorizationWithType
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckUriAuthorizationWithType_006, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    std::vector<std::string> uriVec = { "file://test.txt" };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;
    std::vector<CheckResult> funcResult;

    auto result = upmsi->CheckUriAuthorizationWithType(uriVec, flag, tokenId, funcResult);

    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeAllUriPermissions
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeAllUriPermissions
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeAllUriPermissions_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = false;
    uint32_t tokenId = 1000;
    int32_t funcResult = 0;

    auto result = upmsi->RevokeAllUriPermissions(tokenId, funcResult);
    EXPECT_EQ(funcResult, CHECK_PERMISSION_FAILED);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeAllUriPermissions
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeAllUriPermissions
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeAllUriPermissions_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    uint32_t tokenId = 1000;
    int32_t funcResult = -1;

    upmsi->AddContentTokenIdRecord(tokenId);

    auto result = upmsi->RevokeAllUriPermissions(tokenId, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeAllUriPermissions
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeAllUriPermissions
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeAllUriPermissions_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    uint32_t tokenId = 1000;
    int32_t funcResult = 0;

    upmsi->permissionTokenMap_.insert(tokenId);

    GrantInfo info = { Want::FLAG_AUTH_READ_URI_PERMISSION, 999, tokenId };
    upmsi->uriMap_["file://test.txt"] = { info };

    auto result = upmsi->RevokeAllUriPermissions(tokenId, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(upmsi->uriMap_.empty());
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeAllUriPermissions
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeAllUriPermissions
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeAllUriPermissions_004, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    uint32_t tokenId = 1000;
    int32_t funcResult = 0;

    GrantPolicyInfo policyInfo = { 999, tokenId };
    upmsi->policyMap_["/data/storage/test.txt"] = { policyInfo };

    auto result = upmsi->RevokeAllUriPermissions(tokenId, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(upmsi->policyMap_.empty());
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeAllUriPermissions
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeAllUriPermissions
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeAllUriPermissions_005, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::upmsUtilsIsFoundationCallRet_ = true;
    MyFlag::bundleName_ = "callerAuthority";
    uint32_t tokenId = 1000;
    int32_t funcResult = 0;

    GrantInfo info = { Want::FLAG_AUTH_READ_URI_PERMISSION, tokenId, 1001 };
    upmsi->uriMap_["uri://callerAuthority/test.txt"] = { info };

    auto result = upmsi->RevokeAllUriPermissions(tokenId, funcResult);
    EXPECT_EQ(funcResult, ERR_OK);
    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(upmsi->uriMap_.empty());
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifyUriPermissionInner
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifyUriPermissionInner
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifyUriPermissionInner_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    Uri uri("file://com.example.app/test.txt");
    uint32_t flag = 0;
    uint32_t tokenId = 1000;

    auto result = upmsi->VerifyUriPermissionInner(uri, flag, tokenId);
    EXPECT_FALSE(result);
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifyUriPermissionInner
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifyUriPermissionInner
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifyUriPermissionInner_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    Uri uri("http://example.com/test.txt");
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;

    auto result = upmsi->VerifyUriPermissionInner(uri, flag, tokenId);
    EXPECT_FALSE(result);
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifyUriPermissionInner
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifyUriPermissionInner
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifyUriPermissionInner_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    Uri uri("file://media/test.jpg");
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;

    auto result = upmsi->VerifyUriPermissionInner(uri, flag, tokenId);
    EXPECT_FALSE(result);
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifyUriPermissionInner
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifyUriPermissionInner
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifyUriPermissionInner_004, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::isDocsCloudUri_ = true;
    Uri uri("file://docs/test.txt?networkid=123");
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;

    GrantInfo info = { Want::FLAG_AUTH_READ_URI_PERMISSION, 999, tokenId };
    upmsi->uriMap_[uri.ToString()] = { info };

    auto result = upmsi->VerifyUriPermissionInner(uri, flag, tokenId);

    EXPECT_TRUE(result);
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifyUriPermissionInner
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifyUriPermissionInner
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifyUriPermissionInner_005, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::isDocsCloudUri_ = false;
    Uri uri("file://com.example.app/test.txt");
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;

    auto result = upmsi->VerifyUriPermissionInner(uri, flag, tokenId);

    EXPECT_FALSE(result);
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifyUriPermissionByPolicy
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifyUriPermissionByPolicy
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifyUriPermissionByPolicy_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<PolicyInfo> emptyVec;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;

    auto result = upmsi->VerifyUriPermissionByPolicy(emptyVec, flag, tokenId);
    EXPECT_TRUE(result.empty());
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifyUriPermissionByPolicy
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifyUriPermissionByPolicy
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifyUriPermissionByPolicy_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    PolicyInfo policy;
    policy.path = "/data/storage/el2/base/test.txt";
    policy.mode = 1;
    std::vector<PolicyInfo> policyVec = { policy };

    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;

    auto result = upmsi->VerifyUriPermissionByPolicy(policyVec, flag, tokenId);

    EXPECT_EQ(result.size(), 1);
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifyUriPermissionByPolicy
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifyUriPermissionByPolicy
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifyUriPermissionByPolicy_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    PolicyInfo policy1;
    policy1.path = "/data/storage/el2/base/test1.txt";
    policy1.mode = 1;

    PolicyInfo policy2;
    policy2.path = "/data/storage/el2/base/test2.txt";
    policy2.mode = 2;

    std::vector<PolicyInfo> policyVec = { policy1, policy2 };

    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION | Want::FLAG_AUTH_WRITE_URI_PERMISSION;
    uint32_t tokenId = 1000;

    auto result = upmsi->VerifyUriPermissionByPolicy(policyVec, flag, tokenId);
    EXPECT_EQ(result.size(), policyVec.size());
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifyUriPermissionByMap
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifyUriPermissionByMap
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifyUriPermissionByMap_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<Uri> emptyVec;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;

    auto result = upmsi->VerifyUriPermissionByMap(emptyVec, flag, tokenId);
    EXPECT_TRUE(result.empty());
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifyUriPermissionByMap
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifyUriPermissionByMap
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifyUriPermissionByMap_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<Uri> uriVec;
    uriVec.push_back(Uri("file://docs/test1.txt"));

    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;

    GrantInfo info = { Want::FLAG_AUTH_READ_URI_PERMISSION, 999, tokenId };
    upmsi->uriMap_["file://docs/test1.txt"] = { info };

    auto result = upmsi->VerifyUriPermissionByMap(uriVec, flag, tokenId);
    EXPECT_EQ(result.size(), 1);
    EXPECT_TRUE(result[0]);
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifyUriPermissionByMap
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifyUriPermissionByMap
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifyUriPermissionByMap_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<Uri> uriVec;
    uriVec.push_back(Uri("file://docs/test1.txt"));
    uriVec.push_back(Uri("file://docs/test2.txt"));
    uriVec.push_back(Uri("file://docs/test3.txt"));

    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;

    GrantInfo info1 = { Want::FLAG_AUTH_READ_URI_PERMISSION, 999, tokenId };
    GrantInfo info2 = { Want::FLAG_AUTH_WRITE_URI_PERMISSION, 999, tokenId };

    upmsi->uriMap_["file://docs/test1.txt"] = { info1 };
    upmsi->uriMap_["file://docs/test3.txt"] = { info2 };

    auto result = upmsi->VerifyUriPermissionByMap(uriVec, flag, tokenId);
    EXPECT_EQ(result.size(), 3);
    EXPECT_TRUE(result[0]);
    EXPECT_FALSE(result[1]);

    EXPECT_TRUE(result[2]);
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifySingleUriPermissionByMap
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifySingleUriPermissionByMap
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifySingleUriPermissionByMap_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::string uriStr = "file://docs/notfound.txt";
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;

    upmsi->uriMap_.clear();
    auto result = upmsi->VerifySingleUriPermissionByMap(uriStr, flag, tokenId);
    EXPECT_FALSE(result);
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifySingleUriPermissionByMap
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifySingleUriPermissionByMap
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifySingleUriPermissionByMap_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::string uriStr = "file://docs/test.txt";
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;

    GrantInfo info = { Want::FLAG_AUTH_READ_URI_PERMISSION, 999, tokenId };
    upmsi->uriMap_[uriStr] = { info };

    auto result = upmsi->VerifySingleUriPermissionByMap(uriStr, flag, tokenId);
    EXPECT_TRUE(result);
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifySingleUriPermissionByMap
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifySingleUriPermissionByMap
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifySingleUriPermissionByMap_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::string uriStr = "file://docs/test.txt";
    uint32_t flag = Want::FLAG_AUTH_WRITE_URI_PERMISSION;
    uint32_t tokenId = 1000;

    GrantInfo info = { Want::FLAG_AUTH_READ_URI_PERMISSION, 999, tokenId };
    upmsi->uriMap_[uriStr] = { info };

    auto result = upmsi->VerifySingleUriPermissionByMap(uriStr, flag, tokenId);
    EXPECT_FALSE(result);
}

/*
 * Feature: UriPermissionManagerService
 * Function: VerifySingleUriPermissionByMap
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService VerifySingleUriPermissionByMap
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_VerifySingleUriPermissionByMap_004, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::string uriStr = "file://docs/test.txt";
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t tokenId = 1000;

    GrantInfo info1 = { Want::FLAG_AUTH_READ_URI_PERMISSION, 999, 9999 };
    GrantInfo info2 = { Want::FLAG_AUTH_READ_URI_PERMISSION, 999, tokenId };
    GrantInfo info3 = { Want::FLAG_AUTH_WRITE_URI_PERMISSION, 999, tokenId };
    
    upmsi->uriMap_[uriStr] = { info1, info2, info3 };

    auto result = upmsi->VerifySingleUriPermissionByMap(uriStr, flag, tokenId);
    EXPECT_TRUE(result);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckGrantUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckGrantUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckGrantUriPermission_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::isSAOrSystemAppCall_ = false;
    std::vector<std::string> uriVec = { "file://test.txt" };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    std::string targetBundleName = "com.example.app";
    int32_t appIndex = 0;

    auto result = upmsi->CheckGrantUriPermission(uriVec, flag, targetBundleName, appIndex);
    EXPECT_EQ(result, ERR_NOT_SYSTEM_APP);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckGrantUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckGrantUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckGrantUriPermission_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::isSAOrSystemAppCall_ = true;
    MyFlag::isSandboxAppRet_ = true;
    std::vector<std::string> uriVec = { "file://test.txt" };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    std::string targetBundleName = "com.example.app";
    int32_t appIndex = 0;

    auto result = upmsi->CheckGrantUriPermission(uriVec, flag, targetBundleName, appIndex);
    EXPECT_EQ(result, ERR_CODE_GRANT_URI_PERMISSION);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckGrantUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckGrantUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckGrantUriPermission_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::isSAOrSystemAppCall_ = true;
    MyFlag::isSandboxAppRet_ = false;
    std::vector<std::string> emptyVec;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    std::string targetBundleName = "com.example.app";
    int32_t appIndex = 0;

    auto result = upmsi->CheckGrantUriPermission(emptyVec, flag, targetBundleName, appIndex);
    EXPECT_EQ(result, ERR_URI_LIST_OUT_OF_RANGE);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckGrantUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckGrantUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckGrantUriPermission_004, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::isSAOrSystemAppCall_ = true;
    MyFlag::isSandboxAppRet_ = false;
    std::vector<std::string> largeVec(200001, "file://test.txt");
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    std::string targetBundleName = "com.example.app";
    int32_t appIndex = 0;

    auto result = upmsi->CheckGrantUriPermission(largeVec, flag, targetBundleName, appIndex);
    EXPECT_EQ(result, ERR_URI_LIST_OUT_OF_RANGE);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckGrantUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckGrantUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckGrantUriPermission_005, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::isSAOrSystemAppCall_ = true;
    MyFlag::isSandboxAppRet_ = false;
    std::vector<std::string> uriVec = { "file://test.txt" };
    uint32_t flag = 0;
    std::string targetBundleName = "com.example.app";
    int32_t appIndex = 0;

    auto result = upmsi->CheckGrantUriPermission(uriVec, flag, targetBundleName, appIndex);
    EXPECT_EQ(result, ERR_CODE_INVALID_URI_FLAG);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckGrantUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckGrantUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckGrantUriPermission_006, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::isSAOrSystemAppCall_ = true;
    MyFlag::isSandboxAppRet_ = false;
    std::vector<std::string> uriVec = { "file://test.txt" };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    std::string targetBundleName = "com.example.app";
    int32_t appIndex = 0;

    auto result = upmsi->CheckGrantUriPermission(uriVec, flag, targetBundleName, appIndex);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionInner
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionInner
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionInner_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    BatchUri batchUri;

    std::vector<std::string> uriVec = { "file://test.txt" };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    FUDAppInfo callerInfo = { 1000, "caller", "callerAlter" };
    FUDAppInfo targetInfo = { 1001, "target", "targetAlter" };

    auto result = upmsi->GrantUriPermissionInner(batchUri, uriVec, flag, callerInfo, targetInfo);

    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionInner
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionInner
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionInner_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    BatchUri batchUri;

    std::vector<std::string> uriVec = { "file://test.txt" };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    FUDAppInfo callerInfo = { 1000, "caller", "callerAlter" };
    FUDAppInfo targetInfo = { 1001, "target", "targetAlter" };

    auto result = upmsi->GrantUriPermissionInner(batchUri, uriVec, flag, callerInfo, targetInfo);

    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantBatchMediaUriPermissionImpl
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantBatchMediaUriPermissionImpl
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantBatchMediaUriPermissionImpl_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<std::string> emptyVec;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t callerTokenId = 1000;
    uint32_t targetTokenId = 1001;
    int32_t hideSensitiveType = 0;

    auto result = upmsi->GrantBatchMediaUriPermissionImpl(emptyVec, flag, callerTokenId, targetTokenId,
        hideSensitiveType);
    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantBatchMediaUriPermissionImpl
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantBatchMediaUriPermissionImpl
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantBatchMediaUriPermissionImpl_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();
    std::vector<std::string> mediaUris = { "file://media/test.jpg" };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t callerTokenId = 1000;
    uint32_t targetTokenId = 1001;
    int32_t hideSensitiveType = 0;

    auto result = upmsi->GrantBatchMediaUriPermissionImpl(mediaUris, flag, callerTokenId, targetTokenId,
        hideSensitiveType);

    EXPECT_EQ(result, -1);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantBatchUriPermissionImplByPolicy
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantBatchUriPermissionImplByPolicy
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantBatchUriPermissionImplByPolicy_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<PolicyInfo> emptyVec;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    FUDAppInfo callerInfo = { 1000, "caller", "callerAlter" };
    FUDAppInfo targetInfo = { 1001, "target", "targetAlter" };

    auto result = upmsi->GrantBatchUriPermissionImplByPolicy(emptyVec, flag, callerInfo, targetInfo);
    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantBatchUriPermissionImplByPolicy
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantBatchUriPermissionImplByPolicy
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantBatchUriPermissionImplByPolicy_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    PolicyInfo policy;
    policy.path = "/data/storage/el2/base/test.txt";
    policy.mode = 1;
    std::vector<PolicyInfo> policyVec = { policy };

    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    FUDAppInfo callerInfo = { 1000, "caller", "callerAlter" };
    FUDAppInfo targetInfo = { 1001, "target", "targetAlter" };

    auto result = upmsi->GrantBatchUriPermissionImplByPolicy(policyVec, flag, callerInfo, targetInfo);

    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantBatchContentUriPermissionImpl
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantBatchContentUriPermissionImpl
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantBatchContentUriPermissionImpl_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<std::string> emptyVec;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t targetTokenId = 1001;
    std::string targetBundleName = "com.example.app";

    auto result = upmsi->GrantBatchContentUriPermissionImpl(emptyVec, flag, targetTokenId, targetBundleName);
    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantBatchContentUriPermissionImpl
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantBatchContentUriPermissionImpl
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantBatchContentUriPermissionImpl_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<std::string> contentUris = { "content://test" };
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t targetTokenId = 1001;
    std::string targetBundleName = "com.example.app";

    auto result = upmsi->GrantBatchContentUriPermissionImpl(contentUris, flag, targetTokenId, targetBundleName);

    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeContentUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeContentUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeContentUriPermission_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    auto result = upmsi->RevokeContentUriPermission(tokenId);
    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: IsContentUriGranted
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService IsContentUriGranted
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_IsContentUriGranted_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    auto result = upmsi->IsContentUriGranted(tokenId);
    EXPECT_FALSE(result);
}

/*
 * Feature: UriPermissionManagerService
 * Function: IsContentUriGranted
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService IsContentUriGranted
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_IsContentUriGranted_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    upmsi->contentTokenIdSet_.insert(tokenId);

    auto result = upmsi->IsContentUriGranted(tokenId);
    EXPECT_TRUE(result);
}

/*
 * Feature: UriPermissionManagerService
 * Function: IsContentUriGranted
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService IsContentUriGranted
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_IsContentUriGranted_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId1 = 1000;
    uint32_t tokenId2 = 1001;
    uint32_t tokenId3 = 1002;

    upmsi->contentTokenIdSet_.insert(tokenId1);
    upmsi->contentTokenIdSet_.insert(tokenId2);
    upmsi->contentTokenIdSet_.insert(tokenId3);

    EXPECT_TRUE(upmsi->IsContentUriGranted(tokenId1));
    EXPECT_TRUE(upmsi->IsContentUriGranted(tokenId2));
    EXPECT_TRUE(upmsi->IsContentUriGranted(tokenId3));
    EXPECT_FALSE(upmsi->IsContentUriGranted(9999));
}

/*
 * Feature: UriPermissionManagerService
 * Function: AddContentTokenIdRecord
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService AddContentTokenIdRecord
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_AddContentTokenIdRecord_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    EXPECT_FALSE(upmsi->IsContentUriGranted(tokenId));
    upmsi->AddContentTokenIdRecord(tokenId);
    EXPECT_TRUE(upmsi->IsContentUriGranted(tokenId));
}

/*
 * Feature: UriPermissionManagerService
 * Function: AddContentTokenIdRecord
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService AddContentTokenIdRecord
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_AddContentTokenIdRecord_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    upmsi->AddContentTokenIdRecord(tokenId);
    EXPECT_TRUE(upmsi->IsContentUriGranted(tokenId));

    upmsi->AddContentTokenIdRecord(tokenId);
    EXPECT_TRUE(upmsi->IsContentUriGranted(tokenId));

    EXPECT_EQ(upmsi->contentTokenIdSet_.size(), 1);
}

/*
 * Feature: UriPermissionManagerService
 * Function: AddContentTokenIdRecord
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService AddContentTokenIdRecord
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_AddContentTokenIdRecord_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId1 = 1000;
    uint32_t tokenId2 = 1001;
    uint32_t tokenId3 = 1002;

    upmsi->AddContentTokenIdRecord(tokenId1);
    upmsi->AddContentTokenIdRecord(tokenId2);
    upmsi->AddContentTokenIdRecord(tokenId3);

    EXPECT_TRUE(upmsi->IsContentUriGranted(tokenId1));
    EXPECT_TRUE(upmsi->IsContentUriGranted(tokenId2));
    EXPECT_TRUE(upmsi->IsContentUriGranted(tokenId3));
    EXPECT_EQ(upmsi->contentTokenIdSet_.size(), 3);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RemoveContentTokenIdRecord
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RemoveContentTokenIdRecord
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RemoveContentTokenIdRecord_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    upmsi->AddContentTokenIdRecord(tokenId);
    EXPECT_TRUE(upmsi->IsContentUriGranted(tokenId));

    upmsi->RemoveContentTokenIdRecord(tokenId);
    EXPECT_FALSE(upmsi->IsContentUriGranted(tokenId));
}

/*
 * Feature: UriPermissionManagerService
 * Function: RemoveContentTokenIdRecord
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RemoveContentTokenIdRecord
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RemoveContentTokenIdRecord_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    EXPECT_FALSE(upmsi->IsContentUriGranted(tokenId));

    upmsi->RemoveContentTokenIdRecord(tokenId);
    EXPECT_FALSE(upmsi->IsContentUriGranted(tokenId));
}

/*
 * Feature: UriPermissionManagerService
 * Function: RemoveContentTokenIdRecord
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RemoveContentTokenIdRecord
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RemoveContentTokenIdRecord_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId1 = 1000;
    uint32_t tokenId2 = 1001;
    uint32_t tokenId3 = 1002;

    upmsi->AddContentTokenIdRecord(tokenId1);
    upmsi->AddContentTokenIdRecord(tokenId2);
    upmsi->AddContentTokenIdRecord(tokenId3);

    upmsi->RemoveContentTokenIdRecord(tokenId2);

    EXPECT_TRUE(upmsi->IsContentUriGranted(tokenId1));
    EXPECT_FALSE(upmsi->IsContentUriGranted(tokenId2));
    EXPECT_TRUE(upmsi->IsContentUriGranted(tokenId3));
    EXPECT_EQ(upmsi->contentTokenIdSet_.size(), 2);
}

/*
 * Feature: UriPermissionManagerService
 * Function: AddPolicyRecordCache
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService AddPolicyRecordCache
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_AddPolicyRecordCache_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t callerTokenId = 1000;
    uint32_t targetTokenId = 1001;
    std::string path = "/data/storage/test.txt";

    upmsi->policyMap_.clear();

    MyFlag::isUdmfOrPasteboardCallRet_ = false;

    upmsi->AddPolicyRecordCache(callerTokenId, targetTokenId, path);

    EXPECT_EQ(upmsi->policyMap_.size(), 1);
    EXPECT_TRUE(upmsi->policyMap_.count(path));
    EXPECT_EQ(upmsi->policyMap_[path].size(), 1);
    EXPECT_TRUE(upmsi->policyMap_[path].front().Equal(callerTokenId, targetTokenId));
}

/*
 * Feature: UriPermissionManagerService
 * Function: AddPolicyRecordCache
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService AddPolicyRecordCache
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_AddPolicyRecordCache_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t callerTokenId = 1000;
    uint32_t targetTokenId = 1001;
    std::string path = "/data/storage/test.txt";

    upmsi->policyMap_.clear();

    upmsi->AddPolicyRecordCache(callerTokenId, targetTokenId, path);

    upmsi->AddPolicyRecordCache(callerTokenId, targetTokenId, path);

    EXPECT_EQ(upmsi->policyMap_.size(), 1);
    EXPECT_EQ(upmsi->policyMap_[path].size(), 1);
}

/*
 * Feature: UriPermissionManagerService
 * Function: AddPolicyRecordCache
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService AddPolicyRecordCache
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_AddPolicyRecordCache_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t callerTokenId1 = 1000;
    uint32_t targetTokenId1 = 1001;
    uint32_t callerTokenId2 = 1002;
    uint32_t targetTokenId2 = 1003;
    std::string path = "/data/storage/test.txt";

    upmsi->policyMap_.clear();

    upmsi->AddPolicyRecordCache(callerTokenId1, targetTokenId1, path);

    upmsi->AddPolicyRecordCache(callerTokenId2, targetTokenId2, path);

    EXPECT_EQ(upmsi->policyMap_.size(), 1);
    EXPECT_TRUE(upmsi->policyMap_.count(path));
    EXPECT_EQ(upmsi->policyMap_[path].size(), 2);
}

/*
 * Feature: UriPermissionManagerService
 * Function: AddPolicyRecordCache
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService AddPolicyRecordCache
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_AddPolicyRecordCache_004, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t callerTokenId = 1000;
    uint32_t targetTokenId = 1001;
    std::string path = "/data/storage/test.txt";

    upmsi->policyMap_.clear();

    MyFlag::isUdmfOrPasteboardCallRet_ = true;

    upmsi->AddPolicyRecordCache(callerTokenId, targetTokenId, path);

    EXPECT_EQ(upmsi->policyMap_.size(), 1);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionPrivilegedImpl
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionPrivilegedImpl
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionPrivilegedImpl_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    BatchStringUri batchUris;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    FUDAppInfo callerInfo = { 1000, "caller", "callerAlter" };
    FUDAppInfo targetAppInfo = { 1001, "target", "targetAlter" };
    int32_t hideSensitiveType = 0;

    auto result = upmsi->GrantUriPermissionPrivilegedImpl(batchUris, flag, callerInfo, targetAppInfo,
        hideSensitiveType);

    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionPrivilegedImpl
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionPrivilegedImpl
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionPrivilegedImpl_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    BatchStringUri batchUris;
    batchUris.uriStrVec = { "file://docs/test.txt?networkid=123" };

    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    FUDAppInfo callerInfo = { 1000, "caller", "callerAlter" };
    FUDAppInfo targetAppInfo = { 1001, "target", "targetAlter" };
    int32_t hideSensitiveType = 0;

    auto result = upmsi->GrantUriPermissionPrivilegedImpl(batchUris, flag, callerInfo, targetAppInfo,
        hideSensitiveType);

    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionPrivilegedImpl
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionPrivilegedImpl
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionPrivilegedImpl_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    BatchStringUri batchUris;
    batchUris.mediaUriVec = { "file://media/test.jpg" };

    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    FUDAppInfo callerInfo = { 1000, "caller", "callerAlter" };
    FUDAppInfo targetAppInfo = { 1001, "target", "targetAlter" };
    int32_t hideSensitiveType = 0;

    auto result = upmsi->GrantUriPermissionPrivilegedImpl(batchUris, flag, callerInfo, targetAppInfo,
        hideSensitiveType);

    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionPrivilegedImpl
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionPrivilegedImpl
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionPrivilegedImpl_004, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    BatchStringUri batchUris;
    PolicyInfo policy;
    policy.path = "/data/storage/test.txt";
    policy.mode = 1;
    batchUris.policyVec = { policy };

    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    FUDAppInfo callerInfo = { 1000, "caller", "callerAlter" };
    FUDAppInfo targetAppInfo = { 1001, "target", "targetAlter" };
    int32_t hideSensitiveType = 0;

    auto result = upmsi->GrantUriPermissionPrivilegedImpl(batchUris, flag, callerInfo, targetAppInfo,
        hideSensitiveType);

    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionPrivilegedImpl
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionPrivilegedImpl
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionPrivilegedImpl_005, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    BatchStringUri batchUris;
    batchUris.contentUris = { "content://test" };

    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    FUDAppInfo callerInfo = { 1000, "caller", "callerAlter" };
    FUDAppInfo targetAppInfo = { 1001, "target", "targetAlter" };
    int32_t hideSensitiveType = 0;

    auto result = upmsi->GrantUriPermissionPrivilegedImpl(batchUris, flag, callerInfo, targetAppInfo,
        hideSensitiveType);

    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionPrivilegedImpl
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionPrivilegedImpl
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionPrivilegedImpl_006, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    BatchStringUri batchUris;
    batchUris.uriStrVec = { "file://docs/test.txt?networkid=123" };
    batchUris.mediaUriVec = { "file://media/test.jpg" };
    PolicyInfo policy;
    policy.path = "/data/storage/test.txt";
    policy.mode = 1;
    batchUris.policyVec = { policy };
    batchUris.contentUris = { "content://test" };

    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION | Want::FLAG_AUTH_WRITE_URI_PERMISSION;
    FUDAppInfo callerInfo = { 1000, "caller", "callerAlter" };
    FUDAppInfo targetAppInfo = { 1001, "target", "targetAlter" };
    int32_t hideSensitiveType = 0;

    auto result = upmsi->GrantUriPermissionPrivilegedImpl(batchUris, flag, callerInfo, targetAppInfo,
        hideSensitiveType);

    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: GrantUriPermissionPrivilegedImpl
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService GrantUriPermissionPrivilegedImpl
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_GrantUriPermissionPrivilegedImpl_007, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    BatchStringUri batchUris;
    batchUris.uriStrVec = { "file://docs/test.txt?networkid=123" };

    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION |
                    Want::FLAG_AUTH_WRITE_URI_PERMISSION |
                    Want::FLAG_AUTH_PERSISTABLE_URI_PERMISSION;
    FUDAppInfo callerInfo = { 1000, "caller", "callerAlter" };
    FUDAppInfo targetAppInfo = { 1001, "target", "targetAlter" };
    int32_t hideSensitiveType = 0;

    auto result = upmsi->GrantUriPermissionPrivilegedImpl(batchUris, flag, callerInfo, targetAppInfo,
        hideSensitiveType);

    EXPECT_EQ(result, INNER_ERR);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckUriPermission_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    BatchUri batchUri;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;
    uint32_t callerTokenId = 1000;
    std::string callerAlterableBundleName = "callerBundle";
    uint32_t targetTokenId = 1001;

    auto result = upmsi->CheckUriPermission(batchUri, flag, callerTokenId, callerAlterableBundleName, targetTokenId);

    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckProxyUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckProxyUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckProxyUriPermission_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    BatchUri batchUri;
    uint32_t callerTokenId = 1000;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;

    MyFlag::permissionProxyAuthorization_ = false;

    auto result = upmsi->CheckProxyUriPermission(batchUri, callerTokenId, flag);

    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckProxyUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckProxyUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckProxyUriPermission_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    BatchUri batchUri;
    uint32_t callerTokenId = 1000;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;

    MyFlag::permissionProxyAuthorization_ = true;

    auto result = upmsi->CheckProxyUriPermission(batchUri, callerTokenId, flag);

    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckProxyUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckProxyUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckProxyUriPermission_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    BatchUri batchUri;
    uint32_t callerTokenId = 1000;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;

    MyFlag::permissionProxyAuthorization_ = true;

    PolicyInfo policy;
    policy.path = "/data/storage/proxy.txt";
    policy.mode = 1;
    batchUri.otherPolicyInfos = { policy };

    auto result = upmsi->CheckProxyUriPermission(batchUri, callerTokenId, flag);

    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckProxyUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckProxyUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckProxyUriPermission_004, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    BatchUri batchUri;
    uint32_t callerTokenId = 1000;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION | Want::FLAG_AUTH_WRITE_URI_PERMISSION;

    MyFlag::permissionProxyAuthorization_ = true;

    PolicyInfo policy;
    policy.path = "/data/storage/proxy.txt";
    policy.mode = 1;
    batchUri.otherPolicyInfos = { policy };

    auto result = upmsi->CheckProxyUriPermission(batchUri, callerTokenId, flag);

    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeMapUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeMapUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeMapUriPermission_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    upmsi->uriMap_.clear();

    upmsi->RevokeMapUriPermission(tokenId);

    EXPECT_TRUE(upmsi->uriMap_.empty());
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeMapUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeMapUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeMapUriPermission_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    GrantInfo info1 = { Want::FLAG_AUTH_READ_URI_PERMISSION, 999, tokenId };
    GrantInfo info2 = { Want::FLAG_AUTH_WRITE_URI_PERMISSION, 998, 1001 };
    std::list<GrantInfo> infoList = { info1, info2 };

    upmsi->uriMap_["file://test1.txt"] = infoList;
    upmsi->uriMap_["file://test2.txt"] = { info2 };

    upmsi->RevokeMapUriPermission(tokenId);

    auto it1 = upmsi->uriMap_.find("file://test1.txt");
    EXPECT_TRUE(it1 != upmsi->uriMap_.end());
    EXPECT_EQ(it1->second.size(), 1);

    auto it2 = upmsi->uriMap_.find("file://test2.txt");
    EXPECT_TRUE(it2 != upmsi->uriMap_.end());
    EXPECT_EQ(it2->second.size(), 1);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeMapUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeMapUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeMapUriPermission_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    GrantInfo info = { Want::FLAG_AUTH_READ_URI_PERMISSION, 999, tokenId };
    upmsi->uriMap_["file://test.txt"] = { info };

    upmsi->RevokeMapUriPermission(tokenId);

    auto it = upmsi->uriMap_.find("file://test.txt");
    EXPECT_TRUE(it == upmsi->uriMap_.end());
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeMapUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeMapUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeMapUriPermission_004, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    GrantInfo info1 = { Want::FLAG_AUTH_READ_URI_PERMISSION, 999, tokenId };
    GrantInfo info2 = { Want::FLAG_AUTH_WRITE_URI_PERMISSION, 998, tokenId };
    GrantInfo info3 = { Want::FLAG_AUTH_READ_URI_PERMISSION, 997, 1001 };

    std::list<GrantInfo> infoList = { info1, info2, info3 };
    upmsi->uriMap_["file://test.txt"] = infoList;

    upmsi->RevokeMapUriPermission(tokenId);

    auto it = upmsi->uriMap_.find("file://test.txt");
    EXPECT_TRUE(it != upmsi->uriMap_.end());
    EXPECT_EQ(it->second.size(), 1);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokePolicyUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokePolicyUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokePolicyUriPermission_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    upmsi->policyMap_.clear();

    upmsi->RevokePolicyUriPermission(tokenId);

    EXPECT_TRUE(upmsi->policyMap_.empty());
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokePolicyUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokePolicyUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokePolicyUriPermission_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    GrantPolicyInfo policyInfo1 = { 999, tokenId };
    GrantPolicyInfo policyInfo2 = { 998, 1001 };
    GrantPolicyInfo policyInfo3 = { tokenId, 1002 };

    std::list<GrantPolicyInfo> policyList1 = { policyInfo1, policyInfo2 };
    std::list<GrantPolicyInfo> policyList2 = { policyInfo3 };

    upmsi->policyMap_["/data/path1"] = policyList1;
    upmsi->policyMap_["/data/path2"] = policyList2;

    upmsi->RevokePolicyUriPermission(tokenId);

    auto it1 = upmsi->policyMap_.find("/data/path1");
    EXPECT_TRUE(it1 != upmsi->policyMap_.end());
    EXPECT_EQ(it1->second.size(), 1);

    auto it2 = upmsi->policyMap_.find("/data/path2");
    EXPECT_TRUE(it2 != upmsi->policyMap_.end());
    EXPECT_EQ(it2->second.size(), 1);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokePolicyUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokePolicyUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokePolicyUriPermission_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    GrantPolicyInfo policyInfo = { 999, tokenId };
    upmsi->policyMap_["/data/path"] = { policyInfo };

    upmsi->RevokePolicyUriPermission(tokenId);

    auto it = upmsi->policyMap_.find("/data/path");
    EXPECT_TRUE(it == upmsi->policyMap_.end());
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokePolicyUriPermission
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokePolicyUriPermission
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokePolicyUriPermission_004, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    GrantPolicyInfo policyInfo1 = { 999, tokenId };
    GrantPolicyInfo policyInfo2 = { 998, tokenId };
    GrantPolicyInfo policyInfo3 = { 997, 1001 };

    upmsi->policyMap_["/data/path1"] = { policyInfo1, policyInfo3 };
    upmsi->policyMap_["/data/path2"] = { policyInfo2 };
    upmsi->policyMap_["/data/path3"] = { policyInfo3 };

    upmsi->RevokePolicyUriPermission(tokenId);

    auto it1 = upmsi->policyMap_.find("/data/path1");
    EXPECT_TRUE(it1 != upmsi->policyMap_.end());
    EXPECT_EQ(it1->second.size(), 1);

    auto it2 = upmsi->policyMap_.find("/data/path2");
    EXPECT_TRUE(it2 == upmsi->policyMap_.end());

    auto it3 = upmsi->policyMap_.find("/data/path3");
    EXPECT_TRUE(it3 != upmsi->policyMap_.end());
    EXPECT_EQ(it3->second.size(), 1);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeAllPolicyUriPermissions
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeAllPolicyUriPermissions
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeAllPolicyUriPermissions_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    upmsi->policyMap_.clear();

    auto result = upmsi->RevokeAllPolicyUriPermissions(tokenId);

    EXPECT_EQ(result, ERR_OK);
    EXPECT_TRUE(upmsi->policyMap_.empty());
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeAllPolicyUriPermissions
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeAllPolicyUriPermissions
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeAllPolicyUriPermissions_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    GrantPolicyInfo policyInfo1 = { 999, tokenId };
    GrantPolicyInfo policyInfo2 = { tokenId, 1001 };
    GrantPolicyInfo policyInfo3 = { 998, 1002 };

    std::list<GrantPolicyInfo> policyList1 = { policyInfo1, policyInfo2, policyInfo3 };
    std::list<GrantPolicyInfo> policyList2 = { policyInfo3 };

    upmsi->policyMap_["/data/path1"] = policyList1;
    upmsi->policyMap_["/data/path2"] = policyList2;

    auto result = upmsi->RevokeAllPolicyUriPermissions(tokenId);

    auto it1 = upmsi->policyMap_.find("/data/path1");
    EXPECT_TRUE(it1 != upmsi->policyMap_.end());
    EXPECT_EQ(it1->second.size(), 1);

    auto it2 = upmsi->policyMap_.find("/data/path2");
    EXPECT_TRUE(it2 != upmsi->policyMap_.end());
    EXPECT_EQ(it2->second.size(), 1);

    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeAllPolicyUriPermissions
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeAllPolicyUriPermissions
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeAllPolicyUriPermissions_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t tokenId = 1000;

    GrantPolicyInfo policyInfo1 = { 999, tokenId };
    GrantPolicyInfo policyInfo2 = { tokenId, 1001 };

    upmsi->policyMap_["/data/path1"] = { policyInfo1 };
    upmsi->policyMap_["/data/path2"] = { policyInfo2 };

    auto result = upmsi->RevokeAllPolicyUriPermissions(tokenId);

    auto it1 = upmsi->policyMap_.find("/data/path1");
    EXPECT_TRUE(it1 == upmsi->policyMap_.end());

    auto it2 = upmsi->policyMap_.find("/data/path2");
    EXPECT_TRUE(it2 == upmsi->policyMap_.end());

    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokePolicyUriPermissionManually
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokePolicyUriPermissionManually
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokePolicyUriPermissionManually_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t callerTokenId = 1000;
    uint32_t targetTokenId = 1001;
    Uri uri("file://com.example.app/test.txt");

    auto result = upmsi->RevokePolicyUriPermissionManually(callerTokenId, targetTokenId, uri);

    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: RevokeMediaUriPermissionManually
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService RevokeMediaUriPermissionManually
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_RevokeMediaUriPermissionManually_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t callerTokenId = 1000;
    uint32_t targetTokenId = 1001;
    Uri uri("file://media/test.jpg");

    auto result = upmsi->RevokeMediaUriPermissionManually(callerTokenId, targetTokenId, uri);

    EXPECT_EQ(result, -1);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckCalledBySandBox
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckCalledBySandBox
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckCalledBySandBox_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::isSandboxAppRet_ = false;

    auto result = upmsi->CheckCalledBySandBox();

    EXPECT_EQ(result, ERR_OK);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckCalledBySandBox
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckCalledBySandBox
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckCalledBySandBox_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    MyFlag::isSandboxAppRet_ = true;

    auto result = upmsi->CheckCalledBySandBox();

    EXPECT_EQ(result, ERR_CODE_GRANT_URI_PERMISSION);
}

/*
 * Feature: UriPermissionManagerService
 * Function: BoolVecToRawData
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService BoolVecToRawData
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_BoolVecToRawData_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<bool> boolVector;
    UriPermissionRawData rawData;
    std::vector<char> charVector;

    upmsi->BoolVecToRawData(boolVector, rawData, charVector);

    EXPECT_EQ(rawData.size, sizeof(uint32_t));
    EXPECT_TRUE(rawData.data != nullptr);
}

/*
 * Feature: UriPermissionManagerService
 * Function: BoolVecToRawData
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService BoolVecToRawData
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_BoolVecToRawData_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<bool> boolVector = { true, false, true, false, true };
    UriPermissionRawData rawData;
    std::vector<char> charVector;

    upmsi->BoolVecToRawData(boolVector, rawData, charVector);

    uint32_t expectedSize = sizeof(uint32_t) + 5 * sizeof(char);
    EXPECT_EQ(rawData.size, expectedSize);
    EXPECT_TRUE(rawData.data != nullptr);
}

/*
 * Feature: UriPermissionManagerService
 * Function: BoolVecToRawData
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService BoolVecToRawData
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_BoolVecToRawData_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<bool> boolVector = { false };
    UriPermissionRawData rawData;
    std::vector<char> charVector;

    upmsi->BoolVecToRawData(boolVector, rawData, charVector);

    uint32_t expectedSize = sizeof(uint32_t) + sizeof(char);
    EXPECT_EQ(rawData.size, expectedSize);
    EXPECT_TRUE(rawData.data != nullptr);
}

/*
 * Feature: UriPermissionManagerService
 * Function: CheckGrantUriPermissionPrivileged
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService CheckGrantUriPermissionPrivileged
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_CheckGrantUriPermissionPrivileged_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    uint32_t callerTokenId = 1000;
    uint32_t flag = Want::FLAG_AUTH_READ_URI_PERMISSION;

    MyFlag::permissionAll_ = false;

    auto result = upmsi->CheckGrantUriPermissionPrivileged(callerTokenId, flag);

    EXPECT_EQ(result, CHECK_PERMISSION_FAILED);
}

/*
 * Feature: UriPermissionManagerService
 * Function: StringVecToRawData
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService StringVecToRawData
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_StringVecToRawData_001, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<std::string> stringVec;
    StorageFileRawData rawData;

    upmsi->StringVecToRawData(stringVec, rawData);

    EXPECT_EQ(rawData.size, sizeof(uint32_t));
    EXPECT_TRUE(rawData.data != nullptr);
}

/*
 * Feature: UriPermissionManagerService
 * Function: StringVecToRawData
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService StringVecToRawData
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_StringVecToRawData_002, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<std::string> stringVec = { "test1", "test22", "test333" };
    StorageFileRawData rawData;

    upmsi->StringVecToRawData(stringVec, rawData);

    uint32_t expectedSize = sizeof(uint32_t);
    for (const auto& str : stringVec) {
        expectedSize += sizeof(uint32_t) + str.length();
    }

    EXPECT_EQ(rawData.size, expectedSize);
    EXPECT_TRUE(rawData.data != nullptr);
}

/*
 * Feature: UriPermissionManagerService
 * Function: StringVecToRawData
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService StringVecToRawData
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_StringVecToRawData_003, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<std::string> stringVec = { "single" };
    StorageFileRawData rawData;

    upmsi->StringVecToRawData(stringVec, rawData);

    uint32_t expectedSize = sizeof(uint32_t) + sizeof(uint32_t) + stringVec[0].length();
    EXPECT_EQ(rawData.size, expectedSize);
    EXPECT_TRUE(rawData.data != nullptr);
}

/*
 * Feature: UriPermissionManagerService
 * Function: StringVecToRawData
 * SubFunction: NA
 * FunctionPoints: UriPermissionManagerService StringVecToRawData
 */
HWTEST_F(UriPermissionManagerStubImplTest, Upmsi_StringVecToRawData_004, TestSize.Level1)
{
    auto upmsi = std::make_shared<UriPermissionManagerStubImpl>();

    std::vector<std::string> stringVec = { "", "non-empty", "" };
    StorageFileRawData rawData;

    upmsi->StringVecToRawData(stringVec, rawData);

    uint32_t expectedSize = sizeof(uint32_t);
    for (const auto& str : stringVec) {
        expectedSize += sizeof(uint32_t) + str.length();
    }

    EXPECT_EQ(rawData.size, expectedSize);
    EXPECT_TRUE(rawData.data != nullptr);
}
}  // namespace AAFwk
}  // namespace OHOS