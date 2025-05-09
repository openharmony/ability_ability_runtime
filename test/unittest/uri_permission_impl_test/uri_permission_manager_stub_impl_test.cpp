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

#include "mock_my_flag.h"

#define private public
#define protected public
#include "uri_permission_manager_stub_impl.h"
#include "ability_manager_errors.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
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
    MyFlag::isSAOrSystemAppCall_ = false;
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
    MyFlag::isSAOrSystemAppCall_ = true;
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
    unsigned int flag = 1;
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
    unsigned int flag = 1;
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
    unsigned int flag = 1;
    std::string targetBundleName = "targetBundleName";
    int32_t appIndex = 1;
    uint32_t initiatorTokenId = 1;
    int32_t funcResult = 1;
    auto result = upmsi->GrantUriPermission(uriVec, flag, targetBundleName, appIndex, initiatorTokenId, funcResult);
    EXPECT_EQ(result, ERR_URI_LIST_OUT_OF_RANGE);
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
    auto result = upmsi->GrantUriPermissionPrivilegedInner(uriVec, flag, callerTokenId, targetTokenId,
        targetAlterBundleName, hideSensitiveType);
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
    auto result = upmsi->GrantUriPermissionPrivilegedInner(uriVec, flag, callerTokenId, targetTokenId,
        targetAlterBundleName, hideSensitiveType);
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
    auto result = upmsi->GrantUriPermissionPrivilegedInner(uriVec, flag, callerTokenId, targetTokenId,
        targetAlterBundleName, hideSensitiveType);
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
    MyFlag::isSAOrSystemAppCall_ = true;
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
}  // namespace AAFwk
}  // namespace OHOS
