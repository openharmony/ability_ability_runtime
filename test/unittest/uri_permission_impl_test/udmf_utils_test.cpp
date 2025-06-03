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

#include "udmf_client.h"

#include "ability_manager_errors.h"
#define private public
#include "upms_udmf_utils.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class UriPermissionImplUdmfUtilsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void UriPermissionImplUdmfUtilsTest::SetUpTestCase(void)
{}

void UriPermissionImplUdmfUtilsTest::TearDownTestCase(void)
{}

void UriPermissionImplUdmfUtilsTest::SetUp()
{
    UDMF::UdmfClient::Init();
}

void UriPermissionImplUdmfUtilsTest::TearDown()
{}

/**
 * @tc.number: AddPrivilege_0100
 * @tc.desc: Test AddPrivilege works
 * @tc.type: FUNC
 */
HWTEST_F(UriPermissionImplUdmfUtilsTest, AddPrivilege_0100, TestSize.Level1)
{
    std::string key = "udmfKey";
    uint32_t targetTokenId = 100001;
    std::string readPermission = "";
    auto ret = UDMFUtils::AddPrivilege(key, targetTokenId, readPermission);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: AddPrivilege_0200
 * @tc.desc: Test AddPrivilege works
 * @tc.type: FUNC
 */
HWTEST_F(UriPermissionImplUdmfUtilsTest, AddPrivilege_0200, TestSize.Level1)
{
    std::string key = "udmfKey";
    uint32_t targetTokenId = 100001;
    std::string readPermission = "";
    UDMF::UdmfClient::addPrivilegeRet_ = INNER_ERR;
    auto ret = UDMFUtils::AddPrivilege(key, targetTokenId, readPermission);
    EXPECT_EQ(ret, INNER_ERR);
}

/**
 * @tc.number: GetBatchData_0100
 * @tc.desc: Test GetBatchData works
 * @tc.type: FUNC
 */
HWTEST_F(UriPermissionImplUdmfUtilsTest, GetBatchData_0100, TestSize.Level1)
{
    std::string key = "";
    std::vector<std::string> uris;
    UDMF::UdmfClient::getBatchDataRet_ = INNER_ERR;
    auto ret = UDMFUtils::GetBatchData(key, uris);
    EXPECT_EQ(ret, INNER_ERR);
}

/**
 * @tc.number: GetBatchData_0200
 * @tc.desc: Test GetBatchData works
 * @tc.type: FUNC
 */
HWTEST_F(UriPermissionImplUdmfUtilsTest, GetBatchData_0200, TestSize.Level1)
{
    std::string key = "";
    std::vector<std::string> uris;
    UDMF::UdmfClient::getBatchDataRet_ = 0;
    UDMF::UdmfClient::unifiedData_= {};
    auto ret = UDMFUtils::GetBatchData(key, uris);
    EXPECT_EQ(ret, ERR_UPMS_GET_FILE_URIS_BY_KEY_FAILED);
}

/**
 * @tc.number: GetBatchData_0300
 * @tc.desc: Test GetBatchData works, unified record GetEntry is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(UriPermissionImplUdmfUtilsTest, GetBatchData_0300, TestSize.Level1)
{
    // null entry
    std::string uri = "null";
    std::string key = "udmfKey";
    // create dataset
    std::vector<UDMF::UnifiedData> unifiedDataset;
    std::vector<std::shared_ptr<UDMF::UnifiedRecord>> unifiedRecords;
    unifiedRecords.emplace_back(std::make_shared<UDMF::UnifiedRecord>(uri));
    unifiedDataset.emplace_back(UDMF::UnifiedData(unifiedRecords));
    UDMF::UdmfClient::unifiedData_ = unifiedDataset;
    // GetEntry is nullptr
    std::vector<std::string> uris;
    auto ret = UDMFUtils::GetBatchData(key, uris);
    EXPECT_EQ(ret, ERR_UPMS_GET_ORI_URI_FAILED);
}

/**
 * @tc.number: GetBatchData_0400
 * @tc.desc: Test GetBatchData works, unified record GetValue is empty.
 * @tc.type: FUNC
 */
HWTEST_F(UriPermissionImplUdmfUtilsTest, GetBatchData_0400, TestSize.Level1)
{
    std::string uri = "";
    std::string key = "udmfKey";
    // create dataset
    std::vector<UDMF::UnifiedData> unifiedDataset;
    std::vector<std::shared_ptr<UDMF::UnifiedRecord>> unifiedRecords;
    unifiedRecords.emplace_back(std::make_shared<UDMF::UnifiedRecord>(uri));
    unifiedDataset.emplace_back(UDMF::UnifiedData(unifiedRecords));
    UDMF::UdmfClient::unifiedData_ = unifiedDataset;
    // GetValue oriUri is empty
    std::vector<std::string> uris;
    auto ret = UDMFUtils::GetBatchData(key, uris);
    EXPECT_EQ(ret, ERR_UPMS_GET_ORI_URI_FAILED);
}

/**
 * @tc.number: GetBatchData_0500
 * @tc.desc: Test GetBatchData works, unified record oriUri is not file uri.
 * @tc.type: FUNC
 */
HWTEST_F(UriPermissionImplUdmfUtilsTest, GetBatchData_0500, TestSize.Level1)
{
    std::string uri = "http://temp.txt";
    std::string key = "udmfKey";
    // create dataset
    std::vector<UDMF::UnifiedData> unifiedDataset;
    std::vector<std::shared_ptr<UDMF::UnifiedRecord>> unifiedRecords;
    unifiedRecords.emplace_back(std::make_shared<UDMF::UnifiedRecord>(uri));
    unifiedDataset.emplace_back(UDMF::UnifiedData(unifiedRecords));
    UDMF::UdmfClient::unifiedData_ = unifiedDataset;
    // GetValue oriUri is not file uri
    std::vector<std::string> uris;
    auto ret = UDMFUtils::GetBatchData(key, uris);
    EXPECT_EQ(ret, ERR_UPMS_NOT_FILE_URI);
}

/**
 * @tc.number: GetBatchData_0600
 * @tc.desc: Test GetBatchData works, unified record GetValue is file.
 * @tc.type: FUNC
 */
HWTEST_F(UriPermissionImplUdmfUtilsTest, GetBatchData_0600, TestSize.Level1)
{
    std::string uri = "file://com.example.test/temp.txt";
    std::string key = "udmfKey";
    // create dataset
    std::vector<UDMF::UnifiedData> unifiedDataset;
    std::vector<std::shared_ptr<UDMF::UnifiedRecord>> unifiedRecords;
    unifiedRecords.emplace_back(std::make_shared<UDMF::UnifiedRecord>(uri));
    unifiedDataset.emplace_back(UDMF::UnifiedData(unifiedRecords));
    UDMF::UdmfClient::unifiedData_ = unifiedDataset;
    // GetValue oriUri is file uri
    std::vector<std::string> uris;
    auto ret = UDMFUtils::GetBatchData(key, uris);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(uris.size(), 1);
}

/**
 * @tc.number: GetBatchData_0700
 * @tc.desc: Test GetBatchData works, some uri is invalid.
 * @tc.type: FUNC
 */
HWTEST_F(UriPermissionImplUdmfUtilsTest, GetBatchData_0700, TestSize.Level1)
{
    std::string uri1 = "file://com.example.test/temp.txt";
    std::string uri2 = "http://com.example.test/temp.txt";
    std::string key = "udmfKey";
    // create dataset
    std::vector<UDMF::UnifiedData> unifiedDataset;
    std::vector<std::shared_ptr<UDMF::UnifiedRecord>> unifiedRecords;
    unifiedRecords.emplace_back(std::make_shared<UDMF::UnifiedRecord>(uri1));
    unifiedRecords.emplace_back(std::make_shared<UDMF::UnifiedRecord>(uri2));
    unifiedDataset.emplace_back(UDMF::UnifiedData(unifiedRecords));
    UDMF::UdmfClient::unifiedData_ = unifiedDataset;
    // one uri is invalid
    std::vector<std::string> uris;
    auto ret = UDMFUtils::GetBatchData(key, uris);
    EXPECT_EQ(ret, ERR_UPMS_NOT_FILE_URI);
}

/**
 * @tc.number: ProcessUdmfKey_0100
 * @tc.desc: Test ProcessUdmfKey works, AddPrivilege failed.
 * @tc.type: FUNC
 */
HWTEST_F(UriPermissionImplUdmfUtilsTest, ProcessUdmfKey_0100, TestSize.Level1)
{
    std::string key = "";
    uint32_t callerTokenId = 100001;
    uint32_t targetTokenId = 100002;
    std::vector<std::string> uris;
    UDMF::UdmfClient::addPrivilegeRet_ = INNER_ERR;
    auto ret = UDMFUtils::ProcessUdmfKey(key, callerTokenId, targetTokenId, uris);
    EXPECT_EQ(ret, ERR_UPMS_ADD_PRIVILEGED_FAILED);
}

/**
 * @tc.number: ProcessUdmfKey_0200
 * @tc.desc: Test ProcessUdmfKey works, AddPrivilege first, success second failed.
 * @tc.type: FUNC
 */
HWTEST_F(UriPermissionImplUdmfUtilsTest, ProcessUdmfKey_0200, TestSize.Level1)
{
    std::string key = "";
    uint32_t callerTokenId = 100001;
    // AddPrivileged success
    uint32_t targetTokenId = UDMF::UdmfClient::privilegeTokenId_;
    std::vector<std::string> uris;
    UDMF::UdmfClient::addPrivilegeRet_ = INNER_ERR;
    auto ret = UDMFUtils::ProcessUdmfKey(key, callerTokenId, targetTokenId, uris);
    EXPECT_EQ(ret, ERR_UPMS_ADD_PRIVILEGED_FAILED);
}

/**
 * @tc.number: ProcessUdmfKey_0300
 * @tc.desc: Test ProcessUdmfKey works, GetBatchData failed.
 * @tc.type: FUNC
 */
HWTEST_F(UriPermissionImplUdmfUtilsTest, ProcessUdmfKey_0300, TestSize.Level1)
{
    std::string key = "";
    uint32_t callerTokenId = 100001;
    uint32_t targetTokenId = 100002;
    std::vector<std::string> uris;
    UDMF::UdmfClient::addPrivilegeRet_ = ERR_OK;
    UDMF::UdmfClient::getBatchDataRet_ = INNER_ERR;
    auto ret = UDMFUtils::ProcessUdmfKey(key, callerTokenId, targetTokenId, uris);
    EXPECT_EQ(ret, ERR_UPMS_GET_FILE_URIS_BY_KEY_FAILED);
}

/**
 * @tc.number: ProcessUdmfKey_0400
 * @tc.desc: Test ProcessUdmfKey works, ProcessUdmfKey success.
 * @tc.type: FUNC
 */
HWTEST_F(UriPermissionImplUdmfUtilsTest, ProcessUdmfKey_0400, TestSize.Level1)
{
    std::string uri = "file://com.example.test/temp.txt";
    std::string key = "udmfKey";
    uint32_t callerTokenId = 100001;
    uint32_t targetTokenId = 100002;
    std::vector<std::string> uris;
    // create dataset
    std::vector<UDMF::UnifiedData> unifiedDataset;
    std::vector<std::shared_ptr<UDMF::UnifiedRecord>> unifiedRecords;
    unifiedRecords.emplace_back(std::make_shared<UDMF::UnifiedRecord>(uri));
    unifiedDataset.emplace_back(UDMF::UnifiedData(unifiedRecords));
    UDMF::UdmfClient::unifiedData_ = unifiedDataset;
    // processUdmfKey
    auto ret = UDMFUtils::ProcessUdmfKey(key, callerTokenId, targetTokenId, uris);
    EXPECT_EQ(ret, ERR_OK);
}
}  // namespace AAFwk
}  // namespace OHOS