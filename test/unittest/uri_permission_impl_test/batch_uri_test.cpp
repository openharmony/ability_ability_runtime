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
#include "batch_uri.h"
#include "mock_my_flag.h"
#undef private
#undef protected
using namespace testing::ext;
namespace OHOS {
namespace AAFwk {
class BatchUriTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BatchUriTest::SetUpTestCase()
{}

void BatchUriTest::TearDownTestCase()
{}

void BatchUriTest::SetUp()
{
    MyFlag::Init();
}

void BatchUriTest::TearDown()
{}

/**
 * @tc.number: Init_0100
 * @tc.name: Init
 * @tc.desc: Test Init.
 */
HWTEST_F(BatchUriTest, Init_0100, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    std::vector<std::string> uriVec;
    uint32_t mode = 0;
    std::string callerAlterBundleName = "callerBundleName";
    std::string targetAlterBundleName = "targetBundleName";
    auto ret = batchUri->Init(uriVec, mode, callerAlterBundleName, targetAlterBundleName);
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.number: Init_0200
 * @tc.name: Init
 * @tc.desc: Test Init.
 */
HWTEST_F(BatchUriTest, Init_0200, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    std::vector<std::string> uriVec;
    uriVec.push_back("file://com.example.insertdata/data/storage/el2/base/haps/entry/files/temp1.txt");
    uriVec.push_back("testUri");
    uint32_t mode = 0;
    std::string callerAlterBundleName = "callerBundleName";
    std::string targetAlterBundleName = "targetBundleName";
    auto ret = batchUri->Init(uriVec, mode, callerAlterBundleName, targetAlterBundleName);
    EXPECT_EQ(ret, 1);
}

/**
 * @tc.number: Init_0300
 * @tc.name: Init
 * @tc.desc: Test Init.
 */
HWTEST_F(BatchUriTest, Init_0300, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    std::vector<std::string> uriVec;
    uriVec.push_back("file://com.example.insertdata/data/storage/el2/base/haps/entry/files/temp1.txt");
    uriVec.push_back("file://docs/temp1.txt");
    uint32_t mode = 0;
    std::string callerAlterBundleName = "callerBundleName";
    std::string targetAlterBundleName = "targetBundleName";
    auto ret = batchUri->Init(uriVec, mode, callerAlterBundleName, targetAlterBundleName, true);
    EXPECT_EQ(ret, 2);
    EXPECT_EQ(batchUri->checkResult[0].result, true);
}

/**
 * @tc.number: Init_0400
 * @tc.name: Init
 * @tc.desc: Test Init.
 */
HWTEST_F(BatchUriTest, Init_0400, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    std::vector<std::string> uriVec;
    uriVec.push_back("file://com.example.insertdata/data/storage/el2/base/haps/entry/files/temp1.txt");
    uriVec.push_back("file://docs/temp1.txt");
    uint32_t mode = 0;
    std::string callerAlterBundleName = "callerBundleName";
    std::string targetAlterBundleName = "targetBundleName";
    auto ret = batchUri->Init(uriVec, mode, callerAlterBundleName, targetAlterBundleName, false);
    EXPECT_EQ(ret, 2);
    EXPECT_EQ(batchUri->checkResult[0].result, false);
}

/**
 * @tc.number: Init_0500
 * @tc.name: Init
 * @tc.desc: Test Init.
 */
HWTEST_F(BatchUriTest, Init_0500, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    std::vector<std::string> uriVec;
    uriVec.push_back("content://temp.txt");
    uint32_t mode = 0;
    std::string callerAlterBundleName = "callerBundleName";
    std::string targetAlterBundleName = "targetBundleName";
    auto ret = batchUri->Init(uriVec, mode, callerAlterBundleName, targetAlterBundleName, false);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(batchUri->contentUris.size(), 1);
}

/**
 * @tc.number: Init_0600
 * @tc.name: Init
 * @tc.desc: Test Init.
 */
HWTEST_F(BatchUriTest, Init_0600, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    std::vector<std::string> uriVec;
    uriVec.push_back("file://com.example.caller/temp.txt");
    uint32_t mode = 0;
    std::string callerAlterBundleName = "com.example.caller";
    std::string targetAlterBundleName = "target";
    auto ret = batchUri->Init(uriVec, mode, callerAlterBundleName, targetAlterBundleName, false);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(batchUri->checkResult[0].result, true);
    EXPECT_EQ(batchUri->checkResult[0].permissionType, PolicyType::SELF_PATH);
    EXPECT_EQ(batchUri->selfBundlePolicyInfos.size(), 0);
}

/**
 * @tc.number: Init_0700
 * @tc.name: Init
 * @tc.desc: Test Init.
 */
HWTEST_F(BatchUriTest, Init_0700, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    std::vector<std::string> uriVec;
    uriVec.push_back("file://com.example.caller/temp.txt");
    uint32_t mode = 1;
    std::string callerAlterBundleName = "com.example.caller";
    std::string targetAlterBundleName = "target";
    auto ret = batchUri->Init(uriVec, mode, callerAlterBundleName, targetAlterBundleName, false);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(batchUri->checkResult[0].result, true);
    EXPECT_EQ(batchUri->checkResult[0].permissionType, PolicyType::SELF_PATH);
    EXPECT_EQ(batchUri->selfBundlePolicyInfos.size(), 1);
    EXPECT_EQ(batchUri->selfBundlePolicyInfos[0].type, PolicyType::SELF_PATH);
}

/**
 * @tc.number: Init_0800
 * @tc.name: Init
 * @tc.desc: Test Init.
 */
HWTEST_F(BatchUriTest, Init_0800, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    std::vector<std::string> uriVec;
    uriVec.push_back("file://com.example.test/temp.txt");
    uint32_t mode = 0;
    std::string callerAlterBundleName = "caller";
    std::string targetAlterBundleName = "target";
    auto ret = batchUri->Init(uriVec, mode, callerAlterBundleName, targetAlterBundleName, true);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(batchUri->checkResult[0].result, true);
    EXPECT_EQ(batchUri->checkResult[0].permissionType, PolicyType::UNKNOWN);
    EXPECT_EQ(batchUri->selfBundlePolicyInfos.size(), 0);
}

/**
 * @tc.number: Init_0900
 * @tc.name: Init
 * @tc.desc: Test Init.
 */
HWTEST_F(BatchUriTest, Init_0900, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    std::vector<std::string> uriVec;
    uriVec.push_back("file://com.example.test/temp.txt");
    uint32_t mode = 1;
    std::string callerAlterBundleName = "caller";
    std::string targetAlterBundleName = "target";
    auto ret = batchUri->Init(uriVec, mode, callerAlterBundleName, targetAlterBundleName, true);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(batchUri->checkResult[0].result, true);
    EXPECT_EQ(batchUri->checkResult[0].permissionType, PolicyType::UNKNOWN);
    EXPECT_EQ(batchUri->selfBundlePolicyInfos.size(), 1);
    EXPECT_EQ(batchUri->selfBundlePolicyInfos[0].type, PolicyType::UNKNOWN);
}

/**
 * @tc.number: GetUriToGrantByPolicy_0100
 * @tc.name: GetUriToGrantByPolicy
 * @tc.desc: Test GetUriToGrantByPolicy.
 */
HWTEST_F(BatchUriTest, GetUriToGrantByPolicy_0100, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    PolicyInfo policyInfo;
    policyInfo.path = "testPath";
    policyInfo.mode = 0;
    batchUri->selfBundlePolicyInfos.push_back(policyInfo);
    batchUri->otherPolicyInfos.push_back(policyInfo);
    batchUri->otherIndexes.push_back(0);
    batchUri->checkResult.push_back(CheckResult(false, 0));
    std::vector<PolicyInfo> policys;
    auto ret = batchUri->GetUriToGrantByPolicy(policys);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: GetUriToGrantByPolicy_0200
 * @tc.name: GetUriToGrantByPolicy
 * @tc.desc: Test GetUriToGrantByPolicy.
 */
HWTEST_F(BatchUriTest, GetUriToGrantByPolicy_0200, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    PolicyInfo policyInfo;
    policyInfo.path = "testPath";
    policyInfo.mode = 0;
    batchUri->selfBundlePolicyInfos.push_back(policyInfo);
    batchUri->otherPolicyInfos.push_back(policyInfo);
    batchUri->otherIndexes.push_back(0);
    batchUri->checkResult.push_back(CheckResult(true, 0));
    batchUri->isTargetBundleUri.push_back(true);
    std::vector<PolicyInfo> policys;
    auto ret = batchUri->GetUriToGrantByPolicy(policys);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetUriToGrantByPolicy_0300
 * @tc.name: GetUriToGrantByPolicy
 * @tc.desc: Test GetUriToGrantByPolicy.
 */
HWTEST_F(BatchUriTest, GetUriToGrantByPolicy_0300, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    PolicyInfo policyInfo;
    policyInfo.path = "testPath";
    policyInfo.mode = 0;
    batchUri->selfBundlePolicyInfos.push_back(policyInfo);
    batchUri->selfBundlePolicyInfos[0].type = PolicyType::SELF_PATH;
    batchUri->otherPolicyInfos.push_back(policyInfo);
    batchUri->otherIndexes.push_back(1);
    batchUri->checkResult = { CheckResult(true, PolicyType::SELF_PATH),
        CheckResult(true, PolicyType::AUTHORIZATION_PATH) };
    batchUri->isTargetBundleUri.push_back(false);
    std::vector<PolicyInfo> policys;
    auto ret = batchUri->GetUriToGrantByPolicy(policys);
    EXPECT_TRUE(ret);
    EXPECT_EQ(policys[0].type, PolicyType::SELF_PATH);
    EXPECT_EQ(policys[1].type, PolicyType::AUTHORIZATION_PATH);
}

/**
 * @tc.number: GetUriToGrantByPolicy_0500
 * @tc.name: GetUriToGrantByPolicy
 * @tc.desc: Test GetUriToGrantByPolicy.
 */
HWTEST_F(BatchUriTest, GetUriToGrantByPolicy_0500, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    std::vector<std::string> uriVec;
    uriVec.emplace_back("file://docs/temp.txt");
    uriVec.emplace_back("file://com.example.test/temp.txt");
    batchUri->otherPolicyInfos = { PolicyInfo(), PolicyInfo() };

    uint32_t mode = 0;
    std::string callerAlterBundleName = "callerBundleName";
    std::string targetAlterBundleName = "targetBundleName";
    auto ret = batchUri->Init(uriVec, mode, callerAlterBundleName, targetAlterBundleName, false);
    EXPECT_EQ(ret, 2);

    std::vector<PolicyInfo> docsPolicyInfoVec;
    std::vector<PolicyInfo> bundlePolicyInfoVec;
    batchUri->checkResult = { CheckResult(true, 2), CheckResult(true, 2) };
    auto count = batchUri->GetUriToGrantByPolicy(docsPolicyInfoVec, bundlePolicyInfoVec);
    EXPECT_EQ(count, 2);
    EXPECT_EQ(docsPolicyInfoVec[0].type, 2);
    EXPECT_EQ(bundlePolicyInfoVec[0].type, 2);
}

/**
 * @tc.number: IsAllUriValid_0100
 * @tc.name: IsAllUriValid
 * @tc.desc: Test IsAllUriValid.
 */
HWTEST_F(BatchUriTest, IsAllUriValid_0100, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    batchUri->validUriCount = 0;
    batchUri->totalUriCount = 0;
    auto ret = batchUri->IsAllUriValid();
    EXPECT_TRUE(ret);

    batchUri->totalUriCount = 1;
    ret = batchUri->IsAllUriValid();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsAllUriPermissioned_0100
 * @tc.name: IsAllUriPermissioned
 * @tc.desc: Test IsAllUriPermissioned.
 */
HWTEST_F(BatchUriTest, IsAllUriPermissioned_0100, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    batchUri->checkResult.push_back(CheckResult(false, 0));
    auto ret = batchUri->IsAllUriPermissioned();
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: IsAllUriPermissioned_0200
 * @tc.name: IsAllUriPermissioned
 * @tc.desc: Test IsAllUriPermissioned.
 */
HWTEST_F(BatchUriTest, IsAllUriPermissioned_0200, TestSize.Level2)
{
    auto batchUri = std::make_shared<BatchUri>();
    ASSERT_NE(batchUri, nullptr);
    auto ret = batchUri->IsAllUriPermissioned();
    EXPECT_TRUE(ret);
    batchUri->checkResult.push_back(CheckResult(true, 0));
    ret = batchUri->IsAllUriPermissioned();
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: SetCheckUriAuthorizationResult_0100
 * @tc.name: SetCheckUriAuthorizationResult
 * @tc.desc: Test SetCheckUriAuthorizationResult.
 */
HWTEST_F(BatchUriTest, SetCheckUriAuthorizationResult_0100, TestSize.Level2)
{
    auto batchUri = BatchUri();
    batchUri.checkResult = { CheckResult(true, 0) };
    std::vector<bool> funcResult;
    auto ret = batchUri.SetCheckUriAuthorizationResult(funcResult);
    EXPECT_FALSE(ret);

    funcResult = { false };
    ret = batchUri.SetCheckUriAuthorizationResult(funcResult);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(funcResult[0]);
}

/**
 * @tc.number: SetCheckProxyByPolicyResult_0100
 * @tc.name: SetCheckProxyByPolicyResult
 * @tc.desc: Test SetCheckProxyByPolicyResult.
 */
HWTEST_F(BatchUriTest, SetCheckProxyByPolicyResult_0100, TestSize.Level2)
{
    auto batchUri = BatchUri();
    batchUri.proxyIndexesByPolicy = { 0 };
    batchUri.checkResult = { CheckResult(false, 0) };
    std::vector<bool> proxyResultByPolicy;
    auto ret = batchUri.SetCheckProxyByPolicyResult(proxyResultByPolicy);
    EXPECT_FALSE(ret);

    batchUri.proxyIndexesByPolicy = { 0 };
    proxyResultByPolicy = { false };
    ret = batchUri.SetCheckProxyByPolicyResult(proxyResultByPolicy);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(batchUri.checkResult[0].result);
    EXPECT_EQ(batchUri.checkResult[0].permissionType, 0);

    batchUri.proxyIndexesByPolicy = { 0 };
    proxyResultByPolicy = { true };
    batchUri.isTargetBundleUri = { true };
    ret = batchUri.SetCheckProxyByPolicyResult(proxyResultByPolicy);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(batchUri.checkResult[0].result);
    EXPECT_EQ(batchUri.checkResult[0].permissionType, PolicyType::AUTHORIZATION_PATH);
}
}
}