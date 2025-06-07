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
{}

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
    batchUri->checkResult.push_back(false);
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
    batchUri->checkResult.push_back(true);
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
    batchUri->otherPolicyInfos.push_back(policyInfo);
    batchUri->otherIndexes.push_back(0);
    batchUri->checkResult.push_back(true);
    batchUri->isTargetBundleUri.push_back(false);
    std::vector<PolicyInfo> policys;
    auto ret = batchUri->GetUriToGrantByPolicy(policys);
    EXPECT_TRUE(ret);
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
    batchUri->checkResult.push_back(false);
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
    batchUri->checkResult.push_back(true);
    ret = batchUri->IsAllUriPermissioned();
    EXPECT_TRUE(ret);
}
}
}