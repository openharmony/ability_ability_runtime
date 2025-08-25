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
#include "file_permission_manager.h"
using namespace testing::ext;
namespace OHOS {
namespace AAFwk {
class FilePermissionManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void FilePermissionManagerTest::SetUpTestCase()
{}

void FilePermissionManagerTest::TearDownTestCase()
{}

void FilePermissionManagerTest::SetUp()
{}

void FilePermissionManagerTest::TearDown()
{}
/*
 * Feature: CheckUriPersistentPermission
 * Function: CheckUriPersistentPermission
 * SubFunction: NA
 * FunctionPoints: UPMSUtils CheckUriPersistentPermission
 */
HWTEST_F(FilePermissionManagerTest, CheckUriPersistentPermission_001, TestSize.Level1)
{
    std::vector<Uri> uriVec;
    uint32_t callerTokenId = 0;
    uint32_t flag = 0;
    std::vector<PolicyInfo> pathPolicies;
    auto ret = FilePermissionManager::CheckUriPersistentPermission(uriVec, callerTokenId, flag, pathPolicies, "");
    bool res = false;
    if (ret.empty()) {
        res = true;
    }
    EXPECT_EQ(res, true);
}

/*
 * Feature: GetPathPolicyInfoFromUri
 * Function: GetPathPolicyInfoFromUri
 * SubFunction: NA
 * FunctionPoints: UPMSUtils GetPathPolicyInfoFromUri
 */
HWTEST_F(FilePermissionManagerTest, GetPathPolicyInfoFromUri_001, TestSize.Level1)
{
    Uri uri("file://com.example.test/data/storage/el2/base/haps/entry/files/test_A.txt");
    uint32_t flag = 0;
    auto ret = FilePermissionManager::GetPathPolicyInfoFromUri(uri, flag);
    bool strRes = false;
    if (!ret.path.empty()) {
        strRes = true;
    }
    EXPECT_EQ(strRes, true);
}

}
}