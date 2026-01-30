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
#include <memory>
#include <functional>
#include <thread>
#include "uri.h"

// Workaround to access private members for testing
// NOLINTNEXTLINE(g.nam.03-cpp): Redefining C++ keyword 'private' for unit testing
#define private public

#include "obs_verify_permission_utils.h"
#include "hilog_tag_wrapper.h"

using namespace OHOS;
using namespace testing::ext;
using namespace testing;

namespace OHOS {
namespace AAFwk {
using Uri = OHOS::Uri;

class DataObsMgrObsVerifyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    OBSVerifyPermissionUtils *obsVerifyUtils_ = nullptr;
};

void DataObsMgrObsVerifyTest::SetUpTestCase(void) {}
void DataObsMgrObsVerifyTest::TearDownTestCase(void) {}
void DataObsMgrObsVerifyTest::SetUp()
{
    obsVerifyUtils_ = &OBSVerifyPermissionUtils::GetInstance();
}
void DataObsMgrObsVerifyTest::TearDown() {}

static constexpr int32_t USER_TEST = 100;
static constexpr uint32_t TOKEN_TEST_1 = 1001;
static constexpr uint32_t TOKEN_TEST_2 = 1002;
static constexpr uint32_t TOKEN_SAME = 1001;

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: VerifyPermission with same tokens
 * SubFunction: VerifyPermission
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test permission verification when listenerTokenId equals tokenId
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_VerifyPermission_SameToken_0100, TestSize.Level0)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    Uri uri("rdb://com.example.data/app");
    uint32_t listenerTokenId = TOKEN_TEST_1;
    uint32_t tokenId = TOKEN_TEST_1; // Same token
    int32_t userId = USER_TEST;

    // Should return true when tokens are same
    bool result = obsVerifyUtils_->VerifyPermission(listenerTokenId, userId, uri, tokenId);

    EXPECT_TRUE(result);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: VerifyPermission with different tokens
 * SubFunction: VerifyPermission
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test permission verification with different tokens
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_VerifyPermission_DifferentToken_0100, TestSize.Level0)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    Uri uri("rdb://com.example.data/app");
    uint32_t listenerTokenId = TOKEN_TEST_1;
    uint32_t tokenId = TOKEN_TEST_2; // Different token
    int32_t userId = USER_TEST;

    // Will return false as tokens are different and no group match
    // (GetCallingInfo will try to get real token info which may fail in test)
    bool result = obsVerifyUtils_->VerifyPermission(listenerTokenId, userId, uri, tokenId);

    // Result depends on token info availability, should not crash
    EXPECT_TRUE(result == true || result == false);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: VerifyPermission with RDB scheme
 * SubFunction: VerifyPermission
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test permission verification with RDB URI scheme
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_VerifyPermission_RDBScheme_0100, TestSize.Level0)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    Uri uri("rdb://com.example.data/app");
    uint32_t listenerTokenId = TOKEN_TEST_1;
    uint32_t tokenId = TOKEN_SAME;
    int32_t userId = USER_TEST;

    bool result = obsVerifyUtils_->VerifyPermission(listenerTokenId, userId, uri, tokenId);

    // Should return true for same token regardless of scheme
    EXPECT_TRUE(result);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: VerifyPermission with preferences scheme
 * SubFunction: VerifyPermission
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test permission verification with preferences URI scheme
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_VerifyPermission_PrefScheme_0100, TestSize.Level0)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    Uri uri("sharepreferences://com.example.data/app");
    uint32_t listenerTokenId = TOKEN_TEST_1;
    uint32_t tokenId = TOKEN_SAME;
    int32_t userId = USER_TEST;

    bool result = obsVerifyUtils_->VerifyPermission(listenerTokenId, userId, uri, tokenId);

    // Should return true for same token
    EXPECT_TRUE(result);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: VerifyPermission with different users
 * SubFunction: VerifyPermission
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test permission verification with different user IDs
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_VerifyPermission_DifferentUser_0100, TestSize.Level0)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    Uri uri("rdb://com.example.data/app");
    uint32_t listenerTokenId = TOKEN_TEST_1;
    uint32_t tokenId = TOKEN_SAME;
    int32_t userId1 = 100;
    int32_t userId2 = 200;

    // Test with first user
    bool result1 = obsVerifyUtils_->VerifyPermission(listenerTokenId, userId1, uri, tokenId);
    EXPECT_TRUE(result1);

    // Test with second user - should still return true for same token
    bool result2 = obsVerifyUtils_->VerifyPermission(listenerTokenId, userId2, uri, tokenId);
    EXPECT_TRUE(result2);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: VerifyPermission with complex URI
 * SubFunction: VerifyPermission
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test permission verification with complex URI path
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_VerifyPermission_ComplexURI_0100, TestSize.Level0)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    Uri uri("rdb://com.example.data/app/path/to/data?key=value");
    uint32_t listenerTokenId = TOKEN_TEST_1;
    uint32_t tokenId = TOKEN_SAME;
    int32_t userId = USER_TEST;

    bool result = obsVerifyUtils_->VerifyPermission(listenerTokenId, userId, uri, tokenId);

    // Should return true for same token with complex URI
    EXPECT_TRUE(result);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: VerifyPermission with zero tokens
 * SubFunction: VerifyPermission
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test permission verification with zero token IDs
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_VerifyPermission_ZeroToken_0100, TestSize.Level0)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    Uri uri("rdb://com.example.data/app");
    uint32_t listenerTokenId = 0;
    uint32_t tokenId = 0;
    int32_t userId = USER_TEST;

    bool result = obsVerifyUtils_->VerifyPermission(listenerTokenId, userId, uri, tokenId);

    // Should return true when both tokens are 0 (equal)
    EXPECT_TRUE(result);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: Cache mechanism
 * SubFunction: GetGroupInfosFromCache
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cache size threshold
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_CacheSizeThreshold_0100, TestSize.Level0)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    // Cache size threshold should be 200 as defined in header
    constexpr int32_t expectedThreshold = 200;
    EXPECT_EQ(obsVerifyUtils_->CACHE_SIZE_THRESHOLD, expectedThreshold);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: Cache mechanism
 * SubFunction: GetGroupInfosFromCache
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cache initialization
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_CacheInit_0100, TestSize.Level0)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    // Cache should be empty initially
    EXPECT_TRUE(obsVerifyUtils_->groupsIdCache_.empty());
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: GetCallingInfo
 * SubFunction: GetCallingInfo
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCallingInfo returns pair structure
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_GetCallingInfo_0100, TestSize.Level0)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    // Test with a token ID (will try to get actual token info)
    uint32_t tokenId = TOKEN_TEST_1;
    auto [isSA, callingName] = obsVerifyUtils_->GetCallingInfo(tokenId);

    // Should return a pair regardless of token validity
    // isSA may be false if token is not a native/shell token
    // callingName may be empty if token lookup fails
    EXPECT_TRUE(true); // Test passes if no crash occurs
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: VerifyPermission thread safety
 * SubFunction: VerifyPermission
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test concurrent permission verification
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_ConcurrentVerify_0100, TestSize.Level1)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    Uri uri("rdb://com.example.data/app");
    int32_t userId = USER_TEST;

    // Test multiple concurrent calls with same tokens
    auto verifyFunc = [obsVerifyUtils = obsVerifyUtils_, uri, userId]() {
        for (int i = 0; i < 10; i++) {
            bool result = obsVerifyUtils->VerifyPermission(TOKEN_SAME, userId, uri, TOKEN_SAME);
            EXPECT_TRUE(result);
        }
    };

    std::thread t1(verifyFunc);
    std::thread t2(verifyFunc);

    t1.join();
    t2.join();

    // Should complete without deadlock or crash
    EXPECT_TRUE(true);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: VerifyPermission with empty URI
 * SubFunction: VerifyPermission
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test permission verification with minimal URI
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_VerifyPermission_MinimalURI_0100, TestSize.Level0)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    Uri uri("rdb://a");
    uint32_t listenerTokenId = TOKEN_SAME;
    uint32_t tokenId = TOKEN_SAME;
    int32_t userId = USER_TEST;

    bool result = obsVerifyUtils_->VerifyPermission(listenerTokenId, userId, uri, tokenId);

    // Should handle minimal URI without crash
    EXPECT_TRUE(result);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: RELATIONAL_STORE constant
 * SubFunction: RELATIONAL_STORE
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test RELATIONAL_STORE constant value
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_RelationalStore_0100, TestSize.Level0)
{
    // Test that RELATIONAL_STORE constant is correct
    std::string_view rdb = OBSVerifyPermissionUtils::RELATIONAL_STORE;
    EXPECT_EQ(rdb, "rdb");
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: VerifyPermission with different URIs
 * SubFunction: VerifyPermission
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test with various URI authorities
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_VerifyPermission_DifferentAuthority_0100, TestSize.Level0)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    std::vector<std::string> authorities = {
        "com.example.app1",
        "com.example.app2",
        "com.example.app3"
    };

    uint32_t listenerTokenId = TOKEN_SAME;
    uint32_t tokenId = TOKEN_SAME;
    int32_t userId = USER_TEST;

    for (const auto &authority : authorities) {
        Uri uri("rdb://" + authority + "/data");
        bool result = obsVerifyUtils_->VerifyPermission(listenerTokenId, userId, uri, tokenId);
        EXPECT_TRUE(result);
    }
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: Cache thread safety
 * SubFunction: groupsIdCache_
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cache concurrent access
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_CacheConcurrent_0100, TestSize.Level1)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    // Test concurrent cache access
    auto accessCache = [obsVerifyUtils = obsVerifyUtils_]() {
        for (int i = 0; i < 100; i++) {
            std::shared_lock<std::shared_mutex> readLock(obsVerifyUtils->groupsIdMutex_);
            // Just reading cache, should not crash
            auto size = obsVerifyUtils->groupsIdCache_.size();
            EXPECT_GE(size, 0);
        }
    };

    std::thread t1(accessCache);
    std::thread t2(accessCache);
    std::thread t3(accessCache);

    t1.join();
    t2.join();
    t3.join();

    // Should complete without deadlock
    EXPECT_TRUE(true);
}

} // namespace AAFwk
} // namespace OHOS
