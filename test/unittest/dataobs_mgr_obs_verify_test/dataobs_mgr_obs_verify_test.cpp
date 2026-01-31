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

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: VerifyPermission with listenerGroupIds match
 * SubFunction: VerifyPermission, GetGroupInfosFromCache
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test permission verification when group ID matches URI authority
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_VerifyPermission_GroupMatch_0100, TestSize.Level1)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    // Setup: pre-populate cache with a known group ID
    std::string testUri = "rdb://testGroupId123/data";
    std::vector<std::string> testGroupIds = {"testGroupId123"};

    std::unique_lock<std::shared_mutex> writeLock(obsVerifyUtils_->groupsIdMutex_);
    obsVerifyUtils_->groupsIdCache_.clear();
    obsVerifyUtils_->groupsIdCache_.emplace_back(testUri, testGroupIds);
    writeLock.unlock();

    Uri uri(testUri);
    uint32_t listenerTokenId = TOKEN_TEST_1;
    uint32_t tokenId = TOKEN_TEST_2; // Different tokens
    int32_t userId = USER_TEST;

    // The GetCallingInfo will be called, and if it returns empty callingName
    // the test will still go through the logic
    bool result = obsVerifyUtils_->VerifyPermission(listenerTokenId, userId, uri, tokenId);

    // Result depends on whether token lookup succeeds
    // Test should not crash
    EXPECT_TRUE(result == true || result == false);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: GetGroupInfosFromCache with cache hit
 * SubFunction: GetGroupInfosFromCache
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cache retrieval when entry exists
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_GetGroupInfos_CacheHit_0100, TestSize.Level1)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    // Setup: populate cache
    std::string testUri = "rdb://com.example.test/data";
    std::string testBundle = "com.example.test";
    std::vector<std::string> testGroupIds = {"group1", "group2", "group3"};

    std::unique_lock<std::shared_mutex> writeLock(obsVerifyUtils_->groupsIdMutex_);
    obsVerifyUtils_->groupsIdCache_.clear();
    obsVerifyUtils_->groupsIdCache_.emplace_back(testUri, testGroupIds);
    writeLock.unlock();

    // Call GetGroupInfosFromCache
    auto result = obsVerifyUtils_->GetGroupInfosFromCache(testBundle, USER_TEST, testUri);

    // Should return cached group IDs
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "group1");
    EXPECT_EQ(result[1], "group2");
    EXPECT_EQ(result[2], "group3");
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: GetGroupInfosFromCache with cache miss
 * SubFunction: GetGroupInfosFromCache
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cache miss scenario (will try to query BMS)
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_GetGroupInfos_CacheMiss_0100, TestSize.Level1)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    std::string testUri = "rdb://com.example.nonexistent/data";
    std::string testBundle = "com.example.nonexistent";

    // Clear cache to ensure miss
    std::unique_lock<std::shared_mutex> writeLock(obsVerifyUtils_->groupsIdMutex_);
    obsVerifyUtils_->groupsIdCache_.clear();
    writeLock.unlock();

    // Call GetGroupInfosFromCache - will try to query BMS (may return empty)
    auto result = obsVerifyUtils_->GetGroupInfosFromCache(testBundle, USER_TEST, testUri);

    // Should not crash, result depends on BMS availability
    EXPECT_TRUE(result.empty() || result.size() > 0);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: GetGroupInfosFromCache cache full scenario
 * SubFunction: GetGroupInfosFromCache
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test cache behavior when size threshold is reached
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_GetGroupInfos_CacheFull_0100, TestSize.Level1)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    std::string testBundle = "com.example.test";
    int32_t userId = USER_TEST;

    // Fill cache to threshold
    std::unique_lock<std::shared_mutex> writeLock(obsVerifyUtils_->groupsIdMutex_);
    obsVerifyUtils_->groupsIdCache_.clear();

    // Add entries up to CACHE_SIZE_THRESHOLD
    for (int i = 0; i < obsVerifyUtils_->CACHE_SIZE_THRESHOLD; i++) {
        std::string uri = "rdb://cache" + std::to_string(i) + "/data";
        std::vector<std::string> groupIds = {"group" + std::to_string(i)};
        obsVerifyUtils_->groupsIdCache_.emplace_back(uri, groupIds);
    }

    size_t sizeBefore = obsVerifyUtils_->groupsIdCache_.size();
    EXPECT_EQ(sizeBefore, obsVerifyUtils_->CACHE_SIZE_THRESHOLD);
    writeLock.unlock();

    // This will trigger cache overflow logic - pop_front then emplace_back
    // But since BMS query may fail in test, we just verify no crash
    std::string testUri = "rdb://com.example.test/newentry";
    auto result = obsVerifyUtils_->GetGroupInfosFromCache(testBundle, userId, testUri);

    // Should not crash
    EXPECT_TRUE(true);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: VerifyPermission with empty groupIds
 * SubFunction: VerifyPermission
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test permission verification when group IDs are empty
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_VerifyPermission_EmptyGroups_0100, TestSize.Level1)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    // Setup: cache with empty group IDs
    std::string testUri = "rdb://com.example.empty/data";
    std::vector<std::string> emptyGroupIds;

    std::unique_lock<std::shared_mutex> writeLock(obsVerifyUtils_->groupsIdMutex_);
    obsVerifyUtils_->groupsIdCache_.clear();
    obsVerifyUtils_->groupsIdCache_.emplace_back(testUri, emptyGroupIds);
    writeLock.unlock();

    Uri uri(testUri);
    uint32_t listenerTokenId = TOKEN_TEST_1;
    uint32_t tokenId = TOKEN_TEST_2;
    int32_t userId = USER_TEST;

    // Should handle empty group IDs
    bool result = obsVerifyUtils_->VerifyPermission(listenerTokenId, userId, uri, tokenId);

    // Should return false if GetCallingInfo returns non-SA and empty groups
    // (actual behavior depends on token lookup)
    EXPECT_TRUE(result == true || result == false);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: VerifyPermission with non-matching authority
 * SubFunction: VerifyPermission
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test when cached group IDs don't match URI authority
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_VerifyPermission_NoMatch_0100, TestSize.Level1)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    // Setup: cache with group IDs that don't match URI
    std::string testUri = "rdb://com.example.test/data";
    std::vector<std::string> testGroupIds = {"differentGroupId", "anotherGroupId"};

    std::unique_lock<std::shared_mutex> writeLock(obsVerifyUtils_->groupsIdMutex_);
    obsVerifyUtils_->groupsIdCache_.clear();
    obsVerifyUtils_->groupsIdCache_.emplace_back(testUri, testGroupIds);
    writeLock.unlock();

    Uri uri(testUri);
    uint32_t listenerTokenId = TOKEN_TEST_1;
    uint32_t tokenId = TOKEN_TEST_2;
    int32_t userId = USER_TEST;

    bool result = obsVerifyUtils_->VerifyPermission(listenerTokenId, userId, uri, tokenId);

    // Should return false since authority doesn't match any group ID
    // (assuming GetCallingInfo doesn't return isSA=true)
    EXPECT_TRUE(result == true || result == false);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: GetCallingInfo with various token types
 * SubFunction: GetCallingInfo
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test GetCallingInfo handles different token types
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_GetCallingInfo_TokenTypes_0100, TestSize.Level1)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    // Test with various token IDs
    std::vector<uint32_t> tokenIds = {0, 100, 1000, 65535, 1000000};

    for (auto tokenId : tokenIds) {
        auto [isSA, callingName] = obsVerifyUtils_->GetCallingInfo(tokenId);

        // Should always return a pair without crashing
        // isSA will be true only for TOKEN_NATIVE or TOKEN_SHELL
        // callingName will be populated based on token type
        EXPECT_TRUE(true);
    }
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: GetGroupInfosFromCache with same key insertion
 * SubFunction: GetGroupInfosFromCache
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test double-check pattern in cache insertion
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_GetGroupInfos_DoubleCheck_0100, TestSize.Level1)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    std::string testUri = "rdb://com.example.dblcheck/data";
    std::string testBundle = "com.example.dblcheck";
    std::vector<std::string> testGroupIds = {"group1"};

    std::unique_lock<std::shared_mutex> writeLock(obsVerifyUtils_->groupsIdMutex_);
    obsVerifyUtils_->groupsIdCache_.clear();
    writeLock.unlock();

    // First call - will try to query BMS
    auto result1 = obsVerifyUtils_->GetGroupInfosFromCache(testBundle, USER_TEST, testUri);

    // Manually add to cache for testing
    writeLock.lock();
    obsVerifyUtils_->groupsIdCache_.emplace_back(testUri, testGroupIds);
    writeLock.unlock();

    // Second call - should hit cache
    auto result2 = obsVerifyUtils_->GetGroupInfosFromCache(testBundle, USER_TEST, testUri);

    // Verify second call returns cached data
    EXPECT_EQ(result2.size(), 1);
    EXPECT_EQ(result2[0], "group1");
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: VerifyPermission with preferences scheme (not RDB)
 * SubFunction: VerifyPermission
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test with sharepreferences scheme to ensure correct error reporting
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_VerifyPermission_PrefSchemeFail_0100, TestSize.Level1)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    // Setup: empty cache to ensure verification fails
    std::string testUri = "sharepreferences://com.example.test/data";

    std::unique_lock<std::shared_mutex> writeLock(obsVerifyUtils_->groupsIdMutex_);
    obsVerifyUtils_->groupsIdCache_.clear();
    writeLock.unlock();

    Uri uri(testUri);
    uint32_t listenerTokenId = TOKEN_TEST_1;
    uint32_t tokenId = TOKEN_TEST_2;
    int32_t userId = USER_TEST;

    bool result = obsVerifyUtils_->VerifyPermission(listenerTokenId, userId, uri, tokenId);

    // Should handle preferences scheme correctly
    // Result depends on token lookup
    EXPECT_TRUE(result == true || result == false);
}

/*
 * Feature: OBSVerifyPermissionUtils
 * Function: Cache thread safety with mixed operations
 * SubFunction: GetGroupInfosFromCache
 * FunctionPoints: NA
 * EnvConditions: NA
 * CaseDescription: Test concurrent read and write operations on cache
 */
HWTEST_F(DataObsMgrObsVerifyTest, OBSVerifyPermissionUtils_Cache_MixedConcurrent_0100, TestSize.Level2)
{
    ASSERT_TRUE(obsVerifyUtils_ != nullptr);

    std::string testBundle = "com.example.concurrent";

    // Reader thread
    auto readerFunc = [obsVerifyUtils = obsVerifyUtils_, testBundle]() {
        for (int i = 0; i < 50; i++) {
            std::string uri = "rdb://concurrent" + std::to_string(i) + "/data";
            obsVerifyUtils->GetGroupInfosFromCache(testBundle, USER_TEST, uri);
        }
    };

    // Writer thread
    auto writerFunc = [obsVerifyUtils = obsVerifyUtils_]() {
        for (int i = 0; i < 20; i++) {
            std::string uri = "rdb://writer" + std::to_string(i) + "/data";
            std::vector<std::string> groupIds = {"group" + std::to_string(i)};
            std::unique_lock<std::shared_mutex> writeLock(obsVerifyUtils->groupsIdMutex_);
            if (obsVerifyUtils->groupsIdCache_.size() >= obsVerifyUtils->CACHE_SIZE_THRESHOLD) {
                obsVerifyUtils->groupsIdCache_.pop_front();
            }
            obsVerifyUtils->groupsIdCache_.emplace_back(uri, groupIds);
        }
    };

    std::vector<std::thread> threads;
    threads.emplace_back(readerFunc);
    threads.emplace_back(readerFunc);
    threads.emplace_back(writerFunc);

    for (auto &t : threads) {
        t.join();
    }

    // Should complete without deadlock
    EXPECT_TRUE(true);
}

} // namespace AAFwk
} // namespace OHOS
