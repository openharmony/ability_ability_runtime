/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

/**
 * @file output_param_test.cpp
 * @brief Test suite for output parameter macros
 *
 * This file tests mock functionality with output parameters:
 * - OH_MOCK_METHOD_WITH_OUTPUT_1 (scalar output)
 * - OH_MOCK_METHOD_WITH_OUTPUT_VECTOR (vector output)
 * - OH_MOCK_METHOD_WITH_DECORATOR_AND_OUTPUT_1 (static + scalar output)
 * - OH_MOCK_METHOD_WITH_DECORATOR_AND_OUTPUT_VECTOR (static + vector output)
 */

#define private public
#define protected public

#include <gtest/gtest.h>
#include <vector>
#include <string>
#include "oh_mock_utils.h"
#include "mock_classes/test_class_with_output.h"
#include "mock_classes/test_class_decorator.h"

#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::TestMock;

namespace OHOS {
namespace TestMock {

/**
 * @class OutputParamTest
 * @brief Test fixture for output parameter macro tests
 */
class OutputParamTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void OutputParamTest::SetUpTestCase() {}

void OutputParamTest::TearDownTestCase() {}

void OutputParamTest::SetUp() {}

void OutputParamTest::TearDown() {}

// ============================================================================
// OH_MOCK_METHOD_WITH_OUTPUT_1 Tests (Scalar Output)
// ============================================================================

/**
 * @tc.name: ProcessData_ScalarOutputSuccess_001
 * @tc.desc: Test OH_MOCK_METHOD_WITH_OUTPUT_1 with scalar output parameter
 *           Branch: Return value and output parameter both set correctly
 * @tc.type: FUNC
 */
HWTEST_F(OutputParamTest, ProcessData_ScalarOutputSuccess_001, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassWithOutput testObj;
    int32_t inputVal = 100;
    std::string inputStr = "test";
    int32_t outputResult;

    auto expectRets = std::vector<int32_t>{0};
    auto expectOutputs = std::vector<std::vector<int32_t>>{{42}};
    OH_EXPECT_RET_AND_OUTPUT(expectRets, expectOutputs, TestClassWithOutput, ProcessData,
        int32_t, const std::string&, int32_t& result);

    // ===== Act: Call the code under test =====
    int32_t ret = testObj.ProcessData(inputVal, inputStr, outputResult);

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(outputResult, 42);
}

/**
 * @tc.name: ProcessData_MultipleCallsScalar_002
 * @tc.desc: Test queue mechanism for scalar output parameters
 *           Branch: Multiple calls with queued scalar outputs
 * @tc.type: FUNC
 */
HWTEST_F(OutputParamTest, ProcessData_MultipleCallsScalar_002, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassWithOutput testObj;

    auto expectRets = std::vector<int32_t>{0, 0};
    auto expectOutputs = std::vector<std::vector<int32_t>>{{10}, {20}};
    OH_EXPECT_RET_AND_OUTPUT(expectRets, expectOutputs, TestClassWithOutput, ProcessData,
        int32_t, const std::string&, int32_t& result);

    // ===== Act: Multiple calls =====
    int32_t output1 = 0;
    int32_t output2 = 0;
    int32_t ret1 = testObj.ProcessData(1, "test1", output1);
    int32_t ret2 = testObj.ProcessData(2, "test2", output2);

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret1, 0);
    EXPECT_EQ(ret2, 0);
    EXPECT_EQ(output1, 10);
    EXPECT_EQ(output2, 20);
}

/**
 * @tc.name: ProcessData_ScalarEmptyQueue_003
 * @tc.desc: Test scalar output with empty queue
 *           Branch: Edge case - empty expectation queue for scalar output
 * @tc.type: FUNC
 */
HWTEST_F(OutputParamTest, ProcessData_ScalarEmptyQueue_003, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassWithOutput testObj;
    int32_t outputResult = 999;  // Initial value

    // No expectations set

    // ===== Act: Call the code under test =====
    int32_t ret = testObj.ProcessData(100, "test", outputResult);

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret, 0);  // Default return value
    EXPECT_EQ(outputResult, 0);  // Should remain unchanged (no output set)
}

// ============================================================================
// OH_MOCK_METHOD_WITH_OUTPUT_VECTOR Tests (Vector Output)
// ============================================================================

/**
 * @tc.name: GetItems_VectorOutputSuccess_004
 * @tc.desc: Test OH_MOCK_METHOD_WITH_OUTPUT_VECTOR with vector output
 *           Branch: Vector output parameter populated with all elements
 * @tc.type: FUNC
 */
HWTEST_F(OutputParamTest, GetItems_VectorOutputSuccess_004, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassWithOutput testObj;

    auto expectRets = std::vector<int32_t>{0};
    auto expectOutputs = std::vector<std::vector<int32_t>>{{1, 2, 3, 4, 5}};
    OH_EXPECT_RET_AND_OUTPUT(expectRets, expectOutputs, TestClassWithOutput, GetItems,
        uint32_t, std::vector<int32_t>& items);

    // ===== Act: Call the code under test =====
    std::vector<int32_t> items;
    int32_t ret = testObj.GetItems(5, items);

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(items.size(), 5U);
    EXPECT_EQ(items[0], 1);
    EXPECT_EQ(items[1], 2);
    EXPECT_EQ(items[2], 3);
    EXPECT_EQ(items[3], 4);
    EXPECT_EQ(items[4], 5);
}

/**
 * @tc.name: GetItems_MultipleCallsVector_005
 * @tc.desc: Test queue mechanism for vector output parameters
 *           Branch: Multiple calls with queued vector outputs
 * @tc.type: FUNC
 */
HWTEST_F(OutputParamTest, GetItems_MultipleCallsVector_005, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassWithOutput testObj;

    auto expectRets = std::vector<int32_t>{0, 0};
    auto expectOutputs = std::vector<std::vector<int32_t>>{
        {1, 2},
        {3, 4, 5}
    };
    OH_EXPECT_RET_AND_OUTPUT(expectRets, expectOutputs, TestClassWithOutput, GetItems,
        uint32_t, std::vector<int32_t>& items);

    // ===== Act: Multiple calls =====
    std::vector<int32_t> items1;
    std::vector<int32_t> items2;
    int32_t ret1 = testObj.GetItems(2, items1);
    int32_t ret2 = testObj.GetItems(3, items2);

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret1, 0);
    EXPECT_EQ(ret2, 0);
    EXPECT_EQ(items1.size(), 2U);
    EXPECT_EQ(items2.size(), 3U);
    EXPECT_EQ(items1[0], 1);
    EXPECT_EQ(items2[2], 5);
}

/**
 * @tc.name: GetItems_EmptyVectorOutput_006
 * @tc.desc: Test vector output with empty result
 *           Branch: Edge case - empty vector output
 * @tc.type: FUNC
 */
HWTEST_F(OutputParamTest, GetItems_EmptyVectorOutput_006, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassWithOutput testObj;

    auto expectRets = std::vector<int32_t>{0};
    auto expectOutputs = std::vector<std::vector<int32_t>>{{}};  // Empty vector
    OH_EXPECT_RET_AND_OUTPUT(expectRets, expectOutputs, TestClassWithOutput, GetItems,
        uint32_t, std::vector<int32_t>& items);

    // ===== Act: Call the code under test =====
    std::vector<int32_t> items;
    int32_t ret = testObj.GetItems(0, items);

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE(items.empty());
}

/**
 * @tc.name: GetItems_LargeVectorOutput_007
 * @tc.desc: Test vector output with large dataset (1000+ elements)
 *           Branch: Edge case - large vector handling
 * @tc.type: FUNC
 */
HWTEST_F(OutputParamTest, GetItems_LargeVectorOutput_007, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassWithOutput testObj;

    // Prepare large vector with 1000 elements
    std::vector<int32_t> largeVector;
    for (int i = 0; i < 1000; i++) {
        largeVector.push_back(i);
    }

    auto expectRets = std::vector<int32_t>{0};
    auto expectOutputs = std::vector<std::vector<int32_t>>{largeVector};
    OH_EXPECT_RET_AND_OUTPUT(expectRets, expectOutputs, TestClassWithOutput, GetItems,
        uint32_t, std::vector<int32_t>& items);

    // ===== Act: Call the code under test =====
    std::vector<int32_t> items;
    int32_t ret = testObj.GetItems(1000, items);

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(items.size(), 1000U);
    EXPECT_EQ(items[0], 0);
    EXPECT_EQ(items[999], 999);
}

// ============================================================================
// OH_MOCK_METHOD_WITH_DECORATOR_AND_OUTPUT_1 Tests (Static + Scalar Output)
// ============================================================================

/**
 * @tc.name: GetUserInfo_StaticWithOutput_008
 * @tc.desc: Test OH_MOCK_METHOD_WITH_DECORATOR_AND_OUTPUT_1 with static method
 *           Branch: Static method with struct output parameter
 * @tc.type: FUNC
 */
HWTEST_F(OutputParamTest, GetUserInfo_StaticWithOutput_008, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    UserInfo expectedUserInfo;
    expectedUserInfo.userId = 1001;
    expectedUserInfo.userName = "TestUser";

    auto expectRets = std::vector<int>{0};
    auto expectOutputs = std::vector<std::vector<UserInfo>>{{expectedUserInfo}};
    OH_EXPECT_RET_AND_OUTPUT(expectRets, expectOutputs, TestClassDecorator, GetUserInfo,
        uint32_t, UserInfo& userInfo);

    // ===== Act: Call the code under test =====
    UserInfo result;
    int ret = TestClassDecorator::GetUserInfo(1001, result);

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(result.userId, 1001);
    EXPECT_EQ(result.userName, "TestUser");
}

/**
 * @tc.name: GetUserInfo_StaticMultipleCalls_009
 * @tc.desc: Test static method with scalar output in queue
 *           Branch: Multiple static calls with queued scalar outputs
 * @tc.type: FUNC
 */
HWTEST_F(OutputParamTest, GetUserInfo_StaticMultipleCalls_009, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    UserInfo user1, user2;
    user1.userId = 1001;
    user1.userName = "User1";
    user2.userId = 1002;
    user2.userName = "User2";

    auto expectRets = std::vector<int>{0, 0};
    auto expectOutputs = std::vector<std::vector<UserInfo>>{{user1}, {user2}};
    OH_EXPECT_RET_AND_OUTPUT(expectRets, expectOutputs, TestClassDecorator, GetUserInfo,
        uint32_t, UserInfo& userInfo);

    // ===== Act: Multiple calls =====
    UserInfo result1, result2;
    int ret1 = TestClassDecorator::GetUserInfo(1001, result1);
    int ret2 = TestClassDecorator::GetUserInfo(1002, result2);

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret1, 0);
    EXPECT_EQ(ret2, 0);
    EXPECT_EQ(result1.userId, 1001);
    EXPECT_EQ(result2.userId, 1002);
}

// ============================================================================
// OH_MOCK_METHOD_WITH_DECORATOR_AND_OUTPUT_VECTOR Tests (Static + Vector Output)
// ============================================================================

/**
 * @tc.name: GetPermissions_StaticWithVector_010
 * @tc.desc: Test OH_MOCK_METHOD_WITH_DECORATOR_AND_OUTPUT_VECTOR
 *           Branch: Static method with vector output parameter
 * @tc.type: FUNC
 */
HWTEST_F(OutputParamTest, GetPermissions_StaticWithVector_010, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    auto expectRets = std::vector<int>{0};
    auto expectOutputs = std::vector<std::vector<std::string>>{
        {"read", "write", "execute"}
    };
    OH_EXPECT_RET_AND_OUTPUT(expectRets, expectOutputs, TestClassDecorator, GetPermissions,
        uint32_t, std::vector<std::string>& permissions);

    // ===== Act: Call the code under test =====
    std::vector<std::string> permissions;
    int ret = TestClassDecorator::GetPermissions(1001, permissions);

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(permissions.size(), 3U);
    EXPECT_EQ(permissions[0], "read");
    EXPECT_EQ(permissions[1], "write");
    EXPECT_EQ(permissions[2], "execute");
}

/**
 * @tc.name: GetPermissions_StaticMultipleCalls_011
 * @tc.desc: Test static method with vector output in queue
 *           Branch: Multiple static calls with queued vector outputs
 * @tc.type: FUNC
 */
HWTEST_F(OutputParamTest, GetPermissions_StaticMultipleCalls_011, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    auto expectRets = std::vector<int>{0, 0};
    auto expectOutputs = std::vector<std::vector<std::string>>{
        {"permission1"},
        {"permission2", "permission3"}
    };
    OH_EXPECT_RET_AND_OUTPUT(expectRets, expectOutputs, TestClassDecorator, GetPermissions,
        uint32_t, std::vector<std::string>& permissions);

    // ===== Act: Multiple calls =====
    std::vector<std::string> perms1, perms2;
    int ret1 = TestClassDecorator::GetPermissions(1001, perms1);
    int ret2 = TestClassDecorator::GetPermissions(1002, perms2);

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret1, 0);
    EXPECT_EQ(ret2, 0);
    EXPECT_EQ(perms1.size(), 1U);
    EXPECT_EQ(perms2.size(), 2U);
    EXPECT_EQ(perms1[0], "permission1");
    EXPECT_EQ(perms2[1], "permission3");
}

// ============================================================================
// Complex Scenario Tests
// ============================================================================

/**
 * @tc.name: CheckPermissions_MixedUris_012
 * @tc.desc: Test OH_MOCK_METHOD_WITH_OUTPUT_VECTOR with mixed true/false results
 *           Branch: Real-world scenario - permission check with mixed results
 * @tc.type: FUNC
 */
HWTEST_F(OutputParamTest, CheckPermissions_MixedUris_012, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassWithOutput testObj;

    std::vector<std::string> uris = {
        "file://photo1.jpg",
        "file://photo2.jpg",
        "file://photo3.jpg",
        "file://photo4.jpg"
    };
    std::vector<uint32_t> flags = {1, 1, 1, 1};

    auto expectRets = std::vector<int32_t>{0};
    auto expectOutputs = std::vector<std::vector<bool>>{{true, false, true, false}};
    OH_EXPECT_RET_AND_OUTPUT(expectRets, expectOutputs, TestClassWithOutput, CheckPermissions,
        uint32_t, const std::vector<std::string>&, std::vector<bool>& results, const std::vector<uint32_t>&);

    // ===== Act: Call the code under test =====
    std::vector<bool> results;
    int32_t ret = testObj.CheckPermissions(1001, uris, results, flags);

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(results.size(), 4U);
    EXPECT_TRUE(results[0]);
    EXPECT_FALSE(results[1]);
    EXPECT_TRUE(results[2]);
    EXPECT_FALSE(results[3]);
}

/**
 * @tc.name: ProcessData_RetAndOutputCombo_013
 * @tc.desc: Test combination of return value and output parameter
 *           Branch: Verify both return value and output are set correctly
 * @tc.type: FUNC
 */
HWTEST_F(OutputParamTest, ProcessData_RetAndOutputCombo_013, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassWithOutput testObj;

    auto expectRets = std::vector<int32_t>{100};  // Special return code
    auto expectOutputs = std::vector<std::vector<int32_t>>{{42}};
    OH_EXPECT_RET_AND_OUTPUT(expectRets, expectOutputs, TestClassWithOutput, ProcessData,
        int32_t, const std::string&, int32_t& result);

    // ===== Act: Call the code under test =====
    int32_t outputResult;
    int32_t ret = testObj.ProcessData(999, "important", outputResult);

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret, 100);  // Special return code
    EXPECT_EQ(outputResult, 42);
}

} // namespace TestMock
} // namespace OHOS
