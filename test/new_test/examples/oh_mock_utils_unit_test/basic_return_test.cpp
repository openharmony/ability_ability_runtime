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
 * @file basic_return_test.cpp
 * @brief Test suite for basic OH_MOCK_METHOD and OH_EXPECT_RET macros
 *
 * This file tests the fundamental mock functionality for member functions with return values.
 */

#define private public
#define protected public

#include <gtest/gtest.h>
#include <vector>
#include <string>
#include "oh_mock_utils.h"
#include "mock_classes/test_class_basic.h"

#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::TestMock;

namespace OHOS {
namespace TestMock {

/**
 * @class BasicReturnTest
 * @brief Test fixture for basic return value macro tests
 */
class BasicReturnTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    // Helper method to reset mock state
    void ClearMockState();
};

void BasicReturnTest::SetUpTestCase() {}

void BasicReturnTest::TearDownTestCase() {}

void BasicReturnTest::SetUp() {}

void BasicReturnTest::TearDown() {}

void BasicReturnTest::ClearMockState()
{
    // Mock state is automatically cleared between tests by the framework
}

/**
 * @tc.name: Calculate_SingleCallSuccess_001
 * @tc.desc: Test OH_MOCK_METHOD with single call returning mock value
 *           Branch: Normal execution with one expectation in queue
 * @tc.type: FUNC
 */
HWTEST_F(BasicReturnTest, Calculate_SingleCallSuccess_001, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassBasic testObj;
    auto expectRets = std::vector<int>{100};
    OH_EXPECT_RET(expectRets, TestClassBasic, Calculate, int, int);

    // ===== Act: Call the code under test =====
    int result = testObj.Calculate(10, 20);

    // ===== Assert: Verify results =====
    EXPECT_EQ(result, 100);
}

/**
 * @tc.name: Calculate_MultipleCallsQueue_002
 * @tc.desc: Test queue mechanism returning values in sequence
 *           Branch: Multiple calls consume expectations from queue in order
 * @tc.type: FUNC
 */
HWTEST_F(BasicReturnTest, Calculate_MultipleCallsQueue_002, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassBasic testObj;
    auto expectRets = std::vector<int>{100, 200, 300};
    OH_EXPECT_RET(expectRets, TestClassBasic, Calculate, int, int);

    // ===== Act: Multiple calls =====
    int result1 = testObj.Calculate(1, 1);
    int result2 = testObj.Calculate(2, 2);
    int result3 = testObj.Calculate(3, 3);

    // ===== Assert: Verify queue order =====
    EXPECT_EQ(result1, 100);
    EXPECT_EQ(result2, 200);
    EXPECT_EQ(result3, 300);
}

/**
 * @tc.name: Calculate_EmptyQueueReturnsDefault_003
 * @tc.desc: Test empty expectation queue returns default value
 *           Branch: Edge case - no expectations set, returns default constructed value
 * @tc.type: FUNC
 */
HWTEST_F(BasicReturnTest, Calculate_EmptyQueueReturnsDefault_003, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassBasic testObj;
    // No expectations set - queue is empty

    // ===== Act: Call the code under test =====
    int result = testObj.Calculate(10, 20);

    // ===== Assert: Verify default value =====
    EXPECT_EQ(result, 0);  // Default int value
}

/**
 * @tc.name: Calculate_DifferentReturnTypes_004
 * @tc.desc: Test mock works with different return types (int, string)
 *           Branch: Multiple methods with different return types
 * @tc.type: FUNC
 */
HWTEST_F(BasicReturnTest, Calculate_DifferentReturnTypes_004, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassBasic testObj;

    // Mock int return
    auto expectIntRets = std::vector<int>{42};
    OH_EXPECT_RET(expectIntRets, TestClassBasic, Calculate, int, int);

    // Mock string return
    auto expectStringRets = std::vector<std::string>{"Test Message"};
    OH_EXPECT_RET(expectStringRets, TestClassBasic, GetMessage, const std::string&);

    // ===== Act: Call the code under test =====
    int intResult = testObj.Calculate(5, 10);
    std::string stringResult = testObj.GetMessage("Input");

    // ===== Assert: Verify different types =====
    EXPECT_EQ(intResult, 42);
    EXPECT_EQ(stringResult, "Test Message");
}

/**
 * @tc.name: GetMessage_StringReturn_005
 * @tc.desc: Test string return value handling
 *           Branch: String type mock with multiple expectations
 * @tc.type: FUNC
 */
HWTEST_F(BasicReturnTest, GetMessage_StringReturn_005, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassBasic testObj;
    auto expectRets = std::vector<std::string>{"First", "Second", "Third"};
    OH_EXPECT_RET(expectRets, TestClassBasic, GetMessage, const std::string&);

    // ===== Act: Multiple calls =====
    std::string result1 = testObj.GetMessage("Input1");
    std::string result2 = testObj.GetMessage("Input2");
    std::string result3 = testObj.GetMessage("Input3");

    // ===== Assert: Verify results =====
    EXPECT_EQ(result1, "First");
    EXPECT_EQ(result2, "Second");
    EXPECT_EQ(result3, "Third");
}

/**
 * @tc.name: Calculate_ExpectationOverride_006
 * @tc.desc: Test new expectations replace old ones
 *           Branch: Behavior - OH_EXPECT_RET overwrites previous expectations
 * @tc.type: FUNC
 */
HWTEST_F(BasicReturnTest, Calculate_ExpectationOverride_006, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassBasic testObj;

    // Set first batch of expectations
    auto expectRets1 = std::vector<int>{100, 200};
    OH_EXPECT_RET(expectRets1, TestClassBasic, Calculate, int, int);

    // Override with new expectations
    auto expectRets2 = std::vector<int>{300, 400};
    OH_EXPECT_RET(expectRets2, TestClassBasic, Calculate, int, int);

    // ===== Act: Call the code under test =====
    int result1 = testObj.Calculate(1, 1);
    int result2 = testObj.Calculate(2, 2);

    // ===== Assert: Verify new expectation takes effect =====
    EXPECT_EQ(result1, 300);  // Should use new expectations
    EXPECT_EQ(result2, 400);
}

} // namespace TestMock
} // namespace OHOS
