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
 * @file decorator_test.cpp
 * @brief Test suite for decorator macros
 *
 * This file tests mock functionality with static/virtual decorators and
 * prefix/suffix modifiers:
 * - OH_MOCK_METHOD_WITH_DECORATOR (static)
 * - OH_MOCK_VOID_METHOD_WITH_DECORATOR (static void)
 * - OH_MOCK_METHOD_WITH_PREFIX_AMD_SUFFIX (virtual, noexcept)
 */

#define private public
#define protected public

#include <gtest/gtest.h>
#include <string>
#include "oh_mock_utils.h"
#include "mock_classes/test_class_decorator.h"
#include "mock_classes/test_class_prefix_suffix.h"

#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::TestMock;

namespace OHOS {
namespace TestMock {

/**
 * @class DecoratorTest
 * @brief Test fixture for decorator macro tests
 */
class DecoratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void DecoratorTest::SetUpTestCase() {}

void DecoratorTest::TearDownTestCase() {}

void DecoratorTest::SetUp() {}

void DecoratorTest::TearDown() {}

// ============================================================================
// OH_MOCK_METHOD_WITH_DECORATOR Tests (Static Methods)
// ============================================================================

/**
 * @tc.name: StaticCalculate_StaticMethod_001
 * @tc.desc: Test OH_MOCK_METHOD_WITH_DECORATOR with static method
 *           Branch: Normal execution - static method with decorator
 * @tc.type: FUNC
 */
HWTEST_F(DecoratorTest, StaticCalculate_StaticMethod_001, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    auto expectRets = std::vector<int>{42};
    OH_EXPECT_RET(expectRets, TestClassDecorator, StaticCalculate, int, int);

    // ===== Act: Call the code under test =====
    int result = TestClassDecorator::StaticCalculate(10, 20);

    // ===== Assert: Verify results =====
    EXPECT_EQ(result, 42);
}

/**
 * @tc.name: StaticCalculate_MultipleCallsStatic_003
 * @tc.desc: Test queue mechanism for static methods
 *           Branch: Multiple static calls consume queue in order
 * @tc.type: FUNC
 */
HWTEST_F(DecoratorTest, StaticCalculate_MultipleCallsStatic_003, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    auto expectRets = std::vector<int>{100, 200, 300};
    OH_EXPECT_RET(expectRets, TestClassDecorator, StaticCalculate, int, int);

    // ===== Act: Multiple calls =====
    int result1 = TestClassDecorator::StaticCalculate(1, 1);
    int result2 = TestClassDecorator::StaticCalculate(2, 2);
    int result3 = TestClassDecorator::StaticCalculate(3, 3);

    // ===== Assert: Verify queue order =====
    EXPECT_EQ(result1, 100);
    EXPECT_EQ(result2, 200);
    EXPECT_EQ(result3, 300);
}

/**
 * @tc.name: StaticCalculate_ExpectationOverride_007
 * @tc.desc: Test new expectations replace old ones for static methods
 *           Branch: Behavior - OH_EXPECT_RET overwrites static expectations
 * @tc.type: FUNC
 */
HWTEST_F(DecoratorTest, StaticCalculate_ExpectationOverride_007, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    // Set initial expectations
    auto expectRets1 = std::vector<int>{100, 200};
    OH_EXPECT_RET(expectRets1, TestClassDecorator, StaticCalculate, int, int);

    // Override with new expectations
    auto expectRets2 = std::vector<int>{300, 400};
    OH_EXPECT_RET(expectRets2, TestClassDecorator, StaticCalculate, int, int);

    // ===== Act: Call the code under test =====
    int result1 = TestClassDecorator::StaticCalculate(1, 1);
    int result2 = TestClassDecorator::StaticCalculate(2, 2);

    // ===== Assert: Verify new expectation takes effect =====
    EXPECT_EQ(result1, 300);  // Should use new expectations
    EXPECT_EQ(result2, 400);
}

// ============================================================================
// OH_MOCK_METHOD_WITH_PREFIX_AMD_SUFFIX Tests (Virtual, Noexcept)
// ============================================================================

/**
 * @tc.name: VirtualMethod_VirtualOverride_004
 * @tc.desc: Test OH_MOCK_METHOD_WITH_PREFIX_AMD_SUFFIX with virtual and override
 *           Branch: Normal execution - virtual method with override specifier
 * @tc.type: FUNC
 */
HWTEST_F(DecoratorTest, VirtualMethod_VirtualOverride_004, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassPrefixSuffix testObj;
    auto expectRets = std::vector<int>{99};
    OH_EXPECT_RET(expectRets, TestClassPrefixSuffix, VirtualMethod, int);

    // ===== Act: Call the code under test =====
    int result = testObj.VirtualMethod(42);

    // ===== Assert: Verify results =====
    EXPECT_EQ(result, 99);
}

/**
 * @tc.name: NoexceptMethod_NoexceptSpec_005
 * @tc.desc: Test OH_MOCK_METHOD_WITH_PREFIX_AMD_SUFFIX with noexcept specifier
 *           Branch: Normal execution - method with noexcept specifier
 * @tc.type: FUNC
 */
HWTEST_F(DecoratorTest, NoexceptMethod_NoexceptSpec_005, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassPrefixSuffix testObj;
    auto expectRets = std::vector<std::string>{"Noexcept Response"};
    OH_EXPECT_RET(expectRets, TestClassPrefixSuffix, NoexceptMethod, const std::string&);

    // ===== Act: Call the code under test =====
    std::string result = testObj.NoexceptMethod("TestInput");

    // ===== Assert: Verify results =====
    EXPECT_EQ(result, "Noexcept Response");
}

/**
 * @tc.name: NoexceptMethod_MultipleCalls_006
 * @tc.desc: Test queue mechanism with noexcept methods
 *           Branch: Multiple noexcept method calls with queue
 * @tc.type: FUNC
 */
HWTEST_F(DecoratorTest, NoexceptMethod_MultipleCalls_006, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassPrefixSuffix testObj;
    auto expectRets = std::vector<std::string>{"Response1", "Response2", "Response3"};
    OH_EXPECT_RET(expectRets, TestClassPrefixSuffix, NoexceptMethod, const std::string&);

    // ===== Act: Multiple calls =====
    std::string result1 = testObj.NoexceptMethod("Input1");
    std::string result2 = testObj.NoexceptMethod("Input2");
    std::string result3 = testObj.NoexceptMethod("Input3");

    // ===== Assert: Verify queue order =====
    EXPECT_EQ(result1, "Response1");
    EXPECT_EQ(result2, "Response2");
    EXPECT_EQ(result3, "Response3");
}

} // namespace TestMock
} // namespace OHOS
