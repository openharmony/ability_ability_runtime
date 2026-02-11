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
 * @file global_function_test.cpp
 * @brief Test suite for global function mock macros
 *
 * This file tests mock functionality for global functions:
 * - OH_MOCK_GLOBAL_METHOD
 * - OH_MOCK_GLOBAL_VOID_METHOD
 * - OH_MOCK_GLOBAL_TEMPLATE_METHOD_RET_SPTR (referenced but not used in tests)
 */

#define private public
#define protected public

#include <gtest/gtest.h>
#include <string>
#include "oh_mock_utils.h"
#include "mock_classes/test_global_functions.h"

#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::TestMock;

namespace OHOS {
namespace TestMock {

/**
 * @class GlobalFunctionTest
 * @brief Test fixture for global function macro tests
 */
class GlobalFunctionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void GlobalFunctionTest::SetUpTestCase() {}

void GlobalFunctionTest::TearDownTestCase() {}

void GlobalFunctionTest::SetUp() {}

void GlobalFunctionTest::TearDown() {}

// ============================================================================
// OH_MOCK_GLOBAL_METHOD Tests
// ============================================================================

/**
 * @tc.name: GlobalCalculate_GlobalFunction_001
 * @tc.desc: Test OH_MOCK_GLOBAL_METHOD with global function
 *           Branch: Normal execution - global function call
 * @tc.type: FUNC
 */
HWTEST_F(GlobalFunctionTest, GlobalCalculate_GlobalFunction_001, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    auto expectRets = std::vector<int>{50};
    OH_GLOBAL_EXPECT_RET(expectRets, GlobalCalculate, int, int);

    // ===== Act: Call the code under test =====
    int result = GlobalCalculate(10, 20);

    // ===== Assert: Verify results =====
    EXPECT_EQ(result, 50);
}

/**
 * @tc.name: GlobalCalculate_MultipleCalls_002
 * @tc.desc: Test queue mechanism for global functions
 *           Branch: Multiple calls consume global function queue
 * @tc.type: FUNC
 */
HWTEST_F(GlobalFunctionTest, GlobalCalculate_MultipleCalls_002, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    auto expectRets = std::vector<int>{10, 20, 30};
    OH_GLOBAL_EXPECT_RET(expectRets, GlobalCalculate, int, int);

    // ===== Act: Multiple calls =====
    int result1 = GlobalCalculate(1, 1);
    int result2 = GlobalCalculate(2, 2);
    int result3 = GlobalCalculate(3, 3);

    // ===== Assert: Verify queue order =====
    EXPECT_EQ(result1, 10);
    EXPECT_EQ(result2, 20);
    EXPECT_EQ(result3, 30);
}
} // namespace TestMock
} // namespace OHOS
