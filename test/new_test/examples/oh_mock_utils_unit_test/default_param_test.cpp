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
 * @file default_param_test.cpp
 * @brief Test suite for OH_MOCK_FUNCTION_WITH_DEFAULT_PARAM_BODY macro
 *
 * This file tests mock functionality for methods with default parameters.
 */

#define private public
#define protected public

#include <gtest/gtest.h>
#include <string>
#include "oh_mock_utils.h"
#include "mock_classes/test_class_default_param.h"

#undef private
#undef protected

using namespace testing;
using namespace testing::ext;
using namespace OHOS::TestMock;

namespace OHOS {
namespace TestMock {

/**
 * @class DefaultParamTest
 * @brief Test fixture for default parameter tests
 */
class DefaultParamTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void DefaultParamTest::SetUpTestCase() {}

void DefaultParamTest::TearDownTestCase() {}

void DefaultParamTest::SetUp() {}

void DefaultParamTest::TearDown() {}

/**
 * @tc.name: ProcessData_WithDefaultParam_001
 * @tc.desc: Test OH_MOCK_FUNCTION_WITH_DEFAULT_PARAM_BODY with default parameter
 *           Branch: Method called using default parameter value
 * @tc.type: FUNC
 */
HWTEST_F(DefaultParamTest, ProcessData_WithDefaultParam_001, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassDefaultParam testObj;
    auto expectRets = std::vector<int>{0};
    OH_EXPECT_RET(expectRets, TestClassDefaultParam, ProcessData, const std::string&, int);

    // ===== Act: Call the code under test (using default parameter timeout=5000) =====
    int ret = testObj.ProcessData("TestData");

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: ProcessData_WithExplicitParam_002
 * @tc.desc: Test explicit parameter overrides default value
 *           Branch: Method called with explicit parameter
 * @tc.type: FUNC
 */
HWTEST_F(DefaultParamTest, ProcessData_WithExplicitParam_002, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassDefaultParam testObj;
    auto expectRets = std::vector<int>{0};
    OH_EXPECT_RET(expectRets, TestClassDefaultParam, ProcessData, const std::string&, int);

    // ===== Act: Call the code under test (explicitly specify timeout=3000) =====
    int ret = testObj.ProcessData("TestData", 3000);

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret, 0);
}

/**
 * @tc.name: ProcessData_MixedCalls_003
 * @tc.desc: Test mixing default and explicit parameter calls
 *           Branch: Mixed usage pattern with default and explicit parameters
 * @tc.type: FUNC
 */
HWTEST_F(DefaultParamTest, ProcessData_MixedCalls_003, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassDefaultParam testObj;
    auto expectRets = std::vector<int>{0, 0};
    OH_EXPECT_RET(expectRets, TestClassDefaultParam, ProcessData, const std::string&, int);

    // ===== Act: Mixed calls with default and explicit parameters =====
    int ret1 = testObj.ProcessData("TestData1");              // Using default timeout
    int ret2 = testObj.ProcessData("TestData2", 2000);          // Using explicit timeout

    // ===== Assert: Verify results =====
    EXPECT_EQ(ret1, 0);
    EXPECT_EQ(ret2, 0);
}

/**
 * @tc.name: ProcessData_QueueWithDefault_004
 * @tc.desc: Test queue mechanism works with default parameter methods
 *           Branch: Multiple calls with default parameter in queue
 * @tc.type: FUNC
 */
HWTEST_F(DefaultParamTest, ProcessData_QueueWithDefault_004, TestSize.Level1)
{
    // ===== Arrange: Prepare test data and mock =====
    TestClassDefaultParam testObj;
    auto expectRets = std::vector<int>{100, 200, 300};
    OH_EXPECT_RET(expectRets, TestClassDefaultParam, ProcessData, const std::string&, int);

    // ===== Act: Multiple calls (all using default parameter) =====
    int ret1 = testObj.ProcessData("Test1");
    int ret2 = testObj.ProcessData("Test2");
    int ret3 = testObj.ProcessData("Test3");

    // ===== Assert: Verify queue order =====
    EXPECT_EQ(ret1, 100);
    EXPECT_EQ(ret2, 200);
    EXPECT_EQ(ret3, 300);
}

} // namespace TestMock
} // namespace OHOS
