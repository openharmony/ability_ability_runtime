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
#include <nlohmann/json.hpp>

#include "startup_utils.h"

using namespace testing::ext;
namespace OHOS {
namespace AbilityRuntime {
class StartupUtilsTest : public testing::Test {
public:
    StartupUtilsTest()
    {}
    ~StartupUtilsTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void StartupUtilsTest::SetUpTestCase(void)
{}

void StartupUtilsTest::TearDownTestCase(void)
{}

void StartupUtilsTest::SetUp(void)
{}

void StartupUtilsTest::TearDown(void)
{}

/**
 * @tc.name: ParseJsonStringArray_001
 * @tc.desc: test ParseJsonStringArray
 * @tc.type: FUNC
 */
HWTEST_F(StartupUtilsTest, ParseJsonStringArray_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "ParseJsonStringArray_001 start";
    const std::string jsonStr = R"({
        "actions": [
            "action1",
            "action2"
        ],
        "nonArray" : "nonArray",
        "nonString": [1]
    })";
    nlohmann::json json = nlohmann::json::parse(jsonStr);

    std::vector<std::string> arr;
    StartupUtils::ParseJsonStringArray(json, "nonExist", arr);
    EXPECT_EQ(arr.size(), 0);

    std::vector<std::string> arr1;
    StartupUtils::ParseJsonStringArray(json, "nonArray", arr1);
    EXPECT_EQ(arr1.size(), 0);

    std::vector<std::string> arr2;
    StartupUtils::ParseJsonStringArray(json, "nonString", arr2);
    EXPECT_EQ(arr2.size(), 0);

    std::vector<std::string> arr3;
    StartupUtils::ParseJsonStringArray(json, "actions", arr3);
    EXPECT_EQ(arr3.size(), 2);
    GTEST_LOG_(INFO) << "ParseJsonStringArray_001 end";
}
}
}