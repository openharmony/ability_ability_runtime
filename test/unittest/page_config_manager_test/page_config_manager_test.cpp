/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "ability_manager_errors.h"
#include "window.h"

#define private public
#include "page_config_manager.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AAFwk {
class PageConfigManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void PageConfigManagerTest::SetUpTestCase(void)
{}

void PageConfigManagerTest::TearDownTestCase(void)
{}

void PageConfigManagerTest::SetUp()
{}

void PageConfigManagerTest::TearDown()
{}

/**
 * @tc.name: Initialize_0100
 * @tc.desc: Initialize
 * @tc.type: FUNC
 */
HWTEST_F(PageConfigManagerTest, Initialize_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PageConfigManagerTest, Initialize_0100, TestSize.Level1";
    
    std::string configJson = R"({
        "page": {
            "pn": "com.example.ability",
            "pt": "eq"
        },
        "dpi": [{
                "condition": "A",
                "val": "440"
            }],
        "hsb": [{
                "val": "1"
            }],
        "vd": [{
                "condition": "A",
                "val": ""
            }]
    })";
    int32_t result = AbilityRuntime::PageConfigManager::GetInstance().Initialize(configJson, nullptr);
    EXPECT_EQ(result, ERR_NO_INIT);
}

/**
 * @tc.name: Initialize_0200
 * @tc.desc: Initialize
 * @tc.type: FUNC
 */
HWTEST_F(PageConfigManagerTest, Initialize_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PageConfigManagerTest, Initialize_0200, TestSize.Level1";
    
    std::string configJson = "";
    int32_t result = AbilityRuntime::PageConfigManager::GetInstance().Initialize(configJson, nullptr);
    EXPECT_EQ(result, ERR_NO_INIT);
}

/**
 * @tc.name: NotifyPageChanged_0100
 * @tc.desc: NotifyPageChanged
 * @tc.type: FUNC
 */
HWTEST_F(PageConfigManagerTest, NotifyPageChanged_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PageConfigManagerTest, NotifyPageChanged_0100, TestSize.Level1";
    int32_t result = AbilityRuntime::PageConfigManager::GetInstance().NotifyPageChanged("", 0, 10);
    EXPECT_EQ(result, ERR_NO_INIT);
}

/**
 * @tc.name: NotifyPageChanged_0200
 * @tc.desc: NotifyPageChanged
 * @tc.type: FUNC
 */
HWTEST_F(PageConfigManagerTest, NotifyPageChanged_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PageConfigManagerTest, NotifyPageChanged_0200, TestSize.Level1";
    int32_t result = AbilityRuntime::PageConfigManager::GetInstance().NotifyPageChanged("", 0, -1);
    EXPECT_EQ(result, ERR_NO_INIT);
}

/**
 * @tc.name: NotifyPageChanged_0300
 * @tc.desc: NotifyPageChanged
 * @tc.type: FUNC
 */
HWTEST_F(PageConfigManagerTest, NotifyPageChanged_0300, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "PageConfigManagerTest, NotifyPageChanged_0300, TestSize.Level1";
    int32_t result = AbilityRuntime::PageConfigManager::GetInstance().NotifyPageChanged(
        "com.exmaple.testapplication", 0, 0);
    EXPECT_EQ(result, ERR_NO_INIT);
}
} // namespace AppExecFwk
} // namespace OHOS