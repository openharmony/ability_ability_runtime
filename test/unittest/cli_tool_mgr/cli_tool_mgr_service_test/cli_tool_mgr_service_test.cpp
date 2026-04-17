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

#include <gtest/gtest.h>

#define private public
#include "cli_tool_manager_service.h"
#undef private

using namespace testing::ext;

namespace OHOS {
namespace CliTool {

class CliToolManagerServiceTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CliToolManagerServiceTest::SetUpTestCase(void) {}
void CliToolManagerServiceTest::TearDownTestCase(void) {}
void CliToolManagerServiceTest::SetUp() {}
void CliToolManagerServiceTest::TearDown() {}

/**
 * @tc.name: CliToolManagerService_GetInstance_0100
 * @tc.desc: Test GetInstance returns singleton instance
 * @tc.type: FUNC
 */
HWTEST_F(CliToolManagerServiceTest, GetInstance_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "CliToolManagerService_GetInstance_0100 start";

    auto instance1 = CliToolManagerService::GetInstance();
    auto instance2 = CliToolManagerService::GetInstance();

    EXPECT_EQ(instance1.GetRefPtr(), instance2.GetRefPtr());

    GTEST_LOG_(INFO) << "CliToolManagerService_GetInstance_0100 end";
}
} // namespace CliTool
} // namespace OHOS
