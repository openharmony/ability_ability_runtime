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

#define private public
#include "ability_manager_service.h"
#include "report_data_partition_usage_manager.h"
#undef private
#include "event_report.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
namespace OHOS {
namespace AbilityRuntime {
const std::string INVALID_PATH = "/gggggg";
const std::string PATH = "/data";
class ReportDataPartitionUsageManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ReportDataPartitionUsageManagerTest::SetUpTestCase()
{
}

void ReportDataPartitionUsageManagerTest::TearDownTestCase()
{
}

void ReportDataPartitionUsageManagerTest::SetUp()
{
}

void ReportDataPartitionUsageManagerTest::TearDown()
{
}

/*
 * @tc.number: GenerateEventInfo_0100
 * @tc.name: GenerateEventInfo
 * @tc.desc:
 */
HWTEST_F(ReportDataPartitionUsageManagerTest, GenerateEventInfo_0100, TestSize.Level1)
{
    EventInfo eventInfo;
    ReportDataPartitionUsageManager::GenerateEventInfo(eventInfo);
    EXPECT_EQ(eventInfo.componentName.empty(), false);
    EXPECT_EQ(eventInfo.partitionName.empty(), false);
}

/*
 * @tc.number: GetFilePathSize_0100
 * @tc.name: GetFilePathSize
 * @tc.desc:
 */
HWTEST_F(ReportDataPartitionUsageManagerTest, GetFilePathSize_0100, TestSize.Level1)
{
    uint64_t size = ReportDataPartitionUsageManager::GetFilePathSize(PATH);
    EXPECT_NE(size, 0);
}

/*
 * @tc.number: GetFilePathSize_0200
 * @tc.name: GetFilePathSize
 * @tc.desc:
 */
HWTEST_F(ReportDataPartitionUsageManagerTest, GetFilePathSize_0200, TestSize.Level1)
{
    uint64_t size = ReportDataPartitionUsageManager::GetFilePathSize(INVALID_PATH);
    EXPECT_EQ(size, 0);
}

/*
 * @tc.number: GetPartitionRemainSize_0100
 * @tc.name: GetPartitionRemainSize
 * @tc.desc:
 */
HWTEST_F(ReportDataPartitionUsageManagerTest, GetPartitionRemainSize_0100, TestSize.Level1)
{
    uint64_t size = ReportDataPartitionUsageManager::GetPartitionRemainSize(
        "/data/service/el1/public/database/app_config_data");
    EXPECT_NE(size, 0);
}

/*
 * @tc.number: GetPartitionRemainSize_0200
 * @tc.name: GetPartitionRemainSize
 * @tc.desc:
 */
HWTEST_F(ReportDataPartitionUsageManagerTest, GetPartitionRemainSize_0200, TestSize.Level1)
{
    uint64_t size = ReportDataPartitionUsageManager::GetPartitionRemainSize(INVALID_PATH);
    EXPECT_EQ(size, 0);
}

/*
 * @tc.number: IsExistPath_0100
 * @tc.name: IsExistPath
 * @tc.desc:
 */
HWTEST_F(ReportDataPartitionUsageManagerTest, IsExistPath_0100, TestSize.Level1)
{
    auto result = ReportDataPartitionUsageManager::IsExistPath("/data/service/el1/public/database/app_config_data");
    EXPECT_EQ(result, true);
}

/*
 * @tc.number: IsExistPath_0200
 * @tc.name: IsExistPath
 * @tc.desc:
 */
HWTEST_F(ReportDataPartitionUsageManagerTest, IsExistPath_0200, TestSize.Level1)
{
    auto result = ReportDataPartitionUsageManager::IsExistPath(INVALID_PATH);
    EXPECT_EQ(result, false);
}

/*
 * @tc.number: IsExistPath_0300
 * @tc.name: IsExistPath
 * @tc.desc:
 */
HWTEST_F(ReportDataPartitionUsageManagerTest, IsExistPath_0300, TestSize.Level1)
{
    auto result = ReportDataPartitionUsageManager::IsExistPath("");
    EXPECT_EQ(result, false);
}
} // namespace AbilityRuntime
} // namespace OHOS