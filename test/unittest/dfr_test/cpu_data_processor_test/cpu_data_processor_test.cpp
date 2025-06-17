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
#include "cpu_data_processor.h"
#undef private

#include "appfreeze_data.h"
#include "appfreeze_util.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
class CpuDataProcessorTest : public testing::Test {
public:
    CpuDataProcessorTest()
    {}
    ~CpuDataProcessorTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CpuDataProcessorTest::SetUpTestCase(void)
{}

void CpuDataProcessorTest::TearDownTestCase(void)
{}

void CpuDataProcessorTest::SetUp(void)
{}

void CpuDataProcessorTest::TearDown(void)
{}

/**
 * @tc.number: GetHandlingHalfCpuData_Test_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuDataProcessorTest, GetHandlingHalfCpuData_Test_001, TestSize.Level1)
{
    std::vector<std::vector<CpuFreqData>> cpuData;
    std::vector<TotalTime> totalTimeList;
    CpuStartTime cpuStartTime;
    std::string stackPath = "GetHandlingHalfCpuData_Test_001";
    CpuDataProcessor data(cpuData, totalTimeList, cpuStartTime, stackPath);
    EXPECT_TRUE(data.GetHandlingHalfCpuData().size() == 0);
}

/**
 * @tc.number: GetTotalTimeList_Test_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuDataProcessorTest, GetTotalTimeList_Test_001, TestSize.Level1)
{
    std::vector<std::vector<CpuFreqData>> cpuData;
    std::vector<TotalTime> totalTimeList;
    CpuStartTime cpuStartTime;
    std::string stackPath = "GetTotalTimeList_Test_001";
    CpuDataProcessor data(cpuData, totalTimeList, cpuStartTime, stackPath);
    EXPECT_TRUE(data.GetTotalTimeList().size() == 0);
}

/**
 * @tc.number: GetCpuStartTime_Test_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuDataProcessorTest, GetCpuStartTime_Test_001, TestSize.Level1)
{
    std::vector<std::vector<CpuFreqData>> cpuData;
    std::vector<TotalTime> totalTimeList;
    CpuStartTime cpuStartTime = {
        .halfStartTime = 1234,
        .optimalCpuStartTime = 1234,
    };
    std::string stackPath = "GetCpuStartTime_Test_001";
    CpuDataProcessor data(cpuData, totalTimeList, cpuStartTime, stackPath);
    EXPECT_EQ(data.GetCpuStartTime().halfStartTime, 1234);
    EXPECT_EQ(data.GetCpuStartTime().optimalCpuStartTime, 1234);
}

/**
 * @tc.number: GetStackPath_Test_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuDataProcessorTest, GetStackPath_Test_001, TestSize.Level1)
{
    std::vector<std::vector<CpuFreqData>> cpuData;
    std::vector<TotalTime> totalTimeList;
    CpuStartTime cpuStartTime = {
        .halfStartTime = 1234,
        .optimalCpuStartTime = 1234,
    };
    std::string stackPath = "GetStackPath_Test_001";
    CpuDataProcessor data(cpuData, totalTimeList, cpuStartTime, stackPath);
    EXPECT_EQ(data.GetStackPath(), stackPath);
}
}  // namespace AppExecFwk
}  // namespace OHOS
