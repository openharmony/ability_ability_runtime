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
#include "appfreeze_cpu_freq_manager.h"
#undef private

#include "appfreeze_data.h"
#include "appfreeze_util.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
class AppfreezeCpuFreqManagerTest : public testing::Test {
public:
    AppfreezeCpuFreqManagerTest()
    {}
    ~AppfreezeCpuFreqManagerTest()
    {}
    std::shared_ptr<AppfreezeCpuFreqManager> appfreezeCpuFreqManager_ = nullptr;
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void AppfreezeCpuFreqManagerTest::SetUpTestCase(void)
{}

void AppfreezeCpuFreqManagerTest::TearDownTestCase(void)
{}

void AppfreezeCpuFreqManagerTest::SetUp(void)
{
    appfreezeCpuFreqManager_ = AppfreezeCpuFreqManager::GetInstance();
}

void AppfreezeCpuFreqManagerTest::TearDown(void)
{
    AppfreezeCpuFreqManager::DestroyInstance();
}

/**
 * @tc.number: SetHalfStackPathTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, SetHalfStackPathTest_001, TestSize.Level0)
{
    appfreezeCpuFreqManager_->SetHalfStackPath("");
    EXPECT_TRUE(appfreezeCpuFreqManager_->stackPath_.empty());
    appfreezeCpuFreqManager_->SetHalfStackPath("AppfreezeCpuFreqManagerTest_001");
    EXPECT_TRUE(!appfreezeCpuFreqManager_->stackPath_.empty());
}

/**
 * @tc.number: InitHalfCpuInfoTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, InitHalfCpuInfoTest_001, TestSize.Level1)
{
    appfreezeCpuFreqManager_->InitHalfCpuInfo(getpid());
    appfreezeCpuFreqManager_->InitHalfCpuInfo(getpid());
    EXPECT_TRUE(appfreezeCpuFreqManager_->handlingHalfCpuData_.size() != 0);
    appfreezeCpuFreqManager_->Clear();
}

/**
 * @tc.number: InitHalfCpuInfoTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, ReadCpuDataByNumTest_001, TestSize.Level1)
{
    std::vector<CpuFreqData> parseDatas;
    TotalTime totalTime;
    int32_t num = 100;
    appfreezeCpuFreqManager_->ReadCpuDataByNum(num, parseDatas, totalTime);
    EXPECT_TRUE(parseDatas.size() == 0);
    num = 0;
    appfreezeCpuFreqManager_->ReadCpuDataByNum(num, parseDatas, totalTime);
    EXPECT_TRUE(parseDatas.size() != 0);
}

/**
 * @tc.number: GetCpuStrTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetCpuStrTest_001, TestSize.Level1)
{
    int code = 0;
    std::vector<FrequencyPair> freqPairs;
    float percentage = 44.1000f;
    std::string str = appfreezeCpuFreqManager_->GetCpuStr(code, freqPairs, percentage);
    EXPECT_TRUE(!str.empty());
    FrequencyPair freqPair1 = {
        .frequency = 100,
        .percentage = 10.000f,
    };
    FrequencyPair freqPair2 = {
        .frequency = 120,
        .percentage = 33.000f,
    };
    FrequencyPair freqPair3 = {
        .frequency = 50,
        .percentage = 1.000f,
    };
    freqPairs.push_back(freqPair1);
    freqPairs.push_back(freqPair2);
    freqPairs.push_back(freqPair3);
    str = appfreezeCpuFreqManager_->GetCpuStr(code, freqPairs, percentage);
    EXPECT_TRUE(!str.empty());
}

/**
 * @tc.number: GetCpuTotalValueTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetCpuTotalValueTest_001, TestSize.Level1)
{
    TotalTime time1 = {
        .totalRunningTime = 50,
        .totalCpuTime = 1000,
    };
    std::vector<TotalTime> totalTimeList;
    totalTimeList.push_back(time1);
    std::vector<TotalTime> blockTotalTimeList;
    TotalTime totalTime;
    bool ret = appfreezeCpuFreqManager_->GetCpuTotalValue(0, totalTimeList, blockTotalTimeList, totalTime);
    EXPECT_TRUE(!ret);
    TotalTime time2 = {
        .totalRunningTime = 100,
        .totalCpuTime = 1000,
    };
    blockTotalTimeList.push_back(time2);
    ret = appfreezeCpuFreqManager_->GetCpuTotalValue(0, totalTimeList, blockTotalTimeList, totalTime);
    EXPECT_TRUE(!ret);
    blockTotalTimeList.clear();
    TotalTime time3 = {
        .totalRunningTime = 10,
        .totalCpuTime = 20,
    };
    blockTotalTimeList.push_back(time3);
    ret = appfreezeCpuFreqManager_->GetCpuTotalValue(0, totalTimeList, blockTotalTimeList, totalTime);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetCpuInfoContentTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetCpuInfoContentTest_001, TestSize.Level1)
{
    std::string ret = appfreezeCpuFreqManager_->GetCpuInfoContent();
    appfreezeCpuFreqManager_->Clear();
    EXPECT_TRUE(ret.empty());
    appfreezeCpuFreqManager_->InitHalfCpuInfo(getpid());
    EXPECT_TRUE(appfreezeCpuFreqManager_->handlingHalfCpuData_.size() > 0);
    ret = appfreezeCpuFreqManager_->GetCpuInfoContent();
    EXPECT_TRUE(!ret.empty());
    appfreezeCpuFreqManager_->Clear();
}

/**
 * @tc.number: GetAppCpuTimeTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetAppCpuTimeTest_001, TestSize.Level1)
{
    uint64_t ret = appfreezeCpuFreqManager_->GetAppCpuTime(-1);
    EXPECT_TRUE(ret == 0);
    ret = appfreezeCpuFreqManager_->GetAppCpuTime(getpid());
    EXPECT_TRUE(ret >= 0);
    ret = appfreezeCpuFreqManager_->GetAppCpuTime(12345670);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.number: GetProcessCpuTimeTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetProcessCpuTimeTest_001, TestSize.Level0)
{
    uint64_t ret = appfreezeCpuFreqManager_->GetProcessCpuTime(-1);
    EXPECT_TRUE(ret == 0);
    ret = appfreezeCpuFreqManager_->GetProcessCpuTime(getpid());
    EXPECT_TRUE(ret >= 0);
    ret = appfreezeCpuFreqManager_->GetProcessCpuTime(12345670);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.number: GetDeviceRuntimeTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetDeviceRuntimeTest_001, TestSize.Level0)
{
    uint64_t ret = appfreezeCpuFreqManager_->GetDeviceRuntime();
    EXPECT_TRUE(ret >= 0);
}

/**
 * @tc.number: GetOptimalCpuTimeTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetOptimalCpuTimeTest_001, TestSize.Level0)
{
    uint64_t ret = appfreezeCpuFreqManager_->GetOptimalCpuTime(getpid());
    EXPECT_TRUE(ret >= 0);
}

/**
 * @tc.number: GetStartTimeTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetStartTimeTest_001, TestSize.Level0)
{
    uint64_t start = AppfreezeUtil::GetMilliseconds();
    std::string ret = appfreezeCpuFreqManager_->GetStartTime(start);
    EXPECT_TRUE(!ret.empty());
}

/**
 * @tc.number: GetStaticInfoTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetStaticInfoTest_001, TestSize.Level0)
{
    std::string ret = appfreezeCpuFreqManager_->GetStaticInfo(getpid());
    EXPECT_TRUE(!ret.empty());
}

/**
 * @tc.number: GetStaticInfoHeadTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetStaticInfoHeadTest_001, TestSize.Level0)
{
    std::string ret = appfreezeCpuFreqManager_->GetStaticInfoHead();
    EXPECT_TRUE(!ret.empty());
}

/**
 * @tc.number: WriteDfxLogToFileTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, WriteDfxLogToFileTest_001, TestSize.Level0)
{
    appfreezeCpuFreqManager_->WriteDfxLogToFile("filePath", "bundleName");
    EXPECT_TRUE(appfreezeCpuFreqManager_);
}

/**
 * @tc.number: WriteCpuInfoToFileTest_001
 * @tc.desc: add testcase codecoverage
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, WriteCpuInfoToFileTest_001, TestSize.Level0)
{
    std::string ret = appfreezeCpuFreqManager_->WriteCpuInfoToFile("AppfreezeCpuFreqManagerTest",
        getuid(), getpid(), "AppfreezeCpuFreqManagerTest");
    EXPECT_TRUE(!ret.empty());
    ret = appfreezeCpuFreqManager_->WriteCpuInfoToFile("AppfreezeCpuFreqManagerTest",
        getuid(), getpid(), "LIFECYCLE_TIMEOUT");
    EXPECT_TRUE(!ret.empty());
}
}  // namespace AppExecFwk
}  // namespace OHOS
