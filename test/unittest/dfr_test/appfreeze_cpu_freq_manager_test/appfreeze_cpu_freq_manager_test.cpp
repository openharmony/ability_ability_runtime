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
{}

void AppfreezeCpuFreqManagerTest::TearDown(void)
{}

/**
 * @tc.number: InitCpuDataProcessorTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, InitCpuDataProcessorTest_001, TestSize.Level1)
{
    uint32_t checkMapSize = 10;
    std::string eventType = "test0";
    int32_t pid = getpid();
    int32_t uid = static_cast<int>(getuid());
    std::string stackpath = "InitCpuDataProcessorTest_001";
    bool ret = AppfreezeCpuFreqManager::GetInstance().InitCpuDataProcessor(eventType, pid, uid, stackpath);
    EXPECT_TRUE(ret);
    ret = AppfreezeCpuFreqManager::GetInstance().InitCpuDataProcessor(eventType, pid, uid, stackpath);
    EXPECT_TRUE(!ret);
    for (auto i = 1; i < checkMapSize; i++) {
        eventType = "test" + std::to_string(i);
        AppfreezeCpuFreqManager::GetInstance().InitCpuDataProcessor(eventType, pid, uid, stackpath);
    }
    EXPECT_TRUE(AppfreezeCpuFreqManager::GetInstance().cpuInfoMap_.size() == checkMapSize);
    int left = 8; // over 8s
    while (left > 0) {
        left = sleep(left);
    }
    eventType = "test112";
    ret = AppfreezeCpuFreqManager::GetInstance().InitCpuDataProcessor(eventType, pid, uid, stackpath);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: ReadCpuDataByNumTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, ReadCpuDataByNumTest_001, TestSize.Level1)
{
    std::vector<CpuFreqData> parseDatas;
    TotalTime totalTime;
    int32_t num = 100;
    AppfreezeCpuFreqManager::GetInstance().ReadCpuDataByNum(num, parseDatas, totalTime);
    EXPECT_TRUE(parseDatas.size() == 0);
    num = 0;
    AppfreezeCpuFreqManager::GetInstance().ReadCpuDataByNum(num, parseDatas, totalTime);
    EXPECT_TRUE(parseDatas.size() == 0);
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
    std::string str = AppfreezeCpuFreqManager::GetInstance().GetCpuStr(code, freqPairs, percentage);
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
    str = AppfreezeCpuFreqManager::GetInstance().GetCpuStr(code, freqPairs, percentage);
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
    bool ret = AppfreezeCpuFreqManager::GetInstance().GetCpuTotalValue(0, totalTimeList, blockTotalTimeList, totalTime);
    EXPECT_TRUE(!ret);
    TotalTime time2 = {
        .totalRunningTime = 100,
        .totalCpuTime = 1000,
    };
    blockTotalTimeList.push_back(time2);
    ret = AppfreezeCpuFreqManager::GetInstance().GetCpuTotalValue(0, totalTimeList, blockTotalTimeList, totalTime);
    EXPECT_TRUE(!ret);
    blockTotalTimeList.clear();
    TotalTime time3 = {
        .totalRunningTime = 10,
        .totalCpuTime = 20,
    };
    blockTotalTimeList.push_back(time3);
    ret = AppfreezeCpuFreqManager::GetInstance().GetCpuTotalValue(0, totalTimeList, blockTotalTimeList, totalTime);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: GetAppCpuTimeTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetAppCpuTimeTest_001, TestSize.Level1)
{
    uint64_t ret = AppfreezeCpuFreqManager::GetInstance().GetAppCpuTime(-1);
    EXPECT_TRUE(ret == 0);
    ret = AppfreezeCpuFreqManager::GetInstance().GetAppCpuTime(getpid());
    EXPECT_TRUE(ret >= 0);
    ret = AppfreezeCpuFreqManager::GetInstance().GetAppCpuTime(12345670);
    EXPECT_TRUE(ret == 0);
}

/**
 * @tc.number: GetProcessCpuTimeTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetProcessCpuTimeTest_001, TestSize.Level0)
{
    uint64_t ret = AppfreezeCpuFreqManager::GetInstance().GetProcessCpuTime(-1);
    EXPECT_TRUE(ret == 0);
    ret = AppfreezeCpuFreqManager::GetInstance().GetProcessCpuTime(getpid());
    EXPECT_TRUE(ret >= 0);
    ret = AppfreezeCpuFreqManager::GetInstance().GetProcessCpuTime(12345670);
    EXPECT_TRUE(ret == 0);
    ret = AppfreezeCpuFreqManager::GetInstance().GetDeviceRuntime();
    EXPECT_TRUE(ret >= 0);
}

/**
 * @tc.number: GetOptimalCpuTimeTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetOptimalCpuTimeTest_001, TestSize.Level0)
{
    uint64_t ret = AppfreezeCpuFreqManager::GetInstance().GetOptimalCpuTime(getpid());
    EXPECT_TRUE(ret >= 0);
    int count = AppfreezeCpuFreqManager::GetInstance().cpuCount_;
    AppfreezeCpuFreqManager::GetInstance().cpuCount_ = 0;
    ret = AppfreezeCpuFreqManager::GetInstance().GetOptimalCpuTime(getpid());
    EXPECT_TRUE(ret >= 0);
    AppfreezeCpuFreqManager::GetInstance().cpuCount_ = count;
}

/**
 * @tc.number: GetCpuInfoTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetCpuInfoTest_001, TestSize.Level0)
{
    uint64_t start = AppfreezeUtil::GetMilliseconds();
    std::string ret = AppfreezeCpuFreqManager::GetInstance().GetStartTime(start);
    EXPECT_TRUE(!ret.empty());
    CpuStartTime cpuStartTime;
    ret = AppfreezeCpuFreqManager::GetInstance().GetStaticInfo(getpid(), cpuStartTime);
    EXPECT_TRUE(!ret.empty());
    ret = AppfreezeCpuFreqManager::GetInstance().GetStaticInfoHead();
    EXPECT_TRUE(!ret.empty());
}

/**
 * @tc.number: GetCpuInfoContentTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, GetCpuInfoContentTest_001, TestSize.Level0)
{
    std::vector<std::vector<CpuFreqData>> datas;
    std::vector<TotalTime> totalTimeList;
    std::string ret = AppfreezeCpuFreqManager::GetInstance().GetCpuInfoContent(datas, totalTimeList);
    EXPECT_TRUE(ret.empty());
    std::vector<CpuFreqData> parseDatas;
    CpuFreqData cpuFreqData1 = {
        .frequency = 100,
        .runningTime = 100,
    };
    parseDatas.push_back(cpuFreqData1);
    datas.push_back(parseDatas);
    TotalTime time1 = {
        .totalRunningTime = 50,
        .totalCpuTime = 1000,
    };
    totalTimeList.push_back(time1);
    ret = AppfreezeCpuFreqManager::GetInstance().GetCpuInfoContent(datas, totalTimeList);
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.number: WriteCpuInfoToFileTest_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, WriteCpuInfoToFileTest_001, TestSize.Level0)
{
    AppfreezeCpuFreqManager::GetInstance().WriteDfxLogToFile("filePath", "bundleName");
    std::string eventType = "WriteCpuInfoToFileTest_001";
    std::string testValue = "AppfreezeCpuFreqManagerTest";
    std::string ret = AppfreezeCpuFreqManager::GetInstance().WriteCpuInfoToFile(eventType,
        testValue, getuid(), getpid(), testValue);
    EXPECT_TRUE(ret.empty());
    int32_t pid = getpid();
    int32_t uid = static_cast<int>(getuid());
    bool result = AppfreezeCpuFreqManager::GetInstance().InitCpuDataProcessor(eventType, pid, uid, testValue);
    EXPECT_TRUE(result);
    testValue = "LIFECYCLE_TIMEOUT";
    ret = AppfreezeCpuFreqManager::GetInstance().WriteCpuInfoToFile(eventType,
        testValue, getuid(), getpid(), testValue);
    EXPECT_TRUE(ret.empty());
}

/**
 * @tc.number: WriteCpuInfoToFileTest_002
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(AppfreezeCpuFreqManagerTest, WriteCpuInfoToFileTest_002, TestSize.Level0)
{
    int32_t pid = getpid();
    int32_t uid = static_cast<int>(getuid());
    std::string eventType = "WriteCpuInfoToFileTest_001";
    std::string testValue = "AppfreezeCpuFreqManagerTest";
    bool result = AppfreezeCpuFreqManager::GetInstance().InitCpuDataProcessor(eventType, pid, uid, testValue);
    EXPECT_TRUE(!result);
    int32_t newPid = pid + 10;
    std::string ret = AppfreezeCpuFreqManager::GetInstance().WriteCpuInfoToFile(eventType,
        testValue, getuid(), newPid, testValue);
    EXPECT_TRUE(ret.empty());
    int left = 7;
    while (left > 0) {
        left = sleep(left);
    }
    ret = AppfreezeCpuFreqManager::GetInstance().WriteCpuInfoToFile(eventType,
        testValue, getuid(), pid, testValue);
    EXPECT_TRUE(ret.empty());
}
}  // namespace AppExecFwk
}  // namespace OHOS
