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

#include "cpu_sys_config.h"

#include <gtest/gtest.h>
#include <sstream>
#include <fstream>

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
class CpuSysConfigTest : public testing::Test {
public:
    CpuSysConfigTest()
    {}
    ~CpuSysConfigTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void CpuSysConfigTest::SetUpTestCase(void)
{}

void CpuSysConfigTest::TearDownTestCase(void)
{}

void CpuSysConfigTest::SetUp(void)
{}

void CpuSysConfigTest::TearDown(void)
{}

/**
 * @tc.number: GetFreqTimePath_Test_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuSysConfigTest, GetFreqTimePath_Test_001, TestSize.Level1)
{
    std::shared_ptr<CpuSysConfig> cpuSysConfig = std::make_shared<CpuSysConfig>();
    EXPECT_TRUE(cpuSysConfig);
    int cpu = 0;
    EXPECT_TRUE(!CpuSysConfig::GetFreqTimePath(cpu).empty());
}

/**
 * @tc.number: GetFreqTimePath_Test_002
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuSysConfigTest, GetFreqTimePath_Test_002, TestSize.Level1)
{
    int cpu = -1;
    std::string path = CpuSysConfig::GetFreqTimePath(cpu);
    EXPECT_TRUE(!path.empty());
    std::ifstream fin(path);
    EXPECT_TRUE(!fin.is_open());
}

/**
 * @tc.number: GetFreqTimePath_Test_003
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuSysConfigTest, GetFreqTimePath_Test_003, TestSize.Level1)
{
    int cpu = 0;
    std::string path = CpuSysConfig::GetFreqTimePath(cpu);
    EXPECT_TRUE(!path.empty());
    std::ifstream fin(path);
    EXPECT_TRUE(fin.is_open());
}

/**
 * @tc.number: GetMainThreadRunningTimePath_Test_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuSysConfigTest, GetMainThreadRunningTimePath_Test_001, TestSize.Level1)
{
    int pid = 0;
    std::string path = CpuSysConfig::GetMainThreadRunningTimePath(pid);
    EXPECT_TRUE(!path.empty());
    std::ifstream fin(path);
    EXPECT_TRUE(!fin.is_open());
}

/**
 * @tc.number: GetMainThreadRunningTimePath_Test_002
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuSysConfigTest, GetMainThreadRunningTimePath_Test_002, TestSize.Level1)
{
    int pid = -1;
    std::string path = CpuSysConfig::GetMainThreadRunningTimePath(pid);
    EXPECT_TRUE(!path.empty());
    std::ifstream fin(path);
    EXPECT_TRUE(!fin.is_open());
}

/**
 * @tc.number: GetMainThreadRunningTimePath_Test_003
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuSysConfigTest, GetMainThreadRunningTimePath_Test_003, TestSize.Level1)
{
    int pid = 0;
    std::string path = CpuSysConfig::GetMainThreadRunningTimePath(pid);
    EXPECT_TRUE(!path.empty());
    std::ifstream fin(path);
    EXPECT_TRUE(!fin.is_open());
}

/**
 * @tc.number: GetProcRunningTimePath_Test_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuSysConfigTest, GetProcRunningTimePath_Test_001, TestSize.Level1)
{
    int pid = 0;
    std::string path = CpuSysConfig::GetProcRunningTimePath(pid);
    EXPECT_TRUE(!path.empty());
    std::ifstream fin(path);
    EXPECT_TRUE(!fin.is_open());
}

/**
 * @tc.number: GetProcRunningTimePath_Test_002
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuSysConfigTest, GetProcRunningTimePath_Test_002, TestSize.Level1)
{
    int pid = -1;
    std::string path = CpuSysConfig::GetProcRunningTimePath(pid);
    EXPECT_TRUE(!path.empty());
    std::ifstream fin(path);
    EXPECT_TRUE(!fin.is_open());
}

/**
 * @tc.number: GetProcRunningTimePath_Test_003
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuSysConfigTest, GetProcRunningTimePath_Test_003, TestSize.Level1)
{
    int pid = 0;
    std::string path = CpuSysConfig::GetProcRunningTimePath(pid);
    EXPECT_TRUE(!path.empty());
    std::ifstream fin(path);
    EXPECT_TRUE(!fin.is_open());
}

/**
 * @tc.number: GetMaxCoreDimpsPath_Test_001
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuSysConfigTest, GetMaxCoreDimpsPath_Test_001, TestSize.Level1)
{
    int maxCpuCount = 0;
    std::string path = CpuSysConfig::GetMaxCoreDimpsPath(maxCpuCount);
    EXPECT_TRUE(!path.empty());
    std::ifstream fin(path);
    EXPECT_TRUE(fin.is_open());
}

/**
 * @tc.number: GetMaxCoreDimpsPath_Test_002
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuSysConfigTest, GetMaxCoreDimpsPath_Test_002, TestSize.Level1)
{
    int maxCpuCount = -1;
    std::string path = CpuSysConfig::GetMaxCoreDimpsPath(maxCpuCount);
    EXPECT_TRUE(!path.empty());
    std::ifstream fin(path);
    EXPECT_TRUE(!fin.is_open());
}

/**
 * @tc.number: GetMaxCoreDimpsPath_Test_003
 * @tc.desc: add testcase
 * @tc.type: FUNC
 */
HWTEST_F(CpuSysConfigTest, GetMaxCoreDimpsPath_Test_003, TestSize.Level1)
{
    int maxCpuCount = 0;
    std::string path = CpuSysConfig::GetMaxCoreDimpsPath(maxCpuCount);
    EXPECT_TRUE(!path.empty());
    std::ifstream fin(path);
    EXPECT_TRUE(fin.is_open());
}
}  // namespace AppExecFwk
}  // namespace OHOS
