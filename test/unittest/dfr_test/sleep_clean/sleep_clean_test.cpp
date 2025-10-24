/*
* Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "sleep_clean.h"
#include <memory>

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
class SleepCleanTest : public testing::Test {
public:
    SleepCleanTest() {}

    ~SleepCleanTest() {}

    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void SleepCleanTest::SetUpTestCase(void) {}

void SleepCleanTest::TearDownTestCase(void) {}

void SleepCleanTest::SetUp(void) {}

void SleepCleanTest::TearDown(void) {}

/**
* @tc.number: DumpProcHelperTest001
* @tc.name: DumpProcHelperTest001
* @tc.desc: test GetProcRssMemInfo.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest001 start";
    std::shared_ptr<OHOSApplication> application = nullptr;
    FaultData faultData;
    faultData.waitSaveState = false;
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest001 end";
}


/**
* @tc.number: DumpProcHelperTest002
* @tc.name: DumpProcHelperTest002
* @tc.desc: test GetProcRssMemInfo.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest002 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = false;
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest002 end";
}

/**
* @tc.number: DumpProcHelperTest003
* @tc.name: DumpProcHelperTest003
* @tc.desc: test GetProcRssMemInfo.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest003, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest0023 start";
    std::shared_ptr<OHOSApplication> application = nullptr;
    FaultData faultData;
    faultData.waitSaveState = true;
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest003 end";
}

/**
* @tc.number: DumpProcHelperTest004
* @tc.name: DumpProcHelperTest004
* @tc.desc: test GetProcRssMemInfo.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest004, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest004 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = true;
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest004 end";
}
}
}
