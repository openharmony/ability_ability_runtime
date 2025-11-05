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

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

std::string currentHeapSize = "-1";
namespace OHOS::system {
__attribute__((weak)) std::string GetParameter(const std::string& key, const std::string&def)
{
    if (key == "const.dfx.nightclean.jsheap") {
        return currentHeapSize;
    }
    return def;
}
}

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
* @tc.number: SleepCleanTest001
* @tc.name: SleepCleanTest001
* @tc.desc: test HandleSleepClean.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest001, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest001 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();;
    FaultData faultData;
    faultData.waitSaveState = false;
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest001 end";
}


/**
* @tc.number: SleepCleanTest002
* @tc.name: SleepCleanTest002
* @tc.desc: test HandleSleepClean.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest002, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest002 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = true;
    currentHeapSize = "-1";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest002 end";
}

/**
* @tc.number: SleepCleanTest003
* @tc.name: SleepCleanTest003
* @tc.desc: test HandleSleepClean.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest003, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest003 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = true;
    currentHeapSize = "1";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest003 end";
}

/**
* @tc.number: SleepCleanTest004
* @tc.name: SleepCleanTest004
* @tc.desc: test HandleSleepClean.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest004, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest004 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = true;
    currentHeapSize = "0";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_TRUE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest004 end";
}

/**
* @tc.number: SleepCleanTest005
* @tc.name: SleepCleanTest005
* @tc.desc: test HandleSleepClean.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest005, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest005 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = true;
    currentHeapSize = "20000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest005 end";
}

/**
* @tc.number: SleepCleanTest006
* @tc.name: SleepCleanTest006
* @tc.desc: test HandleSleepClean.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest006, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest006 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = false;
    currentHeapSize = "20000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest006 end";
}

/**
* @tc.number: SleepCleanTest007
* @tc.name: SleepCleanTest007
* @tc.desc: test HandleSleepClean.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest007, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest007 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = false;
    currentHeapSize = "-30";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest007 end";
}
}
}
