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

/**
* @tc.number: SleepCleanTest008
* @tc.name: SleepCleanTest008
* @tc.desc: test HandleSleepClean.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest008, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest008 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = false;
    currentHeapSize = "*";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest008 end";
}

/**
* @tc.number: SleepCleanTest009
* @tc.name: SleepCleanTest009
* @tc.desc: test HandleSleepClean.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest009, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest009 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = false;
    currentHeapSize = "-10000000000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest009 end";
}

/**
* @tc.number: SleepCleanTest010
* @tc.name: SleepCleanTest010
* @tc.desc: test HandleSleepClean.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest010, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest010 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = false;
    currentHeapSize = "hello world";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest010 end";
}

/**
* @tc.number: SleepCleanTest011
* @tc.name: SleepCleanTest011
* @tc.desc: test HandleSleepClean.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest011, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest011 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = true;
    currentHeapSize = "*";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest011 end";
}

/**
* @tc.number: SleepCleanTest012
* @tc.name: SleepCleanTest012
* @tc.desc: test HandleSleepClean.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest012, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest012 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = true;
    currentHeapSize = "-10000000000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest012 end";
}

/**
* @tc.number: SleepCleanTest013
* @tc.name: SleepCleanTest013
* @tc.desc: test HandleSleepClean.
*/
HWTEST_F(SleepCleanTest, SleepCleanTest013, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest013 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = true;
    currentHeapSize = "hello world";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest013 end";
}

/**
* @tc.number: SleepCleanTest014
* @tc.name: SleepCleanTest014
* @tc.desc: test HandleSleepClean with waitSaveState=false and valid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest014, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest014 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = false;
    currentHeapSize = "100000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest014 end";
}

/**
* @tc.number: SleepCleanTest015
* @tc.name: SleepCleanTest015
* @tc.desc: test HandleSleepClean with waitSaveState=false and invalid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest015, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest015 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.waitSaveState = false;
    currentHeapSize = "invalid_heap";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest015 end";
}

/**
* @tc.number: SleepCleanTest016
* @tc.name: SleepCleanTest016
* @tc.desc: test HandleSleepClean with notifyApp=true and valid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest016, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest016 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.notifyApp = true;
    currentHeapSize = "150000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest016 end";
}

/**
* @tc.number: SleepCleanTest017
* @tc.name: SleepCleanTest017
* @tc.desc: test HandleSleepClean with notifyApp=true and invalid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest017, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest017 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.notifyApp = true;
    currentHeapSize = "garbage_value";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest017 end";
}

/**
* @tc.number: SleepCleanTest018
* @tc.name: SleepCleanTest018
* @tc.desc: test HandleSleepClean with forceExit=true and valid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest018, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest018 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.forceExit = true;
    currentHeapSize = "200000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest018 end";
}

/**
* @tc.number: SleepCleanTest019
* @tc.name: SleepCleanTest019
* @tc.desc: test HandleSleepClean with forceExit=true and invalid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest019, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest019 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.forceExit = true;
    currentHeapSize = "corrupted_data";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest019 end";
}

/**
* @tc.number: SleepCleanTest020
* @tc.name: SleepCleanTest020
* @tc.desc: test HandleSleepClean with needKillProcess=false and valid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest020, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest020 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.needKillProcess = false;  // Default is true
    currentHeapSize = "250000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest020 end";
}

/**
* @tc.number: SleepCleanTest021
* @tc.name: SleepCleanTest021
* @tc.desc: test HandleSleepClean with needKillProcess=false and invalid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest021, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest021 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.needKillProcess = false;
    currentHeapSize = "heap_overflow";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest021 end";
}

/**
* @tc.number: SleepCleanTest022
* @tc.name: SleepCleanTest022
* @tc.desc: test HandleSleepClean with isInForeground=true and valid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest022, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest022 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.isInForeground = true;  // No default initialization
    currentHeapSize = "300000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest022 end";
}

/**
* @tc.number: SleepCleanTest023
* @tc.name: SleepCleanTest023
* @tc.desc: test HandleSleepClean with isInForeground=true and invalid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest023, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest023 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.isInForeground = true;
    currentHeapSize = "invalid_data";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest023 end";
}

/**
* @tc.number: SleepCleanTest024
* @tc.name: SleepCleanTest024
* @tc.desc: test HandleSleepClean with isEnableMainThreadSample=true and valid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest024, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest024 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.isEnableMainThreadSample = true;  // No default initialization
    currentHeapSize = "350000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest024 end";
}

/**
* @tc.number: SleepCleanTest025
* @tc.name: SleepCleanTest025
* @tc.desc: test HandleSleepClean with isEnableMainThreadSample=true and invalid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest025, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest025 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.isEnableMainThreadSample = true;
    currentHeapSize = "bad_format";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest025 end";
}

/**
* @tc.number: SleepCleanTest026
* @tc.name: SleepCleanTest026
* @tc.desc: test HandleSleepClean with faultType=APP_FREEZE and valid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest026, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest026 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.faultType = FaultDataType::APP_FREEZE;
    currentHeapSize = "400000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest026 end";
}

/**
* @tc.number: SleepCleanTest027
* @tc.name: SleepCleanTest027
* @tc.desc: test HandleSleepClean with faultType=APP_FREEZE and invalid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest027, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest027 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.faultType = FaultDataType::APP_FREEZE;
    currentHeapSize = "malformed_value";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest027 end";
}

/**
* @tc.number: SleepCleanTest028
* @tc.name: SleepCleanTest028
* @tc.desc: test HandleSleepClean with faultType=CPP_CRASH and valid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest028, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest028 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.faultType = FaultDataType::CPP_CRASH;
    currentHeapSize = "450000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest028 end";
}

/**
* @tc.number: SleepCleanTest029
* @tc.name: SleepCleanTest029
* @tc.desc: test HandleSleepClean with faultType=CPP_CRASH and invalid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest029, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest029 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.faultType = FaultDataType::CPP_CRASH;
    currentHeapSize = "random_string";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest029 end";
}

/**
* @tc.number: SleepCleanTest030
* @tc.name: SleepCleanTest030
* @tc.desc: test HandleSleepClean with stuckTimeout=5000 and valid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest030, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest030 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.stuckTimeout = 5000;
    currentHeapSize = "500000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest030 end";
}

/**
* @tc.number: SleepCleanTest031
* @tc.name: SleepCleanTest031
* @tc.desc: test HandleSleepClean with stuckTimeout=5000 and invalid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest031, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest031 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.stuckTimeout = 5000;
    currentHeapSize = "not_a_number";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest031 end";
}

/**
* @tc.number: SleepCleanTest032
* @tc.name: SleepCleanTest032
* @tc.desc: test HandleSleepClean with stuckTimeout=0 and valid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest032, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest032 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.stuckTimeout = 0;  // Default value
    currentHeapSize = "550000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest032 end";
}

/**
* @tc.number: SleepCleanTest033
* @tc.name: SleepCleanTest033
* @tc.desc: test HandleSleepClean with stuckTimeout=0 and invalid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest033, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest033 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.stuckTimeout = 0;
    currentHeapSize = "corrupted_heap";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest033 end";
}

/**
* @tc.number: SleepCleanTest034
* @tc.name: SleepCleanTest034
* @tc.desc: test HandleSleepClean with state=1 and valid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest034, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest034 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.state = 1;
    currentHeapSize = "600000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest034 end";
}

/**
* @tc.number: SleepCleanTest035
* @tc.name: SleepCleanTest035
* @tc.desc: test HandleSleepClean with state=1 and invalid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest035, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest035 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.state = 1;
    currentHeapSize = "invalid_state";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest035 end";
}

/**
* @tc.number: SleepCleanTest036
* @tc.name: SleepCleanTest036
* @tc.desc: test HandleSleepClean with eventId=100 and valid heap size
*/
HWTEST_F(SleepCleanTest, SleepCleanTest036, TestSize.Level1) {
    GTEST_LOG_(INFO) << "SleepCleanTest036 start";
    std::shared_ptr<OHOSApplication> application = std::make_shared<OHOSApplication>();
    FaultData faultData;
    faultData.eventId = 100;
    currentHeapSize = "65000";
    bool ret = SleepClean::GetInstance().HandleSleepClean(faultData, application);
    EXPECT_FALSE(ret);
    GTEST_LOG_(INFO) << "SleepCleanTest036 end";
}
}
}
