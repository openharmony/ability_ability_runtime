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

#include "keep_alive_utils.h"
#include <gtest/gtest.h>

#include "ability_resident_process_rdb.h"
#include "bundle_info.h"
#include "keep_alive_process_manager.h"
#include "main_element_utils.h"

#include <vector>
#include <memory>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace AbilityRuntime {
bool AmsResidentProcessRdb::residentProcessEnable = false;
}
namespace AAFwk {
bool MainElementUtils::retCheckMainElement = false;
bool MainElementUtils::isUpdateMainElementCalled = false;
bool KeepAliveProcessManager::isKeepAliveBundle = false;

namespace {
    const std::string PROCESS_NAME = "com.ohos.example.process";
    const std::string MAIN_ABILITY = "com.ohos.example.mainability";
    const std::string URI = "https://www.example.com:8080/path/to/resource?key1=value1&key2=value2#section1";
    const std::string BUNDLE_NAME = "com.ohos.example.bundlename";
    const std::string NAME = "com.ohos.example.name";
    const std::string MAINELEMENTNAME = "com.ohos.example.mainelementname";
}

class KeepAliveUtilsTest : public testing::Test {
public:
    KeepAliveUtilsTest();
    ~KeepAliveUtilsTest();
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

KeepAliveUtilsTest::KeepAliveUtilsTest()
{
}

KeepAliveUtilsTest::~KeepAliveUtilsTest()
{
}

void KeepAliveUtilsTest::SetUpTestCase()
{
    MainElementUtils::isUpdateMainElementCalled = false;
}

void KeepAliveUtilsTest::TearDownTestCase()
{
    MainElementUtils::isUpdateMainElementCalled = false;
}

void KeepAliveUtilsTest::SetUp()
{
}

void KeepAliveUtilsTest::TearDown()
{
}

/**
 * @tc.name:  NotifyDisableKeepAliveProcesses_0100
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(KeepAliveUtilsTest, NotifyDisableKeepAliveProcesses_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyDisableKeepAliveProcesses_0100 start";

    AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.applicationInfo.process = PROCESS_NAME;
    AppExecFwk::HapModuleInfo hapModuleInfo;
    hapModuleInfo.isModuleJson = false;
    bundleInfo.hapModuleInfos.push_back(hapModuleInfo);

    std::vector<AppExecFwk::BundleInfo> bundleInfos;
    bundleInfos.push_back(bundleInfo);
    MainElementUtils::retCheckMainElement = false;
    int32_t userId = 0;
    std::string mainElement;
    std::string uriStr;
    bool isDataAbility = false;
    KeepAliveUtils::NotifyDisableKeepAliveProcesses(bundleInfos, userId);
    EXPECT_FALSE(MainElementUtils::CheckMainElement(hapModuleInfo, bundleInfo.applicationInfo.process,
        mainElement, isDataAbility, uriStr, userId));
    EXPECT_FALSE(MainElementUtils::isUpdateMainElementCalled);

    GTEST_LOG_(INFO) << "NotifyDisableKeepAliveProcesses_0100 end";
}

/**
 * @tc.name:  NotifyDisableKeepAliveProcesses_0200
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(KeepAliveUtilsTest, NotifyDisableKeepAliveProcesses_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "NotifyDisableKeepAliveProcesses_0200 start";

    AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.applicationInfo.process = PROCESS_NAME;

    AppExecFwk::HapModuleInfo hapModuleInfo;
    hapModuleInfo.mainAbility = MAIN_ABILITY;
    hapModuleInfo.bundleName = BUNDLE_NAME;
    hapModuleInfo.mainElementName = MAINELEMENTNAME;
    hapModuleInfo.name = NAME;
    hapModuleInfo.isModuleJson = true;
    hapModuleInfo.process = PROCESS_NAME;

    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.process = PROCESS_NAME;
    abilityInfo.name = MAIN_ABILITY;
    abilityInfo.type = AppExecFwk::AbilityType::DATA;
    abilityInfo.uri = URI;
    hapModuleInfo.abilityInfos.push_back(abilityInfo);
    bundleInfo.hapModuleInfos.push_back(hapModuleInfo);

    MainElementUtils::retCheckMainElement = true;
    std::vector<AppExecFwk::BundleInfo> bundleInfos;
    bundleInfos.push_back(bundleInfo);
    int32_t userId = 0;
    std::string mainElement;
    std::string uriStr;
    bool isDataAbility = false;

    KeepAliveUtils::NotifyDisableKeepAliveProcesses(bundleInfos, userId);
    EXPECT_TRUE(MainElementUtils::CheckMainElement(hapModuleInfo, bundleInfo.applicationInfo.process,
        mainElement, isDataAbility, uriStr, userId));
    EXPECT_TRUE(MainElementUtils::isUpdateMainElementCalled);

    GTEST_LOG_(INFO) << "NotifyDisableKeepAliveProcesses_0200 end";
}

/**
 * @tc.name:  IsKeepAliveBundle_0100
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(KeepAliveUtilsTest, IsKeepAliveBundle_0100, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsKeepAliveBundle_0100 start";

    KeepAliveProcessManager::isKeepAliveBundle = true;
    AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.name = BUNDLE_NAME;
    bundleInfo.isKeepAlive = false;
    int32_t userId = 0;
    AAFwk::KeepAliveType type = AAFwk::KeepAliveType::UNSPECIFIED;

    auto result = KeepAliveUtils::IsKeepAliveBundle(bundleInfo, userId, type);
    EXPECT_EQ(result, true);
    EXPECT_EQ(type, KeepAliveType::THIRD_PARTY);

    GTEST_LOG_(INFO) << "IsKeepAliveBundle_0100 end";
}

/**
 * @tc.name:  IsKeepAliveBundle_0200
 * @tc.desc: basic function test.
 * @tc.type: FUNC
 */
HWTEST_F(KeepAliveUtilsTest, IsKeepAliveBundle_0200, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "IsKeepAliveBundle_0200 start";

    KeepAliveProcessManager::isKeepAliveBundle = false;
    AbilityRuntime::AmsResidentProcessRdb::residentProcessEnable = true;
    AppExecFwk::BundleInfo bundleInfo;
    bundleInfo.isKeepAlive = true;
    int32_t userId = 0;
    AAFwk::KeepAliveType type = AAFwk::KeepAliveType::UNSPECIFIED;
    auto result = KeepAliveUtils::IsKeepAliveBundle(bundleInfo, userId, type);
    EXPECT_EQ(result, true);
    EXPECT_EQ(type, AAFwk::KeepAliveType::RESIDENT_PROCESS);

    GTEST_LOG_(INFO) << "IsKeepAliveBundle_0200 end";
}

} // namespace AbilityRuntime
} // namespace OHOS