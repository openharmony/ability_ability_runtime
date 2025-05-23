/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#define protected public
#include "hdc_register.h"
#undef private
#undef protected

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace AbilityRuntime {
class HdcRegisterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void HdcRegisterTest::SetUpTestCase()
{}

void HdcRegisterTest::TearDownTestCase()
{}

void HdcRegisterTest::SetUp()
{}

void HdcRegisterTest::TearDown()
{}

/**
 * @tc.name: HdcRegisterTest_0100
 * @tc.desc: HdcRegisterTest Test
 * @tc.type: FUNC
 */
HWTEST_F(HdcRegisterTest, HdcRegisterTest_0100, TestSize.Level0)
{
    const std::string processName = "";
    const std::string bundleName = "";
    bool debugApp = true;
    auto &pHdcRegister = AbilityRuntime::HdcRegister::Get();

    pHdcRegister.StartHdcRegister(bundleName, processName, debugApp,
        AbilityRuntime::HdcRegister::DebugRegisterMode::HDC_DEBUG_REG, nullptr);

    EXPECT_NE(pHdcRegister.registerHdcHandler_, nullptr);
}

/**
 * @tc.name: HdcRegisterTest_0200
 * @tc.desc: HdcRegisterTest Test
 * @tc.type: FUNC
 */
HWTEST_F(HdcRegisterTest, HdcRegisterTest_0200, TestSize.Level0)
{
    auto &pHdcRegister = AbilityRuntime::HdcRegister::Get();
    pHdcRegister.registerHdcHandler_ = nullptr;
    pHdcRegister.StopHdcRegister();
    
    EXPECT_EQ(pHdcRegister.registerHdcHandler_, nullptr);
}

/**
 * @tc.name: HdcRegisterTest_0300
 * @tc.desc: HdcRegisterTest Test
 * @tc.type: FUNC
 */
HWTEST_F(HdcRegisterTest, HdcRegisterTest_0300, TestSize.Level1)
{
    const std::string processName = "123";
    const std::string bundleName = "123";
    bool debugApp = true;
    auto &pHdcRegister = AbilityRuntime::HdcRegister::Get();
    pHdcRegister.StartHdcRegister(bundleName, processName, debugApp,
        AbilityRuntime::HdcRegister::DebugRegisterMode::HDC_DEBUG_REG, nullptr);
    pHdcRegister.StopHdcRegister();

    EXPECT_EQ(pHdcRegister.registerHdcHandler_, nullptr);
}

/**
 * @tc.name: HdcRegisterTest_0400
 * @tc.desc: HdcRegisterTest Test
 * @tc.type: FUNC
 */
HWTEST_F(HdcRegisterTest, HdcRegisterTest_0400, TestSize.Level1)
{
    const std::string processName = "123";
    const std::string bundleName = "123";
    bool debugApp = true;
    auto &pHdcRegister = AbilityRuntime::HdcRegister::Get();
    pHdcRegister.StartHdcRegister(bundleName, processName, debugApp,
        AbilityRuntime::HdcRegister::DebugRegisterMode::LOCAL_DEBUG_REG, nullptr);
    EXPECT_EQ(pHdcRegister.registerLocalHandler_, nullptr);
    pHdcRegister.StopHdcRegister();
    EXPECT_EQ(pHdcRegister.registerLocalHandler_, nullptr);
}

/**
 * @tc.name: HdcRegisterTest_0500
 * @tc.desc: HdcRegisterTest Test
 * @tc.type: FUNC
 */
HWTEST_F(HdcRegisterTest, HdcRegisterTest_0500, TestSize.Level1)
{
    const std::string processName = "123";
    const std::string bundleName = "123";
    bool debugApp = true;
    auto &pHdcRegister = AbilityRuntime::HdcRegister::Get();
    pHdcRegister.StartHdcRegister(bundleName, processName, debugApp,
        AbilityRuntime::HdcRegister::DebugRegisterMode::BOTH_REG, nullptr);
    EXPECT_NE(pHdcRegister.registerHdcHandler_, nullptr);
    EXPECT_EQ(pHdcRegister.registerLocalHandler_, nullptr);
    pHdcRegister.StopHdcRegister();
    EXPECT_EQ(pHdcRegister.registerHdcHandler_, nullptr);
    EXPECT_EQ(pHdcRegister.registerLocalHandler_, nullptr);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
