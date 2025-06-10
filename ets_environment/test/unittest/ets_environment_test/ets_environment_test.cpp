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
#include <cstdarg>
#include <gtest/gtest.h>
#include <gtest/hwext/gtest-multithread.h>
#include <string>

#include "runtime.h"
#define private public
#include "ets_environment.h"
#undef private

using namespace testing;
using namespace testing::ext;
using namespace testing::mt;

namespace {
bool g_callbackModuleFlag;
}

namespace OHOS {
namespace EtsEnv {
const std::string TEST_ABILITY_NAME = "ContactsDataAbility";

class EtsEnvironmentTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void EtsEnvironmentTest::SetUpTestCase() {}

void EtsEnvironmentTest::TearDownTestCase() {}

void EtsEnvironmentTest::SetUp() {}

void EtsEnvironmentTest::TearDown() {}

namespace {
void CallBackModuleFunc()
{
    g_callbackModuleFlag = true;
}
} // namespace

/**
 * @tc.name: LoadBootPathFile_0100
 * @tc.desc: LoadBootPathFile.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, LoadBootPathFile_0100, TestSize.Level0)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    std::string str = "LoadBootPathFile";
    bool bVal = etsEnv->LoadBootPathFile(str);
    EXPECT_EQ(bVal, true);
}
/**
 * @tc.name: LoadRuntimeApis_0100
 * @tc.desc: LoadRuntimeApis.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, LoadRuntimeApis_0100, TestSize.Level0)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    bool bVal = etsEnv->LoadRuntimeApis();
    EXPECT_EQ(bVal, true);
}

/**
 * @tc.name: GetAniEnv_0100
 * @tc.desc: GetAniEnv.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, GetAniEnv_0100, TestSize.Level0)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ETSEnvironment::VMEntry vMEntryOld = etsEnv->vmEntry_;
    ETSEnvironment::VMEntry vmEntry;
    vmEntry.aniEnv_ = nullptr;
    etsEnv->vmEntry_ = vmEntry;
    auto result = etsEnv->GetAniEnv();
    EXPECT_EQ(result, nullptr);
    etsEnv->vmEntry_ = vMEntryOld;
}

} // namespace StsEnv
} // namespace OHOS