/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "ohos_sts_environment_impl.h"
#include "runtime.h"
#define private public
#include "sts_environment.h"
#undef private
#include "sts_environment_impl.h"

using namespace testing;
using namespace testing::ext;
using namespace testing::mt;

namespace {
bool g_callbackModuleFlag;
}

namespace OHOS {
namespace StsEnv {
const std::string TEST_ABILITY_NAME = "ContactsDataAbility";

class StsEnvironmentTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void StsEnvironmentTest::SetUpTestCase() {}

void StsEnvironmentTest::TearDownTestCase() {}

void StsEnvironmentTest::SetUp() {}

void StsEnvironmentTest::TearDown() {}

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
HWTEST_F(StsEnvironmentTest, LoadBootPathFile_0100, TestSize.Level0)
{
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner = AppExecFwk::EventRunner::Create(TEST_ABILITY_NAME);
    auto stsEnv =
        std::make_shared<STSEnvironment>(std::make_unique<AbilityRuntime::OHOSStsEnvironmentImpl>(eventRunner));
    ASSERT_NE(stsEnv, nullptr);
    std::string str = "LoadBootPathFile";
    bool bVal = stsEnv->LoadBootPathFile(str);
    EXPECT_EQ(bVal, true);
}
/**
 * @tc.name: LoadRuntimeApis_0100
 * @tc.desc: LoadRuntimeApis.
 * @tc.type: FUNC
 */
HWTEST_F(StsEnvironmentTest, LoadRuntimeApis_0100, TestSize.Level0)
{
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner = AppExecFwk::EventRunner::Create(TEST_ABILITY_NAME);
    auto stsEnv =
        std::make_shared<STSEnvironment>(std::make_unique<AbilityRuntime::OHOSStsEnvironmentImpl>(eventRunner));
    ASSERT_NE(stsEnv, nullptr);
    bool bVal = stsEnv->LoadRuntimeApis();
    EXPECT_EQ(bVal, true);
}

/**
 * @tc.name: PostTask_0100
 * @tc.desc: PostTask
 * @tc.type: FUNC
 */
HWTEST_F(StsEnvironmentTest, PostTask_0100, TestSize.Level0)
{
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner = AppExecFwk::EventRunner::Create(TEST_ABILITY_NAME);
    auto stsEnv =
        std::make_shared<STSEnvironment>(std::make_unique<AbilityRuntime::OHOSStsEnvironmentImpl>(eventRunner));
    ASSERT_NE(stsEnv, nullptr);

    std::function<void()> task = CallBackModuleFunc;
    std::string name = "NAME";
    int64_t delayTime = 10;
    stsEnv->PostTask(task, name, delayTime);
}

/**
 * @tc.name: PostSyncTask_0100
 * @tc.desc: PostSyncTask
 * @tc.type: FUNC
 */
HWTEST_F(StsEnvironmentTest, PostSyncTask_0100, TestSize.Level0)
{
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner = AppExecFwk::EventRunner::Create(TEST_ABILITY_NAME);
    auto stsEnv =
        std::make_shared<STSEnvironment>(std::make_unique<AbilityRuntime::OHOSStsEnvironmentImpl>(eventRunner));
    ASSERT_NE(stsEnv, nullptr);

    std::function<void()> task = CallBackModuleFunc;
    std::string name = "NAME";
    stsEnv->PostSyncTask(task, name);
}

/**
 * @tc.name: RemoveTask_0100
 * @tc.desc: RemoveTask
 * @tc.type: FUNC
 */
HWTEST_F(StsEnvironmentTest, RemoveTask_0100, TestSize.Level0)
{
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner = AppExecFwk::EventRunner::Create(TEST_ABILITY_NAME);
    auto stsEnv =
        std::make_shared<STSEnvironment>(std::make_unique<AbilityRuntime::OHOSStsEnvironmentImpl>(eventRunner));
    ASSERT_NE(stsEnv, nullptr);

    std::string name = "NAME";
    stsEnv->RemoveTask(name);
}

/**
 * @tc.name: InitLoop_0100
 * @tc.desc: InitLoop
 * @tc.type: FUNC
 */
HWTEST_F(StsEnvironmentTest, InitLoop_0100, TestSize.Level0)
{
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner = AppExecFwk::EventRunner::Create(TEST_ABILITY_NAME);
    auto stsEnv =
        std::make_shared<STSEnvironment>(std::make_unique<AbilityRuntime::OHOSStsEnvironmentImpl>(eventRunner));
    ASSERT_NE(stsEnv, nullptr);

    bool bIsStage = true;
    bool bVal = stsEnv->InitLoop(bIsStage);
    EXPECT_TRUE(bVal);
}

/**
 * @tc.name: DeInitLoop_0100
 * @tc.desc: DeInitLoop
 * @tc.type: FUNC
 */
HWTEST_F(StsEnvironmentTest, DeInitLoop_0100, TestSize.Level0)
{
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner = AppExecFwk::EventRunner::Create(TEST_ABILITY_NAME);
    auto stsEnv =
        std::make_shared<STSEnvironment>(std::make_unique<AbilityRuntime::OHOSStsEnvironmentImpl>(eventRunner));
    ASSERT_NE(stsEnv, nullptr);

    stsEnv->DeInitLoop();
}

/**
 * @tc.name: ReInitUVLoop_0100
 * @tc.desc: ReInitUVLoop.
 * @tc.type: FUNC
 */
HWTEST_F(StsEnvironmentTest, ReInitUVLoop_0100, TestSize.Level0)
{
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner = AppExecFwk::EventRunner::Create(TEST_ABILITY_NAME);
    auto stsEnv =
        std::make_shared<STSEnvironment>(std::make_unique<AbilityRuntime::OHOSStsEnvironmentImpl>(eventRunner));
    bool result = stsEnv->ReInitUVLoop();
    EXPECT_EQ(result, true);
}

/**
 * @tc.name: GetAniEnv_0100
 * @tc.desc: GetAniEnv.
 * @tc.type: FUNC
 */
HWTEST_F(StsEnvironmentTest, GetAniEnv_0100, TestSize.Level0)
{
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner = AppExecFwk::EventRunner::Create(TEST_ABILITY_NAME);

    auto stsEnv =
        std::make_shared<STSEnvironment>(std::make_unique<AbilityRuntime::OHOSStsEnvironmentImpl>(eventRunner));
    STSEnvironment::VMEntry vMEntryOld = stsEnv->vmEntry_;
    STSEnvironment::VMEntry vmEntry;
    vmEntry.ani_env = nullptr;
    stsEnv->vmEntry_ = vmEntry;
    auto result = stsEnv->GetAniEnv();
    EXPECT_EQ(result, nullptr);
    stsEnv->vmEntry_ = vMEntryOld;
}

} // namespace StsEnv
} // namespace OHOS