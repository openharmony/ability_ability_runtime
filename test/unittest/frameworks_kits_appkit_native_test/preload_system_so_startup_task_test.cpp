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
#include "preload_system_so_startup_task.h"
#undef private
#include "mock_native_module_manager.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AbilityRuntime;

class PreloadSystemSoStartupTaskTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void PreloadSystemSoStartupTaskTest::SetUpTestCase() {}
void PreloadSystemSoStartupTaskTest::TearDownTestCase() {}
void PreloadSystemSoStartupTaskTest::SetUp()
{
    MockSetNativeModuleManager(nullptr);
    MockSetNativeModule(nullptr);
}
void PreloadSystemSoStartupTaskTest::TearDown() {}

/**
 * @tc.number: PreloadSystemSoStartupTask_0100
 * @tc.name: RunTaskInit
 * @tc.desc: Test RunTaskInit with empty ohmUrl.
 */
HWTEST_F(PreloadSystemSoStartupTaskTest, PreloadSystemSoStartupTask_0100, Function | MediumTest | Level1)
{
    auto task = std::make_shared<PreloadSystemSoStartupTask>("test", "");
    auto callback = std::make_unique<StartupTaskResultCallback>();
    int32_t ret = task->RunTaskInit(std::move(callback));
    EXPECT_EQ(ret, OHOS::ERR_OK);
}

/**
 * @tc.number: PreloadSystemSoStartupTask_0200
 * @tc.name: RunTaskInit
 * @tc.desc: Test RunTaskInit with invalid prefix.
 */
HWTEST_F(PreloadSystemSoStartupTaskTest, PreloadSystemSoStartupTask_0200, Function | MediumTest | Level1)
{
    auto task = std::make_shared<PreloadSystemSoStartupTask>("test", "@oho");
    auto callback = std::make_unique<StartupTaskResultCallback>();
    int32_t ret = task->RunTaskInit(std::move(callback));
    EXPECT_EQ(ret, OHOS::ERR_OK);
}

/**
 * @tc.number: PreloadSystemSoStartupTask_0300
 * @tc.name: RunTaskInit
 * @tc.desc: Test RunTaskInit with invalid prefix 2.
 */
HWTEST_F(PreloadSystemSoStartupTaskTest, PreloadSystemSoStartupTask_0300, Function | MediumTest | Level1)
{
    auto task = std::make_shared<PreloadSystemSoStartupTask>("test", "@ohos!test");
    auto callback = std::make_unique<StartupTaskResultCallback>();
    int32_t ret = task->RunTaskInit(std::move(callback));
    EXPECT_EQ(ret, OHOS::ERR_OK);
}

/**
 * @tc.number: PreloadSystemSoStartupTask_0400
 * @tc.name: RunTaskInit
 * @tc.desc: Test RunTaskInit with only prefix.
 */
HWTEST_F(PreloadSystemSoStartupTaskTest, PreloadSystemSoStartupTask_0400, Function | MediumTest | Level1)
{
    auto task = std::make_shared<PreloadSystemSoStartupTask>("test", "@ohos:");
    auto callback = std::make_unique<StartupTaskResultCallback>();
    int32_t ret = task->RunTaskInit(std::move(callback));
    EXPECT_EQ(ret, OHOS::ERR_OK);
}

/**
 * @tc.number: PreloadSystemSoStartupTask_0500
 * @tc.name: RunTaskInit
 * @tc.desc: Test RunTaskInit with moduleManager null.
 */
HWTEST_F(PreloadSystemSoStartupTaskTest, PreloadSystemSoStartupTask_0500, Function | MediumTest | Level1)
{
    auto task = std::make_shared<PreloadSystemSoStartupTask>("test", "@ohos:test");
    auto callback = std::make_unique<StartupTaskResultCallback>();
    MockSetNativeModuleManager(nullptr);
    int32_t ret = task->RunTaskInit(std::move(callback));
    EXPECT_EQ(ret, ERR_STARTUP_INTERNAL_ERROR);
}

/**
 * @tc.number: PreloadSystemSoStartupTask_0600
 * @tc.name: RunTaskInit
 * @tc.desc: Test RunTaskInit with load module failed.
 */
HWTEST_F(PreloadSystemSoStartupTaskTest, PreloadSystemSoStartupTask_0600, Function | MediumTest | Level1)
{
    auto task = std::make_shared<PreloadSystemSoStartupTask>("test", "@ohos:test");
    auto callback = std::make_unique<StartupTaskResultCallback>();
    MockSetNativeModuleManager(reinterpret_cast<NativeModuleManager*>(1));
    MockSetNativeModule(nullptr);
    int32_t ret = task->RunTaskInit(std::move(callback));
    EXPECT_EQ(ret, ERR_STARTUP_INTERNAL_ERROR);
}

/**
 * @tc.number: PreloadSystemSoStartupTask_0700
 * @tc.name: RunTaskInit
 * @tc.desc: Test RunTaskInit success.
 */
HWTEST_F(PreloadSystemSoStartupTaskTest, PreloadSystemSoStartupTask_0700, Function | MediumTest | Level1)
{
    auto task = std::make_shared<PreloadSystemSoStartupTask>("test", "@ohos:test");
    auto callback = std::make_unique<StartupTaskResultCallback>();
    MockSetNativeModuleManager(reinterpret_cast<NativeModuleManager*>(1));
    MockSetNativeModule(reinterpret_cast<NativeModule*>(1));
    int32_t ret = task->RunTaskInit(std::move(callback));
    EXPECT_EQ(ret, OHOS::ERR_OK);
}

/**
 * @tc.number: PreloadSystemSoStartupTask_0800
 * @tc.name: GetType
 * @tc.desc: Test GetType.
 */
HWTEST_F(PreloadSystemSoStartupTaskTest, PreloadSystemSoStartupTask_0800, Function | MediumTest | Level1)
{
    auto task = std::make_shared<PreloadSystemSoStartupTask>("test", "@ohos:test");
    EXPECT_EQ(task->GetType(), "PreloadSystemSo");
}
