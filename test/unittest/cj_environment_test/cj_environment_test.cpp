/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "cj_environment.h"
#include "dynamic_loader.h"

#include <string>

#include "cj_invoker.h"
#ifdef __OHOS__
#include <dlfcn.h>
#endif
#include "dynamic_loader.h"
#ifdef WITH_EVENT_HANDLER
#include "event_handler.h"
#endif

using namespace OHOS;
using namespace testing;
using namespace testing::ext;


class CjEnvironmentTest : public testing::Test {
public:
    CjEnvironmentTest()
    {}
    ~CjEnvironmentTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;
};

void CjEnvironmentTest::SetUpTestCase(void)
{}

void CjEnvironmentTest::TearDownTestCase(void)
{}

void CjEnvironmentTest::SetUp(void)
{}

void CjEnvironmentTest::TearDown(void)
{}

void TestFunc()
{}

/**
 * @tc.name: CjEnvironmentTestPostTask_001
 * @tc.desc: CjEnvironmentTest test for PostTask.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestPostTask_001, TestSize.Level0)
{
    auto cjEnv = std::make_shared<CJEnvironment>(CJEnvironment::NSMode::APP);
    cjEnv->PostTask(nullptr);
    void (*func)() = TestFunc;
    auto ret = cjEnv->PostTask(func);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: CjEnvironmentTestHasHigherPriorityTask_001
 * @tc.desc: CjEnvironmentTest test for HasHigherPriorityTask.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestHasHigherPriorityTask_001, TestSize.Level0)
{
    auto cjEnv = std::make_shared<CJEnvironment>(CJEnvironment::NSMode::APP);
    auto ret = cjEnv->HasHigherPriorityTask();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CjEnvironmentTestInitCJChipSDKNS_001
 * @tc.desc: CjEnvironmentTest test for InitCJChipSDKNS.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitCJChipSDKNS_001, TestSize.Level0)
{
    auto cjEnv = std::make_shared<CJEnvironment>(CJEnvironment::NSMode::APP);
    cjEnv->InitCJChipSDKNS("path/to/hap");
    EXPECT_NE(cjEnv->cjAppNSName, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestInitCJAppNS_001
 * @tc.desc: CjEnvironmentTest test for InitCJAppNS.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitCJAppNS_001, TestSize.Level0)
{
    auto cjEnv = std::make_shared<CJEnvironment>(CJEnvironment::NSMode::APP);
    cjEnv->InitCJAppNS("path/to/hap");
    EXPECT_NE(cjEnv->cjAppNSName, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestInitCJSDKNS_001
 * @tc.desc: CjEnvironmentTest test for InitCJSDKNS.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitCJSDKNS_001, TestSize.Level0)
{
    auto cjEnv = std::make_shared<CJEnvironment>(CJEnvironment::NSMode::APP);
    cjEnv->InitCJSDKNS("path/to/hap");
    EXPECT_NE(cjEnv->cjAppNSName, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestInitCJSysNS_001
 * @tc.desc: CjEnvironmentTest test for InitCJSysNS.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitCJSysNS_001, TestSize.Level0)
{
    auto cjEnv = std::make_shared<CJEnvironment>(CJEnvironment::NSMode::APP);
    cjEnv->InitCJSysNS("path/to/hap");
    EXPECT_NE(cjEnv->cjAppNSName, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestStartRuntime_001
 * @tc.desc: CjEnvironmentTest test for StartRuntime.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestStartRuntime_001, TestSize.Level0)
{
    auto cjEnv = std::make_shared<CJEnvironment>(CJEnvironment::NSMode::APP);
    auto ret = cjEnv->StartRuntime();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CjEnvironmentTestStopRuntime_001
 * @tc.desc: CjEnvironmentTest test for StopRuntime.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestStopRuntime_001, TestSize.Level0)
{
    auto cjEnv = std::make_shared<CJEnvironment>(CJEnvironment::NSMode::APP);
    cjEnv->StopRuntime();
    EXPECT_NE(cjEnv, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestStopUIScheduler_001
 * @tc.desc: CjEnvironmentTest test for StopUIScheduler.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestStopUIScheduler_001, TestSize.Level0)
{
    auto cjEnv = std::make_shared<CJEnvironment>(CJEnvironment::NSMode::APP);
    cjEnv->StopUIScheduler();
    EXPECT_NE(cjEnv, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestLoadCJLibrary_001
 * @tc.desc: CjEnvironmentTest test for LoadCJLibrary.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestLoadCJLibrary_001, TestSize.Level0)
{
    auto cjEnv = std::make_shared<CJEnvironment>(CJEnvironment::NSMode::APP);
    auto ret = cjEnv->LoadCJLibrary("dlName");
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestLoadCJLibrary_001
 * @tc.desc: CjEnvironmentTest test for LoadCJLibrary.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestLoadCJLibrary_002, TestSize.Level0)
{
    auto cjEnv = std::make_shared<CJEnvironment>(CJEnvironment::NSMode::APP);
    cjEnv->LoadCJLibrary(cjEnv->LibraryKind::APP, "dlName");
    cjEnv->LoadCJLibrary(cjEnv->LibraryKind::SYSTEM, "dlName");
    cjEnv->LoadCJLibrary(cjEnv->LibraryKind::SDK, "dlName");
    EXPECT_NE(cjEnv, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestStartDebugger_001
 * @tc.desc: CjEnvironmentTest test for StartDebugger.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestStartDebugger_001, TestSize.Level0)
{
    auto cjEnv = std::make_shared<CJEnvironment>(CJEnvironment::NSMode::APP);
    auto ret = cjEnv->StartDebugger();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CjEnvironmentTestGetSymbol_001
 * @tc.desc: CjEnvironmentTest test for GetSymbol.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestGetSymbol_001, TestSize.Level0)
{
    auto cjEnv = std::make_shared<CJEnvironment>(CJEnvironment::NSMode::APP);
    auto ret = cjEnv->GetSymbol(nullptr, "dlName");
    EXPECT_EQ(ret, nullptr);
}
