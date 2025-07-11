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

void RegisterCJUncaughtExceptionHandlerTest(const CJUncaughtExceptionInfo &handle)
{}

/**
 * @tc.name: CjEnvironmentTestPostTask_001
 * @tc.desc: CjEnvironmentTest test for PostTask.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestPostTask_001, TestSize.Level2)
{
    CJEnvironment::GetInstance()->PostTask(nullptr);
    void (*func)() = TestFunc;
    auto ret = CJEnvironment::GetInstance()->PostTask(func);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: CjEnvironmentTestHasHigherPriorityTask_001
 * @tc.desc: CjEnvironmentTest test for HasHigherPriorityTask.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestHasHigherPriorityTask_001, TestSize.Level2)
{
    auto ret = CJEnvironment::GetInstance()->HasHigherPriorityTask();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CjEnvironmentTestInitCJChipSDKNS_001
 * @tc.desc: CjEnvironmentTest test for InitCJChipSDKNS.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitCJChipSDKNS_001, TestSize.Level2)
{
    CJEnvironment::GetInstance()->InitCJChipSDKNS("path/to/hap");
    EXPECT_NE(CJEnvironment::GetInstance()->cjAppNSName, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestInitCJAppNS_001
 * @tc.desc: CjEnvironmentTest test for InitCJAppNS.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitCJAppNS_001, TestSize.Level2)
{
    CJEnvironment::GetInstance()->InitCJAppNS("path/to/hap");
    EXPECT_NE(CJEnvironment::GetInstance()->cjAppNSName, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestInitCJSDKNS_001
 * @tc.desc: CjEnvironmentTest test for InitCJSDKNS.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitCJSDKNS_001, TestSize.Level2)
{
    CJEnvironment::GetInstance()->InitCJSDKNS("path/to/hap");
    EXPECT_NE(CJEnvironment::GetInstance()->cjAppNSName, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestInitCJSysNS_001
 * @tc.desc: CjEnvironmentTest test for InitCJSysNS.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitCJSysNS_001, TestSize.Level2)
{
    CJEnvironment::GetInstance()->InitCJSysNS("path/to/hap");
    EXPECT_NE(CJEnvironment::GetInstance()->cjAppNSName, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestStartRuntime_001
 * @tc.desc: CjEnvironmentTest test for StartRuntime.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestStartRuntime_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::APP);
    CJUncaughtExceptionInfo handle;
    handle.hapPath = "/test1/";
    handle.uncaughtTask = [](const char* summary, const CJErrorObject errorObj) {};

    CJRuntimeAPI api {
        .InitCJRuntime = nullptr,
        .InitUIScheduler = nullptr,
        .RunUIScheduler = nullptr,
        .FiniCJRuntime = nullptr,
        .InitCJLibrary = nullptr,
        .RegisterEventHandlerCallbacks = nullptr,
        .RegisterCJUncaughtExceptionHandler = RegisterCJUncaughtExceptionHandlerTest,
    };

    CJRuntimeAPI* lazyApi = new CJRuntimeAPI(api);
    cJEnvironment.SetLazyApis(lazyApi);
    cJEnvironment.RegisterCJUncaughtExceptionHandler(handle);
    auto ret = cJEnvironment.StartRuntime();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CjEnvironmentTestStopRuntime_001
 * @tc.desc: CjEnvironmentTest test for StopRuntime.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestStopRuntime_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::APP);
    CJUncaughtExceptionInfo handle;
    handle.hapPath = "/test1/";
    handle.uncaughtTask = [](const char* summary, const CJErrorObject errorObj) {};

    CJRuntimeAPI api {
        .InitCJRuntime = nullptr,
        .InitUIScheduler = nullptr,
        .RunUIScheduler = nullptr,
        .FiniCJRuntime = nullptr,
        .InitCJLibrary = nullptr,
        .RegisterEventHandlerCallbacks = nullptr,
        .RegisterCJUncaughtExceptionHandler = RegisterCJUncaughtExceptionHandlerTest,
    };

    CJRuntimeAPI* lazyApi = new CJRuntimeAPI(api);
    cJEnvironment.SetLazyApis(lazyApi);
    cJEnvironment.RegisterCJUncaughtExceptionHandler(handle);
    cJEnvironment.StopRuntime();
    EXPECT_EQ(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestStopUIScheduler_001
 * @tc.desc: CjEnvironmentTest test for StopUIScheduler.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestStopUIScheduler_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::APP);
    CJUncaughtExceptionInfo handle;
    handle.hapPath = "/test1/";
    handle.uncaughtTask = [](const char* summary, const CJErrorObject errorObj) {};

    CJRuntimeAPI api {
        .InitCJRuntime = nullptr,
        .InitUIScheduler = nullptr,
        .RunUIScheduler = nullptr,
        .FiniCJRuntime = nullptr,
        .InitCJLibrary = nullptr,
        .RegisterEventHandlerCallbacks = nullptr,
        .RegisterCJUncaughtExceptionHandler = RegisterCJUncaughtExceptionHandlerTest,
    };

    CJRuntimeAPI* lazyApi = new CJRuntimeAPI(api);
    cJEnvironment.SetLazyApis(lazyApi);
    cJEnvironment.RegisterCJUncaughtExceptionHandler(handle);
    cJEnvironment.StopUIScheduler();
    EXPECT_EQ(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestLoadCJLibrary_001
 * @tc.desc: CjEnvironmentTest test for LoadCJLibrary.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestLoadCJLibrary_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::APP);
    auto ret = cJEnvironment.LoadCJLibrary("dlName");
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestLoadCJLibrary_001
 * @tc.desc: CjEnvironmentTest test for LoadCJLibrary.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestLoadCJLibrary_002, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::APP);
    cJEnvironment.LoadCJLibrary(CJEnvironment::GetInstance()->LibraryKind::APP, "dlName");
    cJEnvironment.LoadCJLibrary(CJEnvironment::GetInstance()->LibraryKind::SYSTEM, "dlName");
    cJEnvironment.LoadCJLibrary(CJEnvironment::GetInstance()->LibraryKind::SDK, "dlName");
    EXPECT_EQ(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestStartDebugger_001
 * @tc.desc: CjEnvironmentTest test for StartDebugger.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestStartDebugger_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::APP);
    auto ret = cJEnvironment.StartDebugger();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CjEnvironmentTestGetSymbol_001
 * @tc.desc: CjEnvironmentTest test for GetSymbol.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestGetSymbol_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::APP);
    auto ret = cJEnvironment.GetSymbol(nullptr, "dlName");
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: InitCJNS_0100
 * @tc.desc: Test InitCJNS.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitCJNS_0100, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::APP);
    std::string appPath = "com/ohos/unittest/test/";
    cJEnvironment.InitCJNS(appPath);
    EXPECT_EQ(cJEnvironment.IsRuntimeStarted(), false);
}

/**
 * @tc.name: SanitizerKindRuntimeVersion_001
 * @tc.desc: Test SanitizerKindRuntimeVersion.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestSanitizerKindRuntimeVersion_001, TestSize.Level2)
{
    CJEnvMethods* cjEnv = CJEnvironment::CreateEnvMethods();
    SanitizerKind kind = SanitizerKind::ASAN;
    cjEnv->setSanitizerKindRuntimeVersion(kind);
    EXPECT_NE(OHOS::CJEnvironment::sanitizerKind, SanitizerKind::NONE);
    kind = SanitizerKind::NONE;
    cjEnv->setSanitizerKindRuntimeVersion(kind);
    EXPECT_EQ(OHOS::CJEnvironment::sanitizerKind, SanitizerKind::NONE);
}

/**
 * @tc.name: CjEnvironmentTestDetectAppNSMode_001
 * @tc.desc: Test DetectAppNSMode.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestDetectAppNSMode_001, TestSize.Level2)
{
    SanitizerKind kind = SanitizerKind::ASAN;
    OHOS::CJEnvironment::SetSanitizerKindRuntimeVersion(kind);
    EXPECT_EQ(OHOS::CJEnvironment::DetectAppNSMode(), OHOS::CJEnvironment::NSMode::APP);
    kind = SanitizerKind::NONE;
    OHOS::CJEnvironment::SetSanitizerKindRuntimeVersion(kind);
    EXPECT_EQ(OHOS::CJEnvironment::DetectAppNSMode(), OHOS::CJEnvironment::NSMode::SINK);
}