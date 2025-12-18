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

void DumpHeapSnapshot(int fd)
{}

void ForceFullGC()
{}

int InitCJLibrary(const char* dlName)
{
    return E_OK;
}

void RegisterStackInfoCallbacks(UpdateStackInfoFuncType uFunc)
{}

void RegisterArkVMInRuntime(unsigned long long externalVM)
{}

void* InitUIScheduler()
{
    return nullptr;
}

void RegisterEventHandlerCallbacks(PostTaskType, HasHigherPriorityType)
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

    CJRuntimeAPI api;
    api.RegisterCJUncaughtExceptionHandler = RegisterCJUncaughtExceptionHandlerTest;
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI(api);
    cJEnvironment.SetLazyApis(lazyApis_);
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

    CJRuntimeAPI api;
    api.RegisterCJUncaughtExceptionHandler = RegisterCJUncaughtExceptionHandlerTest;
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI(api);
    cJEnvironment.SetLazyApis(lazyApis_);
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

    CJRuntimeAPI api;
    api.RegisterCJUncaughtExceptionHandler = RegisterCJUncaughtExceptionHandlerTest;
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI(api);
    cJEnvironment.SetLazyApis(lazyApis_);
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
 * @tc.name: CjEnvironmentTestLoadCJLibrary_002
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
 * @tc.name: CjEnvironmentTestLoadCJLibrary_003
 * @tc.desc: CjEnvironmentTest test for LoadCJLibrary.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestLoadCJLibrary_003, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    auto result = cJEnvironment.LoadCJLibrary(CJEnvironment::GetInstance()->LibraryKind::SDK, "dlName");
    EXPECT_EQ(result, nullptr);
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
    EXPECT_EQ(CJEnvironment::GetInstance(), nullptr);
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
}

/**
 * @tc.name: SanitizerKindRuntimeVersion_002
 * @tc.desc: Test SanitizerKindRuntimeVersion.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestSanitizerKindRuntimeVersion_002, TestSize.Level2)
{
    CJEnvMethods* cjEnv = CJEnvironment::CreateEnvMethods();
    SanitizerKind kind = SanitizerKind::NONE;
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
    EXPECT_EQ(OHOS::CJEnvironment::DetectAppNSMode(), OHOS::CJEnvironment::NSMode::SINK);
}

/**
 * @tc.name: CjEnvironmentTestDynamicInherit_001
 * @tc.desc: Test DynamicInherit.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestDynamicInherit_001, TestSize.Level2)
{
    Dl_namespace ns;
    dlns_get("cj_test_namespace", &ns);
    DynamicInherit(&ns, "cj_test_namespace_2", "allow_all_shared_libs");
    DynamicInheritByName("cj_test_namespace", "cj_test_namespace_2", "allow_all_shared_libs");
    EXPECT_EQ(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestDynamicInherit_002
 * @tc.desc: Test DynamicInherit.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestDynamicInherit_002, TestSize.Level2)
{
    Dl_namespace ns;
    dlns_get("cj_test_namespace", &ns);
    DynamicInherit(&ns, "default", "allow_all_shared_libs");
    DynamicInheritByName("cj_test_namespace", "default", "allow_all_shared_libs");
    DynamicInheritByName("default", "cj_test_namespace", "allow_all_shared_libs");
    EXPECT_EQ(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestDynamicInherit_003
 * @tc.desc: Test DynamicInherit.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestDynamicInherit_003, TestSize.Level2)
{
    Dl_namespace ns;
    dlns_get("cj_test_namespace", &ns);
    DynamicInherit(&ns, nullptr, nullptr);
    DynamicInheritByName(nullptr, nullptr, nullptr);
    DynamicInheritByName("cj_test_namespace", nullptr, nullptr);
    DynamicInheritByName("cj_test_namespace", "cj_test_namespace", nullptr);
    EXPECT_EQ(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestSetAppPath_001
 * @tc.desc: CjEnvironmentTest test for SetAppPath.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestSetAppPath_001, TestSize.Level2)
{
    CJEnvironment::SetSanitizerKindRuntimeVersion(OHOS::SanitizerKind::ASAN);
    CJEnvironment::SetAppPath("path/to/hap");
    EXPECT_NE(CJEnvironment::GetInstance()->cjAppNSName, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestLoadRuntimeLib_001
 * @tc.desc: CjEnvironmentTest test for LoadRuntimeLib.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestLoadRuntimeLib_001, TestSize.Level2)
{
    CJEnvironment::SetAppPath("");
    EXPECT_EQ(CJEnvironment::GetInstance()->LoadRuntimeLib("test.so"), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestInitCJLibrary_001
 * @tc.desc: CjEnvironmentTest test for InitCJLibrary.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitCJLibrary_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    auto res = cJEnvironment.InitCJLibrary(nullptr);
    EXPECT_EQ(res, E_FAILED);
}

/**
 * @tc.name: CjEnvironmentTestInitCJLibrary_002
 * @tc.desc: CjEnvironmentTest test for InitCJLibrary.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitCJLibrary_002, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    cJEnvironment.UnLoadRuntimeApis();
    auto res = cJEnvironment.InitCJLibrary("lib_cj_test.so");
    EXPECT_EQ(res, E_FAILED);
}

/**
 * @tc.name: CjEnvironmentTestInitCJLibrary_003
 * @tc.desc: CjEnvironmentTest test for InitCJLibrary.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitCJLibrary_003, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI api;
    api.InitCJLibrary = InitCJLibrary;
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI(api);
    cJEnvironment.SetLazyApis(lazyApis_);
    auto res = cJEnvironment.InitCJLibrary("lib_cj_test.so");
    EXPECT_EQ(res, E_OK);
}

/**
 * @tc.name: CjEnvironmentTestInitCJLibrary_004
 * @tc.desc: CjEnvironmentTest test for InitCJLibrary.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitCJLibrary_004, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI();
    cJEnvironment.SetLazyApis(lazyApis_);
    auto res = cJEnvironment.InitCJLibrary("lib_cj_test.so");
    EXPECT_EQ(res, E_FAILED);
}

/**
 * @tc.name: CjEnvironmentTestFiniCJRuntime_001
 * @tc.desc: CjEnvironmentTest test for FiniCJRuntime.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestFiniCJRuntime_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    cJEnvironment.UnLoadRuntimeApis();
    auto res = cJEnvironment.FiniCJRuntime();
    EXPECT_EQ(res, E_FAILED);
}

/**
 * @tc.name: CjEnvironmentTestFiniCJRuntime_002
 * @tc.desc: CjEnvironmentTest test for FiniCJRuntime.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestFiniCJRuntime_002, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI();
    cJEnvironment.SetLazyApis(lazyApis_);
    auto res = cJEnvironment.FiniCJRuntime();
    EXPECT_EQ(res, E_FAILED);
}

/**
 * @tc.name: CjEnvironmentTestInitUIScheduler_001
 * @tc.desc: CjEnvironmentTest test for InitUIScheduler.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitUIScheduler_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    cJEnvironment.UnLoadRuntimeApis();
    auto res = cJEnvironment.InitUIScheduler();
    EXPECT_EQ(res, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestInitUIScheduler_002
 * @tc.desc: CjEnvironmentTest test for InitUIScheduler.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitUIScheduler_002, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI api;
    api.InitUIScheduler = InitUIScheduler;
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI(api);
    cJEnvironment.SetLazyApis(lazyApis_);
    auto res = cJEnvironment.InitUIScheduler();
    EXPECT_EQ(res, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestInitUIScheduler_003
 * @tc.desc: CjEnvironmentTest test for InitUIScheduler.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestInitUIScheduler_003, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI();
    cJEnvironment.SetLazyApis(lazyApis_);
    auto res = cJEnvironment.InitUIScheduler();
    EXPECT_EQ(res, nullptr);
}

/**
 * @tc.name: CjEnvironmentTestDumpHeapSnapshot_001
 * @tc.desc: CjEnvironmentTest test for DumpHeapSnapshot.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestDumpHeapSnapshot_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    cJEnvironment.UnLoadRuntimeApis();
    cJEnvironment.DumpHeapSnapshot(0);
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestDumpHeapSnapshot_002
 * @tc.desc: CjEnvironmentTest test for DumpHeapSnapshot.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestDumpHeapSnapshot_002, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI api;
    api.DumpHeapSnapshot = DumpHeapSnapshot;
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI(api);
    cJEnvironment.SetLazyApis(lazyApis_);
    cJEnvironment.DumpHeapSnapshot(0);
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestDumpHeapSnapshot_003
 * @tc.desc: CjEnvironmentTest test for DumpHeapSnapshot.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestDumpHeapSnapshot_003, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI();
    cJEnvironment.SetLazyApis(lazyApis_);
    cJEnvironment.DumpHeapSnapshot(0);
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestForceFullGC_001
 * @tc.desc: CjEnvironmentTest test for ForceFullGC.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestForceFullGC_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    cJEnvironment.UnLoadRuntimeApis();
    cJEnvironment.ForceFullGC();
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestForceFullGC_002
 * @tc.desc: CjEnvironmentTest test for ForceFullGC.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestForceFullGC_002, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI api;
    api.ForceFullGC = ForceFullGC;
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI(api);
    cJEnvironment.SetLazyApis(lazyApis_);
    cJEnvironment.ForceFullGC();
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestForceFullGC_003
 * @tc.desc: CjEnvironmentTest test for ForceFullGC.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestForceFullGC_003, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI();
    cJEnvironment.SetLazyApis(lazyApis_);
    cJEnvironment.ForceFullGC();
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestRegisterStackInfoCallbacks_001
 * @tc.desc: CjEnvironmentTest test for RegisterStackInfoCallbacks.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestRegisterStackInfoCallbacks_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    cJEnvironment.UnLoadRuntimeApis();
    cJEnvironment.RegisterStackInfoCallbacks(nullptr);
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestRegisterStackInfoCallbacks_002
 * @tc.desc: CjEnvironmentTest test for RegisterStackInfoCallbacks.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestRegisterStackInfoCallbacks_002, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI api;
    api.RegisterStackInfoCallbacks = RegisterStackInfoCallbacks;
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI(api);
    cJEnvironment.SetLazyApis(lazyApis_);
    cJEnvironment.RegisterStackInfoCallbacks(nullptr);
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestRegisterStackInfoCallbacks_003
 * @tc.desc: CjEnvironmentTest test for RegisterStackInfoCallbacks.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestRegisterStackInfoCallbacks_003, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI();
    cJEnvironment.SetLazyApis(lazyApis_);
    cJEnvironment.RegisterStackInfoCallbacks(nullptr);
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestRegisterArkVMInRuntime_001
 * @tc.desc: CjEnvironmentTest test for RegisterArkVMInRuntime.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestRegisterArkVMInRuntime_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    cJEnvironment.UnLoadRuntimeApis();
    cJEnvironment.RegisterArkVMInRuntime(0);
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestRegisterArkVMInRuntime_002
 * @tc.desc: CjEnvironmentTest test for RegisterArkVMInRuntime.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestRegisterArkVMInRuntime_002, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI api;
    api.RegisterArkVMInRuntime = RegisterArkVMInRuntime;
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI(api);
    cJEnvironment.SetLazyApis(lazyApis_);
    cJEnvironment.RegisterArkVMInRuntime(0);
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestRegisterArkVMInRuntime_003
 * @tc.desc: CjEnvironmentTest test for RegisterArkVMInRuntime.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestRegisterArkVMInRuntime_003, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI();
    cJEnvironment.SetLazyApis(lazyApis_);
    cJEnvironment.RegisterArkVMInRuntime(0);
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestRegisterEventHandlerCallbacks_001
 * @tc.desc: CjEnvironmentTest test for RegisterEventHandlerCallbacks.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestRegisterEventHandlerCallbacks_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    cJEnvironment.UnLoadRuntimeApis();
    cJEnvironment.RegisterEventHandlerCallbacks();
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestRegisterEventHandlerCallbacks_002
 * @tc.desc: CjEnvironmentTest test for RegisterEventHandlerCallbacks.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestRegisterEventHandlerCallbacks_002, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI api;
    api.RegisterEventHandlerCallbacks = RegisterEventHandlerCallbacks;
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI(api);
    cJEnvironment.SetLazyApis(lazyApis_);
    cJEnvironment.RegisterEventHandlerCallbacks();
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestRegisterEventHandlerCallbacks_003
 * @tc.desc: CjEnvironmentTest test for RegisterEventHandlerCallbacks.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestRegisterEventHandlerCallbacks_003, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI();
    cJEnvironment.SetLazyApis(lazyApis_);
    cJEnvironment.RegisterEventHandlerCallbacks();
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestRegisterCJUncaughtExceptionHandler_001
 * @tc.desc: CjEnvironmentTest test for RegisterCJUncaughtExceptionHandler.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestRegisterCJUncaughtExceptionHandler_001, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJUncaughtExceptionInfo handle;
    handle.hapPath = "/test1/";
    handle.uncaughtTask = [](const char* summary, const CJErrorObject errorObj) {};
    cJEnvironment.UnLoadRuntimeApis();
    cJEnvironment.RegisterCJUncaughtExceptionHandler(handle);
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestRegisterCJUncaughtExceptionHandler_002
 * @tc.desc: CjEnvironmentTest test for RegisterCJUncaughtExceptionHandler.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestRegisterCJUncaughtExceptionHandler_002, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJUncaughtExceptionInfo handle;
    handle.hapPath = "/test1/";
    handle.uncaughtTask = [](const char* summary, const CJErrorObject errorObj) {};

    CJRuntimeAPI api;
    api.RegisterCJUncaughtExceptionHandler = RegisterCJUncaughtExceptionHandlerTest;
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI(api);
    cJEnvironment.SetLazyApis(lazyApis_);
    cJEnvironment.RegisterCJUncaughtExceptionHandler(handle);
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: CjEnvironmentTestRegisterCJUncaughtExceptionHandler_003
 * @tc.desc: CjEnvironmentTest test for RegisterCJUncaughtExceptionHandler.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestRegisterCJUncaughtExceptionHandler_003, TestSize.Level2)
{
    CJEnvironment cJEnvironment(CJEnvironment::NSMode::SINK);
    CJUncaughtExceptionInfo handle;
    handle.hapPath = "/test1/";
    handle.uncaughtTask = [](const char* summary, const CJErrorObject errorObj) {};
    CJRuntimeAPI* lazyApis_ = new CJRuntimeAPI();
    cJEnvironment.SetLazyApis(lazyApis_);
    cJEnvironment.RegisterCJUncaughtExceptionHandler(handle);
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: DumpCjHeap_0100
 * @tc.desc: Test DumpCjHeap.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestDumpCjHeap_0100, TestSize.Level2)
{
    CJEnvironment::DumpCjHeap(1);
    CJEnvironment::SetAppPath("path/to/hap");
    CJEnvironment::DumpCjHeap(2);
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}

/**
 * @tc.name: GC_0100
 * @tc.desc: Test GC.
 * @tc.type: FUNC
 */
HWTEST_F(CjEnvironmentTest, CjEnvironmentTestGC_0100, TestSize.Level2)
{
    CJEnvironment::GC();
    CJEnvironment::SetAppPath("path/to/hap");
    CJEnvironment::GC();
    EXPECT_NE(CJEnvironment::GetInstance(), nullptr);
}