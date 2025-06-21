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
#include <dlfcn.h>
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
 * @tc.name: GetBuildId_0100
 * @tc.desc: Test GetBuildId with stack containing non-parseable lines.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, GetBuildId_0100, TestSize.Level0)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    std::string stack = "NonParseableLineWithoutSpace\n"
                        "#00 pc 000000000001a0b8 /system/lib64/libutils.so\n"
                        "AnotherLineWithoutSpace\n";
    std::string result = etsEnv->GetBuildId(stack);
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("/system/lib64/libutils.so"), std::string::npos);
    EXPECT_EQ(result.find("NonParseableLineWithoutSpace"), std::string::npos);
    EXPECT_EQ(result.find("AnotherLineWithoutSpace"), std::string::npos);
    size_t expectedLines = 1;
    size_t resultLines = std::count(result.begin(), result.end(), '\n');
    EXPECT_EQ(resultLines, expectedLines);
}

/**
 * @tc.name: GetBuildId_0200
 * @tc.desc: Test GetBuildId with empty input.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, GetBuildId_0200, TestSize.Level0)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    std::string stack = "";
    std::string result = etsEnv->GetBuildId(stack);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: GetBuildId_0300
 * @tc.desc: Test GetBuildId with stack containing only newlines.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, GetBuildId_0300, TestSize.Level0)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    std::string stack = "\n\n\n";
    std::string result = etsEnv->GetBuildId(stack);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: RegisterUncaughtExceptionHandler_0100
 * @tc.desc: Test basic registration and triggering of uncaught exception handler.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, RegisterUncaughtExceptionHandler_0100, TestSize.Level0)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    g_callbackModuleFlag = false;
    ETSUncaughtExceptionInfo handlerInfo;
    handlerInfo.uncaughtTask = [](const std::string& summary, const ETSErrorObject& errorObj) {
        g_callbackModuleFlag = true;
    };
    etsEnv->RegisterUncaughtExceptionHandler(handlerInfo);
    ETSErrorObject errorObj;
    errorObj.name = "TestError";
    errorObj.message = "Test error message";
    errorObj.stack = "Test stack trace";
    etsEnv->uncaughtExceptionInfo_.uncaughtTask("Test summary", errorObj);
    EXPECT_TRUE(g_callbackModuleFlag);
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

/**
 * @tc.name: LoadSymbolCreateVM_0100
 * @tc.desc: Test LoadSymbolCreateVM when dlsym returns nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, LoadSymbolCreateVM_0100, TestSize.Level1)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    void* handle = dlopen(nullptr, RTLD_LAZY);
    ASSERT_NE(handle, nullptr);
    ETSRuntimeAPI apis = {};
    bool result = etsEnv->LoadSymbolCreateVM(handle, apis);
    dlclose(handle);
    EXPECT_TRUE(result);
    EXPECT_NE(apis.ANI_CreateVM, nullptr);
}

/**
 * @tc.name: LoadSymbolCreateVM_0200
 * @tc.desc: Test LoadSymbolCreateVM returns false when symbol is not found.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, LoadSymbolCreateVM_0200, TestSize.Level0)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    void* invalidHandle = reinterpret_cast<void*>(0x1);
    ETSRuntimeAPI apis = {};
    bool result = etsEnv->LoadSymbolCreateVM(invalidHandle, apis);
    EXPECT_FALSE(result);
    EXPECT_EQ(apis.ANI_CreateVM, nullptr);
}

/**
 * @tc.name: LoadSymbolANIGetCreatedVMs_0100
 * @tc.desc: Test LoadSymbolANIGetCreatedVMs when symbol is not found.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, LoadSymbolANIGetCreatedVMs_0100, TestSize.Level1)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    void* handle = dlopen(nullptr, RTLD_LAZY);
    ASSERT_NE(handle, nullptr);
    ETSRuntimeAPI apis = {};
    bool result = etsEnv->LoadSymbolANIGetCreatedVMs(handle, apis);
    dlclose(handle);
    EXPECT_TRUE(result);
    EXPECT_NE(apis.ANI_GetCreatedVMs, nullptr);
}

/**
 * @tc.name: LoadSymbolANIGetCreatedVMs_0200
 * @tc.desc: Test LoadSymbolANIGetCreatedVMs returns false when symbol is not found.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, LoadSymbolANIGetCreatedVMs_0200, TestSize.Level0)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    void* invalidHandle = reinterpret_cast<void*>(0x1);
    ETSRuntimeAPI apis = {};
    bool result = etsEnv->LoadSymbolANIGetCreatedVMs(invalidHandle, apis);
    EXPECT_FALSE(result);
    EXPECT_EQ(apis.ANI_GetCreatedVMs, nullptr);
}

/**
 * @tc.name: Initialize_0100
 * @tc.desc: Test Initialize can be called without crash.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, Initialize_0100, TestSize.Level0)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    napi_env napiEnv = reinterpret_cast<napi_env>(0x1);
    std::vector<ani_option> options;
    bool result = etsEnv->Initialize(napiEnv, options);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: HandleUncaughtError_0100
 * @tc.desc: Test HandleUncaughtError can be called without crash.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, HandleUncaughtError_0100, TestSize.Level1)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    bool result = etsEnv->HandleUncaughtError();
    EXPECT_FALSE(result);
}

/**
 * @tc.name: LoadAbcLinker_0100
 * @tc.desc: LoadAbcLinker returns false when env is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, LoadAbcLinker_0100, TestSize.Level0)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    ani_class cls = nullptr;
    ani_object obj = nullptr;
    bool result = etsEnv->LoadAbcLinker(nullptr, "testModule", cls, obj);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: PreloadModule_0100
 * @tc.desc: PreloadModule returns false when env is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, PreloadModule_0100, TestSize.Level0)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    bool result = etsEnv->PreloadModule("testModule");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: LoadModule_0100
 * @tc.desc: LoadModule returns false when env is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(EtsEnvironmentTest, LoadModule_0100, TestSize.Level0)
{
    auto etsEnv = std::make_shared<ETSEnvironment>();
    ASSERT_NE(etsEnv, nullptr);
    ani_class cls = nullptr;
    ani_object obj = nullptr;
    ani_ref ref = nullptr;
    bool result = etsEnv->LoadModule("testModule", "testModule", cls, obj, ref);
    EXPECT_FALSE(result);
}
} // namespace StsEnv
} // namespace OHOS