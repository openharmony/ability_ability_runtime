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
#include <gtest/hwext/gtest-multithread.h>

#define private public
#define protected public
#include "ets_environment.h"
#include "ets_runtime.h"
#undef private
#undef protected
#include "hilog_tag_wrapper.h"
#include "js_runtime.h"
#include "runtime.h"
#include "ets_environment.h"

using namespace testing;
using namespace testing::ext;
using namespace testing::mt;

namespace OHOS {
namespace AbilityRuntime {
namespace {
const std::string TEST_BUNDLE_NAME = "com.ohos.contactsdataability";
const std::string TEST_MODULE_NAME = ".ContactsDataAbility";
const std::string TEST_ABILITY_NAME = "ContactsDataAbility";
const std::string TEST_CODE_PATH = "/data/storage/el1/bundle";
const std::string TEST_HAP_PATH = "/system/app/com.ohos.contactsdataabilityContacts_DataAbility.hap";
const std::string TEST_LIB_PATH = "/data/storage/el1/bundle/lib/";
const std::string TEST_MODULE_PATH = "/data/storage/el1/bundle/curJsModulePath";
} // namespace

class EtsRuntimeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    Runtime::Options options_;
};

void EtsRuntimeTest::SetUpTestCase() {}

void EtsRuntimeTest::TearDownTestCase() {}

void EtsRuntimeTest::SetUp()
{
    Runtime::Options newOptions;
    options_ = newOptions;
    options_.bundleName = TEST_BUNDLE_NAME;
    options_.codePath = TEST_CODE_PATH;
    options_.loadAce = false;
    options_.isBundle = true;
    options_.preload = false;
    std::shared_ptr<AppExecFwk::EventRunner> eventRunner = AppExecFwk::EventRunner::Create(TEST_ABILITY_NAME);
    options_.eventRunner = eventRunner;
}

void EtsRuntimeTest::TearDown() {}

/**
 * @tc.name: Create_100
 * @tc.desc: EtsRuntime test for Create Initialize failed.
 * @tc.type: FUNC
 */
HWTEST_F(EtsRuntimeTest, Create_100, TestSize.Level1)
{
    options_.lang = Runtime::Language::JS;
    options_.preload = true;
    options_.isStageModel = false;
    auto jsRuntime = JsRuntime::Create(options_);
    auto etsRuntime = ETSRuntime::Create(options_, jsRuntime.get());
    EXPECT_EQ(etsRuntime, nullptr);
    options_.lang = Runtime::Language::ETS;
    options_.preload = false;
    options_.isStageModel = true;
}

/**
 * @tc.name: SetAppLibPath_100
 * @tc.desc: EtsRuntime test for SetAppLibPath.
 * @tc.type: FUNC
 */
HWTEST_F(EtsRuntimeTest, SetAppLibPath_100, TestSize.Level1)
{
    std::map<std::string, std::vector<std::string>> testPathMap;
    testPathMap["com.example.app"] = { "/data/abc", "/data/def" };
    testPathMap["com.example.demo"] = { "/data/demo/es", "/data/demo/ts" };
    std::unique_ptr<ETSRuntime> etsRuntime = std::make_unique<ETSRuntime>();
    etsRuntime->SetAppLibPath(testPathMap);
    EXPECT_NE(testPathMap.size(), 0);
}

/**
 * @tc.name: Initialize_100
 * @tc.desc: EtsRuntime test for Initialize lang is not ETS.
 * @tc.type: FUNC
 */
HWTEST_F(EtsRuntimeTest, Initialize_100, TestSize.Level1)
{
    options_.lang = Runtime::Language::JS;
    Runtime *jsRuntime = nullptr;
    std::unique_ptr<ETSRuntime> etsRuntime = std::make_unique<ETSRuntime>();
    bool result = etsRuntime->Initialize(options_, jsRuntime);
    EXPECT_EQ(result, false);
    options_.lang = Runtime::Language::ETS;
}

/**
 * @tc.name: Initialize_200
 * @tc.desc: EtsRuntime test for Initialize lang is not ETS.
 * @tc.type: FUNC
 */
HWTEST_F(EtsRuntimeTest, Initialize_200, TestSize.Level1)
{
    Runtime::Options options;
    options.lang = Runtime::Language::ETS;
    options.arkNativeFilePath = "test_app/";
    options.moduleName = "TestModule";
    auto jsRuntime = AbilityRuntime::JsRuntime::Create(options);
    ASSERT_NE(jsRuntime, nullptr);
    std::unique_ptr<ETSRuntime> etsRuntime = std::make_unique<ETSRuntime>();
    ASSERT_NE(etsRuntime, nullptr);
    bool result = etsRuntime->Initialize(options, jsRuntime.get());
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: LoadModule_0100
 * @tc.desc: LoadModule with non-empty hapPath should construct file path directly.
 * @tc.type: FUNC
 */
HWTEST_F(EtsRuntimeTest, LoadModule_0100, TestSize.Level1)
{
    auto etsRuntime = std::make_unique<ETSRuntime>();
    etsRuntime->codePath_ = "/test/code/path";
    std::string moduleName = "abc";
    std::string modulePath = "dir.test.module";
    std::string hapPath = "/some/hap";
    std::string srcEntrance = "main.ets";
    auto result = etsRuntime->LoadModule(moduleName, modulePath, hapPath, false, false, srcEntrance);
    EXPECT_NE(result, nullptr);
}

/**
 * @tc.name: LoadModule_0200
 * @tc.desc: LoadModule trims moduleName containing "::" correctly.
 * @tc.type: FUNC
 */
HWTEST_F(EtsRuntimeTest, LoadModule_0200, TestSize.Level1)
{
    auto etsRuntime = std::make_unique<ETSRuntime>();
    etsRuntime->codePath_ = "/code";
    std::string moduleName = "lib::submod";
    std::string modulePath = "m.js";
    std::string hapPath = "/hap";
    std::string srcEntrance = "main";
    etsRuntime->LoadModule(moduleName, modulePath, hapPath, false, false, srcEntrance);
    EXPECT_EQ(etsRuntime->moduleName_, "lib");
}


/**
 * @tc.name: LoadAbcLinker_0100
 * @tc.desc: LoadAbcLinker returns false when env is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(EtsRuntimeTest, LoadAbcLinker_0100, TestSize.Level0)
{
    ETSRuntime etsRuntime;
    ani_class cls = nullptr;
    ani_object obj = nullptr;
    bool result = etsRuntime.LoadAbcLinker(nullptr, "testModule", cls, obj);
    EXPECT_FALSE(result);
}

/**
 * @tc.name: Deinitialize_100
 * @tc.desc: EtsRuntime test for Deinitialize.
 * @tc.type: FUNC
 */
HWTEST_F(EtsRuntimeTest, Deinitialize_100, TestSize.Level1)
{
    std::unique_ptr<ETSRuntime> etsRuntime = std::make_unique<ETSRuntime>();
    std::shared_ptr<EtsEnv::ETSEnvironment> etsEnv = etsRuntime->etsEnv_;

    etsRuntime->etsEnv_ == nullptr;
    etsRuntime->Deinitialize();
    EXPECT_EQ(etsRuntime->etsEnv_, nullptr);

    etsRuntime->etsEnv_ = std::make_shared<EtsEnv::ETSEnvironment>();
    etsRuntime->Deinitialize();
    EXPECT_NE(etsRuntime->etsEnv_, nullptr);
    etsRuntime->etsEnv_ = etsEnv;
}

/**
 * @tc.name: GetAniEnv_100
 * @tc.desc: EtsRuntime test for GetAniEnv.
 * @tc.type: FUNC
 */
HWTEST_F(EtsRuntimeTest, GetAniEnv_100, TestSize.Level1)
{
    std::unique_ptr<ETSRuntime> etsRuntime = std::make_unique<ETSRuntime>();
    std::shared_ptr<EtsEnv::ETSEnvironment> etsEnv = etsRuntime->etsEnv_;

    etsRuntime->etsEnv_ == nullptr;
    auto env = etsRuntime->GetAniEnv();
    EXPECT_EQ(env, nullptr);

    env = nullptr;
    etsRuntime->etsEnv_ = std::make_shared<EtsEnv::ETSEnvironment>();
    env = etsRuntime->GetAniEnv();
    EXPECT_EQ(env, nullptr);
    etsRuntime->etsEnv_ = etsEnv;
}

/**
 * @tc.name: LoadModule_100
 * @tc.desc: EtsRuntime test for LoadModule.
 * @tc.type: FUNC
 */
HWTEST_F(EtsRuntimeTest, LoadModule_100, TestSize.Level1)
{
    std::unique_ptr<ETSRuntime> etsRuntime = std::make_unique<ETSRuntime>();

    std::string moduleName = TEST_MODULE_NAME;
    moduleName += "::";
    std::string modulePath = TEST_MODULE_PATH;
    std::string hapPath = "";
    bool esmodule = true;
    bool useCommonChunk = false;
    std::string srcEntrance = "";

    auto env = etsRuntime->LoadModule(moduleName, modulePath, hapPath, esmodule, useCommonChunk, srcEntrance);
    EXPECT_EQ(env, nullptr);

    env = nullptr;
    hapPath = TEST_HAP_PATH;
    env = etsRuntime->LoadModule(moduleName, modulePath, hapPath, esmodule, useCommonChunk, srcEntrance);
    EXPECT_NE(env, nullptr);
}

/**
 * @tc.name: LoadEtsModule_100
 * @tc.desc: EtsRuntime test for LoadEtsModule.
 * @tc.type: FUNC
 */
HWTEST_F(EtsRuntimeTest, LoadEtsModule_100, TestSize.Level1)
{
    std::unique_ptr<ETSRuntime> etsRuntime = std::make_unique<ETSRuntime>();

    std::string moduleName = TEST_MODULE_NAME;
    moduleName += "::";
    std::string modulePath = TEST_MODULE_PATH;
    std::string hapPath = "";
    std::string srcEntrance = "";
    auto env = etsRuntime->LoadEtsModule(moduleName, modulePath, hapPath, srcEntrance);
    EXPECT_NE(env, nullptr);
}
} // namespace AbilityRuntime
} // namespace OHOS