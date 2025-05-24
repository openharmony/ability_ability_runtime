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
#include "sts_environment.h"
#include "sts_runtime.h"
#undef private
#undef protected
#include "hilog_tag_wrapper.h"
#include "js_runtime.h"
#include "ohos_sts_environment_impl.h"
#include "runtime.h"
#include "sts_environment.h"

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

class StsRuntimeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    Runtime::Options options_;
};

void StsRuntimeTest::SetUpTestCase() {}

void StsRuntimeTest::TearDownTestCase() {}

void StsRuntimeTest::SetUp()
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

void StsRuntimeTest::TearDown() {}

/**
 * @tc.name: Create_100
 * @tc.desc: StsRuntime test for Create Initialize failed.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, Create_100, TestSize.Level1)
{
    options_.lang = Runtime::Language::JS;
    options_.preload = true;
    options_.isStageModel = false;
    auto jsRuntime = JsRuntime::Create(options_);
    auto stsRuntime = STSRuntime::Create(options_, jsRuntime.get());
    EXPECT_EQ(stsRuntime, nullptr);
    options_.lang = Runtime::Language::STS;
    options_.preload = false;
    options_.isStageModel = true;
}

/**
 * @tc.name: SetAppLibPath_100
 * @tc.desc: StsRuntime test for SetAppLibPath.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, SetAppLibPath_100, TestSize.Level1)
{
    std::map<std::string, std::vector<std::string>> testPathMap;
    testPathMap["com.example.app"] = { "/data/abc", "/data/def" };
    testPathMap["com.example.demo"] = { "/data/demo/es", "/data/demo/ts" };
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    stsRuntime->SetAppLibPath(testPathMap);
    EXPECT_NE(testPathMap.size(), 0);
}

/**
 * @tc.name: Initialize_100
 * @tc.desc: StsRuntime test for Initialize lang is not STS.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, Initialize_100, TestSize.Level1)
{
    options_.lang = Runtime::Language::JS;
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    bool result = stsRuntime->Initialize(options_);
    EXPECT_EQ(result, false);
    options_.lang = Runtime::Language::STS;
}

/**
 * @tc.name: Initialize_200
 * @tc.desc: StsRuntime test for Initialize lang is not STS.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, Initialize_200, TestSize.Level1)
{
    options_.lang = Runtime::Language::JS;
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    bool result = stsRuntime->Initialize(options_);
    EXPECT_EQ(result, false);
    options_.lang = Runtime::Language::STS;
}

/**
 * @tc.name: LoadSTSAppLibrary_100
 * @tc.desc: StsRuntime test for LoadSTSAppLibrary successful.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, LoadSTSAppLibrary_100, TestSize.Level1)
{
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    std::vector<std::string> appLibPaths = {};
    std::shared_ptr<StsEnv::STSEnvironment> stsEnv = stsRuntime->stsEnv_;

    stsRuntime->stsEnv_ == nullptr;
    bool result = stsRuntime->LoadSTSAppLibrary(appLibPaths);
    EXPECT_EQ(result, false);

    result = false;
    stsRuntime->stsEnv_ =
        std::make_shared<StsEnv::STSEnvironment>(std::make_unique<OHOSStsEnvironmentImpl>(options_.eventRunner));
    result = stsRuntime->LoadSTSAppLibrary(appLibPaths);
    EXPECT_EQ(result, true);
    stsRuntime->stsEnv_ = stsEnv;
}

/**
 * @tc.name: StartDebugger_100
 * @tc.desc: StsRuntime test for StartDebugger.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, StartDebugger_100, TestSize.Level1)
{
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    std::shared_ptr<StsEnv::STSEnvironment> stsEnv = stsRuntime->stsEnv_;

    stsRuntime->stsEnv_ == nullptr;
    bool result = stsRuntime->StartDebugger();
    EXPECT_EQ(result, false);

    result = false;
    stsRuntime->stsEnv_ =
        std::make_shared<StsEnv::STSEnvironment>(std::make_unique<OHOSStsEnvironmentImpl>(options_.eventRunner));
    result = stsRuntime->StartDebugger();
    EXPECT_EQ(result, true);
    stsRuntime->stsEnv_ = stsEnv;
}

/**
 * @tc.name: PostTask_100
 * @tc.desc: StsRuntime test for PostTask.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, PostTask_100, TestSize.Level1)
{
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    std::shared_ptr<StsEnv::STSEnvironment> stsEnv = stsRuntime->stsEnv_;

    std::string taskName = "syncTask001";
    bool taskExecuted = false;
    auto task = [taskName, &taskExecuted]() {
        TAG_LOGI(AAFwkTag::TEST, "%{public}s called.", taskName.c_str());
        taskExecuted = true;
    };
    std::string name = "postTask001";
    int64_t delayTime = 10;

    stsRuntime->stsEnv_ == nullptr;
    stsRuntime->PostTask(task, name, delayTime);
    EXPECT_EQ(stsRuntime->stsEnv_, nullptr);

    stsRuntime->stsEnv_ =
        std::make_shared<StsEnv::STSEnvironment>(std::make_unique<OHOSStsEnvironmentImpl>(options_.eventRunner));
    stsRuntime->PostTask(task, name, delayTime);
    EXPECT_NE(stsRuntime->stsEnv_, nullptr);
    stsRuntime->stsEnv_ = stsEnv;
}

/**
 * @tc.name: PostSyncTask_100
 * @tc.desc: StsRuntime test for PostSyncTask.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, PostSyncTask_100, TestSize.Level1)
{
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    std::shared_ptr<StsEnv::STSEnvironment> stsEnv = stsRuntime->stsEnv_;

    std::string taskName = "syncTask001";
    bool taskExecuted = false;
    auto task = [taskName, &taskExecuted]() {
        TAG_LOGI(AAFwkTag::TEST, "%{public}s called.", taskName.c_str());
        taskExecuted = true;
    };
    std::string name = "postTask001";

    stsRuntime->stsEnv_ == nullptr;
    stsRuntime->PostSyncTask(task, name);
    EXPECT_EQ(taskExecuted, false);

    stsRuntime->stsEnv_ =
        std::make_shared<StsEnv::STSEnvironment>(std::make_unique<OHOSStsEnvironmentImpl>(options_.eventRunner));
    stsRuntime->PostSyncTask(task, name);
    EXPECT_EQ(taskExecuted, true);
    stsRuntime->stsEnv_ = stsEnv;
}

/**
 * @tc.name: RemoveTask_100
 * @tc.desc: StsRuntime test for RemoveTask.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, RemoveTask_100, TestSize.Level1)
{
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    std::shared_ptr<StsEnv::STSEnvironment> stsEnv = stsRuntime->stsEnv_;

    std::string name = "postTask001";

    stsRuntime->stsEnv_ == nullptr;
    stsRuntime->RemoveTask(name);
    EXPECT_EQ(stsRuntime->stsEnv_, nullptr);

    stsRuntime->stsEnv_ =
        std::make_shared<StsEnv::STSEnvironment>(std::make_unique<OHOSStsEnvironmentImpl>(options_.eventRunner));
    stsRuntime->RemoveTask(name);
    EXPECT_NE(stsRuntime->stsEnv_, nullptr);
    stsRuntime->stsEnv_ = stsEnv;
}

/**
 * @tc.name: Deinitialize_100
 * @tc.desc: StsRuntime test for Deinitialize.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, Deinitialize_100, TestSize.Level1)
{
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    std::shared_ptr<StsEnv::STSEnvironment> stsEnv = stsRuntime->stsEnv_;

    stsRuntime->stsEnv_ == nullptr;
    stsRuntime->Deinitialize();
    EXPECT_EQ(stsRuntime->stsEnv_, nullptr);

    stsRuntime->stsEnv_ =
        std::make_shared<StsEnv::STSEnvironment>(std::make_unique<OHOSStsEnvironmentImpl>(options_.eventRunner));
    stsRuntime->Deinitialize();
    EXPECT_NE(stsRuntime->stsEnv_, nullptr);
    stsRuntime->stsEnv_ = stsEnv;
}

/**
 * @tc.name: PreloadAce_100
 * @tc.desc: StsRuntime test for PreloadAce.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, PreloadAce_100, TestSize.Level1)
{
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    Runtime::Options options;
    options.loadAce = true;
    options.isUnique = true;
    stsRuntime->PreloadAce(options);
    EXPECT_EQ(options.isUnique, true);

    options.isUnique = false;
    stsRuntime->PreloadAce(options);
    EXPECT_EQ(options.isUnique, false);
}

/**
 * @tc.name: ReInitStsEnvImpl_100
 * @tc.desc: StsRuntime test for ReInitStsEnvImpl.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, ReInitStsEnvImpl_100, TestSize.Level1)
{
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    std::shared_ptr<StsEnv::STSEnvironment> stsEnv = stsRuntime->stsEnv_;

    stsRuntime->stsEnv_ == nullptr;
    stsRuntime->ReInitStsEnvImpl(options_);
    EXPECT_EQ(stsRuntime->stsEnv_, nullptr);

    stsRuntime->stsEnv_ =
        std::make_shared<StsEnv::STSEnvironment>(std::make_unique<OHOSStsEnvironmentImpl>(options_.eventRunner));
    stsRuntime->ReInitStsEnvImpl(options_);
    EXPECT_NE(stsRuntime->stsEnv_, nullptr);
    stsRuntime->stsEnv_ = stsEnv;
}

/**
 * @tc.name: LoadAotFile_100
 * @tc.desc: StsRuntime test for LoadAotFile.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, LoadAotFile_100, TestSize.Level1)
{
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    Runtime::Options options;
    options.hapPath = "";
    stsRuntime->LoadAotFile(options_);
    EXPECT_EQ(options.hapPath.empty(), true);

    options.hapPath = "test.hap";
    stsRuntime->LoadAotFile(options_);
    EXPECT_NE(options.hapPath.empty(), true);
}

/**
 * @tc.name: ReInitUVLoop_100
 * @tc.desc: StsRuntime test for ReInitUVLoop.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, ReInitUVLoop_100, TestSize.Level1)
{
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    std::shared_ptr<StsEnv::STSEnvironment> stsEnv = stsRuntime->stsEnv_;

    stsRuntime->stsEnv_ == nullptr;
    stsRuntime->ReInitUVLoop();
    EXPECT_EQ(stsRuntime->stsEnv_, nullptr);

    stsRuntime->stsEnv_ =
        std::make_shared<StsEnv::STSEnvironment>(std::make_unique<OHOSStsEnvironmentImpl>(options_.eventRunner));
    stsRuntime->ReInitUVLoop();
    EXPECT_NE(stsRuntime->stsEnv_, nullptr);
    stsRuntime->stsEnv_ = stsEnv;
}

/**
 * @tc.name: GetAniEnv_100
 * @tc.desc: StsRuntime test for GetAniEnv.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, GetAniEnv_100, TestSize.Level1)
{
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    std::shared_ptr<StsEnv::STSEnvironment> stsEnv = stsRuntime->stsEnv_;

    stsRuntime->stsEnv_ == nullptr;
    auto env = stsRuntime->GetAniEnv();
    EXPECT_EQ(env, nullptr);

    env = nullptr;
    stsRuntime->stsEnv_ =
        std::make_shared<StsEnv::STSEnvironment>(std::make_unique<OHOSStsEnvironmentImpl>(options_.eventRunner));
    env = stsRuntime->GetAniEnv();
    EXPECT_EQ(env, nullptr);
    stsRuntime->stsEnv_ = stsEnv;
}

/**
 * @tc.name: LoadModule_100
 * @tc.desc: StsRuntime test for LoadModule.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, LoadModule_100, TestSize.Level1)
{
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();

    std::string moduleName = TEST_MODULE_NAME;
    moduleName += "::";
    std::string modulePath = TEST_MODULE_PATH;
    std::string hapPath = "";
    bool esmodule = true;
    bool useCommonChunk = false;
    std::string srcEntrance = "";

    auto env = stsRuntime->LoadModule(moduleName, modulePath, hapPath, esmodule, useCommonChunk, srcEntrance);
    EXPECT_EQ(env, nullptr);

    env = nullptr;
    hapPath = TEST_HAP_PATH;
    env = stsRuntime->LoadModule(moduleName, modulePath, hapPath, esmodule, useCommonChunk, srcEntrance);
    EXPECT_NE(env, nullptr);
}

/**
 * @tc.name: LoadStsModule_100
 * @tc.desc: StsRuntime test for LoadStsModule.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, LoadStsModule_100, TestSize.Level1)
{
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();

    std::string moduleName = TEST_MODULE_NAME;
    moduleName += "::";
    std::string modulePath = TEST_MODULE_PATH;
    std::string hapPath = "";
    bool esmodule = true;
    bool useCommonChunk = true;
    std::string srcEntrance = "";
    auto env = stsRuntime->LoadModule(moduleName, modulePath, hapPath, esmodule, useCommonChunk, srcEntrance);
    EXPECT_EQ(env, nullptr);
}

/**
 * @tc.name: RunScript_100
 * @tc.desc: StsRuntime test for RunScript.
 * @tc.type: FUNC
 */
HWTEST_F(StsRuntimeTest, RunScript_100, TestSize.Level1)
{
    std::unique_ptr<STSRuntime> stsRuntime = std::make_unique<STSRuntime>();
    ani_env* aniEnv = nullptr;
    std::string moduleName = "";
    std::string abcPath = "";
    std::string hapPath = "test.hap";
    std::string srcEntrance = "";
    bool result = stsRuntime->RunScript(aniEnv, moduleName, abcPath, hapPath, srcEntrance);
    EXPECT_EQ(result, true);
}
} // namespace AbilityRuntime
} // namespace OHOS