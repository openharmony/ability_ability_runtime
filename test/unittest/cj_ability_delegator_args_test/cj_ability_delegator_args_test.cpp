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

#include <string>
#include "gtest/gtest.h"
#include "cj_ability_delegator_args.h"
#include "ability_delegator_registry.h"
#include "cj_application_context.h"
#include "application_context.h"
#include "runner_runtime/cj_test_runner.h"

using namespace testing::ext;
using namespace OHOS::FFI;
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;
using namespace OHOS::RunnerRuntime;

namespace OHOS {
namespace AbilityDelegatorArgsCJ {
namespace {
const int32_t DEFAULT_VALUE = 0;
const int32_t INVALID_ARG = -1;
const std::string KEY_TEST_BUNDLE_NAME = "-p";
const std::string VALUE_TEST_BUNDLE_NAME = "com.example.myapplication";
const std::string KEY_TEST_RUNNER_CLASS = "-s unittest";
const std::string VALUE_TEST_RUNNER_CLASS = "JSUserTestRunner";
const std::string KEY_TEST_CASE = "-s class";
const std::string VALUE_TEST_CASE = "ohos.acts.aafwk.ability.test.ConstructorTest";
const std::string KEY_TEST_WAIT_TIMEOUT = "-w";
const std::string VALUE_TEST_WAIT_TIMEOUT = "50";
const std::string KEY_TEST_DEBUG {"-D"};
const std::string VALUE_TEST_DEBUG {"true"};
}  // namespace

class CjAbilityDelegatorArgsTest : public testing::Test {
public:
    CjAbilityDelegatorArgsTest()
    {}
    ~CjAbilityDelegatorArgsTest()
    {}
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

protected:
    static std::shared_ptr<CJAbilityDelegatorImpl> abilityDelegator_;
    static std::shared_ptr<AbilityDelegatorArgs> abilityDelegatorArgs_;
};

std::shared_ptr<CJAbilityDelegatorImpl> CjAbilityDelegatorArgsTest::abilityDelegator_ = nullptr;
std::shared_ptr<AbilityDelegatorArgs> CjAbilityDelegatorArgsTest::abilityDelegatorArgs_ = nullptr;

void CjAbilityDelegatorArgsTest::SetUpTestCase()
{
    std::map<std::string, std::string> paras;
    paras.emplace(KEY_TEST_CASE, VALUE_TEST_CASE);
    paras.emplace(KEY_TEST_DEBUG, VALUE_TEST_DEBUG);
    paras.emplace(KEY_TEST_BUNDLE_NAME, VALUE_TEST_BUNDLE_NAME);
    paras.emplace(KEY_TEST_RUNNER_CLASS, VALUE_TEST_RUNNER_CLASS);
    paras.emplace(KEY_TEST_WAIT_TIMEOUT, VALUE_TEST_WAIT_TIMEOUT);
    Want want;
    for (auto para : paras) {
        want.SetParam(para.first, para.second);
    }
    abilityDelegatorArgs_ = std::make_shared<AbilityDelegatorArgs>(want);
    AbilityRuntime::Runtime::Options options;
    BundleInfo bundleInfo;
    auto runner = CJTestRunner::Create(AbilityRuntime::Runtime::Create(options), abilityDelegatorArgs_, bundleInfo);
    abilityDelegator_ = std::make_shared<CJAbilityDelegatorImpl>(std::make_shared<AbilityRuntime::ContextImpl>(),
        std::move(runner), nullptr);
}

void CjAbilityDelegatorArgsTest::TearDownTestCase()
{}

void CjAbilityDelegatorArgsTest::SetUp()
{}

void CjAbilityDelegatorArgsTest::TearDown()
{}

/**
 * @tc.name: CjAbilityDelegatorArgsTestFfiAbilityDelegatorRegistryGetArguments_001
 * @tc.desc: CjAbilityDelegatorArgsTest test for FfiAbilityDelegatorRegistryGetArguments.
 * @tc.type: FUNC
 */
HWTEST_F(CjAbilityDelegatorArgsTest,
    CjAbilityDelegatorArgsTestFfiAbilityDelegatorRegistryGetArguments_001, TestSize.Level1)
{
    OHOS::AppExecFwk::AbilityDelegatorRegistry::RegisterInstance(nullptr, nullptr);
    auto result = FfiAbilityDelegatorRegistryGetArguments();
    EXPECT_TRUE(result == INVALID_ARG);
}

/**
 * @tc.name: CjAbilityDelegatorArgsTestFfiAbilityDelegatorRegistryGetArguments_002
 * @tc.desc: CjAbilityDelegatorArgsTest test for FfiAbilityDelegatorRegistryGetArguments.
 * @tc.type: FUNC
 */
HWTEST_F(CjAbilityDelegatorArgsTest,
    CjAbilityDelegatorArgsTestFfiAbilityDelegatorRegistryGetArguments_002, TestSize.Level1)
{
    OHOS::AppExecFwk::AbilityDelegatorRegistry::RegisterInstance(abilityDelegator_, abilityDelegatorArgs_);
    auto result = FfiAbilityDelegatorRegistryGetArguments();
    EXPECT_TRUE(result != INVALID_ARG);
}

/**
 * @tc.name: CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestBundleName_001
 * @tc.desc: CjAbilityDelegatorArgsTest test for FfiAbilityDelegatorArgsGetTestBundleName.
 * @tc.type: FUNC
 */
HWTEST_F(CjAbilityDelegatorArgsTest,
    CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestBundleName_001, TestSize.Level1)
{
    int32_t errCode = DEFAULT_VALUE;
    int64_t id = INVALID_ARG;
    FfiAbilityDelegatorArgsGetTestBundleName(id, &errCode);
    EXPECT_TRUE(errCode == INVALID_ARG);
}

/**
 * @tc.name: CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestBundleName_002
 * @tc.desc: CjAbilityDelegatorArgsTest test for FfiAbilityDelegatorArgsGetTestBundleName.
 * @tc.type: FUNC
 */
HWTEST_F(CjAbilityDelegatorArgsTest,
    CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestBundleName_002, TestSize.Level1)
{
    int32_t errCode = DEFAULT_VALUE;
    int64_t id = FfiAbilityDelegatorRegistryGetArguments();
    FfiAbilityDelegatorArgsGetTestBundleName(id, &errCode);
    EXPECT_TRUE(errCode != INVALID_ARG);
}

/**
 * @tc.name: CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestParam_001
 * @tc.desc: CjAbilityDelegatorArgsTest test for FfiAbilityDelegatorArgsGetTestParam.
 * @tc.type: FUNC
 */
HWTEST_F(CjAbilityDelegatorArgsTest,
    CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestParam_001, TestSize.Level1)
{
    int32_t errCode = DEFAULT_VALUE;
    int64_t id = INVALID_ARG;
    FfiAbilityDelegatorArgsGetTestParam(id, &errCode);
    EXPECT_TRUE(errCode == INVALID_ARG);
}

/**
 * @tc.name: CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestParam_002
 * @tc.desc: CjAbilityDelegatorArgsTest test for FfiAbilityDelegatorArgsGetTestParam.
 * @tc.type: FUNC
 */
HWTEST_F(CjAbilityDelegatorArgsTest,
    CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestParam_002, TestSize.Level1)
{
    int32_t errCode = DEFAULT_VALUE;
    int64_t id = FfiAbilityDelegatorRegistryGetArguments();
    FfiAbilityDelegatorArgsGetTestParam(id, &errCode);
    EXPECT_TRUE(errCode != INVALID_ARG);
}

/**
 * @tc.name: CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestCaseName_001
 * @tc.desc: CjAbilityDelegatorArgsTest test for FfiAbilityDelegatorArgsGetTestCaseName.
 * @tc.type: FUNC
 */
HWTEST_F(CjAbilityDelegatorArgsTest,
    CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestCaseName_001, TestSize.Level1)
{
    int32_t errCode = DEFAULT_VALUE;
    int64_t id = INVALID_ARG;
    FfiAbilityDelegatorArgsGetTestCaseName(id, &errCode);
    EXPECT_TRUE(errCode == INVALID_ARG);
}

/**
 * @tc.name: CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestCaseName_002
 * @tc.desc: CjAbilityDelegatorArgsTest test for FfiAbilityDelegatorArgsGetTestCaseName.
 * @tc.type: FUNC
 */
HWTEST_F(CjAbilityDelegatorArgsTest,
    CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestCaseName_002, TestSize.Level1)
{
    int32_t errCode = DEFAULT_VALUE;
    int64_t id = FfiAbilityDelegatorRegistryGetArguments();
    FfiAbilityDelegatorArgsGetTestCaseName(id, &errCode);
    EXPECT_TRUE(errCode != INVALID_ARG);
}

/**
 * @tc.name: CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestRunnerClassName_001
 * @tc.desc: CjAbilityDelegatorArgsTest test for FfiAbilityDelegatorArgsGetTestRunnerClassName.
 * @tc.type: FUNC
 */
HWTEST_F(CjAbilityDelegatorArgsTest,
    CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestRunnerClassName_001, TestSize.Level1)
{
    int32_t errCode = DEFAULT_VALUE;
    int64_t id = INVALID_ARG;
    FfiAbilityDelegatorArgsGetTestRunnerClassName(id, &errCode);
    EXPECT_TRUE(errCode == INVALID_ARG);
}

/**
 * @tc.name: CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestRunnerClassName_002
 * @tc.desc: CjAbilityDelegatorArgsTest test for FfiAbilityDelegatorArgsGetTestRunnerClassName.
 * @tc.type: FUNC
 */
HWTEST_F(CjAbilityDelegatorArgsTest,
    CjAbilityDelegatorArgsTestFfiAbilityDelegatorArgsGetTestRunnerClassName_002, TestSize.Level1)
{
    int32_t errCode = DEFAULT_VALUE;
    int64_t id = FfiAbilityDelegatorRegistryGetArguments();
    FfiAbilityDelegatorArgsGetTestRunnerClassName(id, &errCode);
    EXPECT_TRUE(errCode != INVALID_ARG);
}

}  // namespace AbilityDelegatorArgsCJ
}  // namespace OHOS
