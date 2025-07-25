/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "ability_delegator_registry.h"
#include "ability_runtime/context/context_impl.h"
#include "app_loader.h"
#include "hilog_tag_wrapper.h"
#include "mock_ability_delegator_stub.h"
#include "ohos_application.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AAFwk;

namespace {
const std::string KEY_TEST_BUNDLE_NAME = "-p";
const std::string VALUE_TEST_BUNDLE_NAME = "com.example.myapplicationmodule";
const std::string KEY_TEST_RUNNER_CLASS = "-s unittest";
const std::string VALUE_TEST_RUNNER_CLASS = "JSUserTestRunnermodule";
const std::string KEY_TEST_CASE = "-s class";
const std::string VALUE_TEST_CASE =
    "ohos.acts.aafwk.ability.test.ConstructorTest#testDataAbilityOtherFunction0010_module";
const std::string KEY_TEST_WAIT_TIMEOUT = "-w";
const std::string VALUE_TEST_WAIT_TIMEOUT = "160";
}

class AbilityDelegatorRegistryModuleTest : public ::testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void AbilityDelegatorRegistryModuleTest::SetUpTestCase()
{}

void AbilityDelegatorRegistryModuleTest::TearDownTestCase()
{}

void AbilityDelegatorRegistryModuleTest::SetUp()
{}

void AbilityDelegatorRegistryModuleTest::TearDown()
{}

/**
 * @tc.number: Ability_Delegator_Registry_Module_Test_0100
 * @tc.name: RegisterInstance and GetAbilityDelegator and GetArguments
 * @tc.desc: Verify the RegisterInstance and GetAbilityDelegator and GetArguments.
 */
HWTEST_F(AbilityDelegatorRegistryModuleTest,
    Ability_Delegator_Registry_Module_Test_0100, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "Ability_Delegator_Registry_Module_Test_0100 is called");

    std::map<std::string, std::string> paras;
    paras.emplace(KEY_TEST_BUNDLE_NAME, VALUE_TEST_BUNDLE_NAME);
    paras.emplace(KEY_TEST_RUNNER_CLASS, VALUE_TEST_RUNNER_CLASS);
    paras.emplace(KEY_TEST_CASE, VALUE_TEST_CASE);
    paras.emplace(KEY_TEST_WAIT_TIMEOUT, VALUE_TEST_WAIT_TIMEOUT);

    Want want;
    for (auto para : paras) {
        want.SetParam(para.first, para.second);
    }
    std::shared_ptr<AbilityDelegatorArgs> abilityArgs = std::make_shared<AbilityDelegatorArgs>(want);
    std::unique_ptr<TestRunner> testRunner = TestRunner::Create(
        std::shared_ptr<OHOSApplication>(ApplicationLoader::GetInstance().GetApplicationByName())->GetRuntime(),
        abilityArgs,
        true);
    std::shared_ptr<AbilityDelegator> abilityDelegator =
        std::make_shared<AbilityDelegator>(nullptr, std::move(testRunner), nullptr);
    AbilityDelegatorRegistry::RegisterInstance(abilityDelegator, abilityArgs,
        OHOS::AbilityRuntime::Runtime::Language::JS);

    EXPECT_EQ(AbilityDelegatorRegistry::GetAbilityDelegator(OHOS::AbilityRuntime::Runtime::Language::JS),
        abilityDelegator);
    EXPECT_EQ(AbilityDelegatorRegistry::GetArguments(), abilityArgs);
}

/**
 * @tc.number: Ability_Delegator_Registry_Module_Test_0200
 * @tc.name: RegisterInstance and GetAbilityDelegator and GetArguments
 * @tc.desc: Verify the RegisterInstance and GetAbilityDelegator and GetArguments.
 */
HWTEST_F(AbilityDelegatorRegistryModuleTest,
    Ability_Delegator_Registry_Module_Test_0200, Function | MediumTest | Level1)
{
    TAG_LOGI(AAFwkTag::TEST, "Ability_Delegator_Registry_Module_Test_0200 is called");

    std::map<std::string, std::string> paras;
    paras.emplace(KEY_TEST_BUNDLE_NAME, VALUE_TEST_BUNDLE_NAME);
    paras.emplace(KEY_TEST_RUNNER_CLASS, VALUE_TEST_RUNNER_CLASS);
    paras.emplace(KEY_TEST_CASE, VALUE_TEST_CASE);
    paras.emplace(KEY_TEST_WAIT_TIMEOUT, VALUE_TEST_WAIT_TIMEOUT);

    Want want;
    for (auto para : paras) {
        want.SetParam(para.first, para.second);
    }
    std::shared_ptr<AbilityDelegatorArgs> abilityArgs = std::make_shared<AbilityDelegatorArgs>(want);
    std::unique_ptr<TestRunner> testRunner = TestRunner::Create(
        std::shared_ptr<OHOSApplication>(ApplicationLoader::GetInstance().GetApplicationByName())->GetRuntime(),
        abilityArgs,
        true);
    std::shared_ptr<AbilityDelegator> abilityDelegator =
        std::make_shared<AbilityDelegator>(nullptr, std::move(testRunner), nullptr);
    AbilityDelegatorRegistry::RegisterInstance(abilityDelegator, abilityArgs,
        OHOS::AbilityRuntime::Runtime::Language::ETS);

    EXPECT_EQ(AbilityDelegatorRegistry::GetAbilityDelegator(OHOS::AbilityRuntime::Runtime::Language::ETS),
        abilityDelegator);
    EXPECT_EQ(AbilityDelegatorRegistry::GetArguments(), abilityArgs);
}
