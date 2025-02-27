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

#include <regex>

#include "ability_delegator_registry.h"
#include "hilog_tag_wrapper.h"
#include "runner_runtime/sts_test_runner.h"

namespace OHOS {
namespace RunnerRuntime {
namespace {
const std::string CAPITALTESTRUNNER = "/ets/TestRunner/";
const std::string LOWERCASETESTRUNNER = "/ets/testrunner/";
}  // namespace

std::unique_ptr<TestRunner> STSTestRunner::Create(const std::unique_ptr<Runtime> &runtime,
    const std::shared_ptr<AbilityDelegatorArgs> &args, const AppExecFwk::BundleInfo &bundleInfo)
{
    if (!runtime) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid runtime");
        return nullptr;
    }

    if (!args) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid args");
        return nullptr;
    }

    auto pTestRunner = new (std::nothrow) STSTestRunner(static_cast<STSRuntime &>(*runtime), args, bundleInfo);
    if (!pTestRunner) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null testRunner");
        return nullptr;
    }

    return std::unique_ptr<STSTestRunner>(pTestRunner);
}

STSTestRunner::STSTestRunner(
    STSRuntime &stsRuntime, const std::shared_ptr<AbilityDelegatorArgs> &args, const AppExecFwk::BundleInfo &bundleInfo)
    : stsRuntime_(stsRuntime)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "Enter");
    // TODO need review & test
    // std::string moduleName;
    // if (args) {
    //     std::string srcPath;
    //     if (bundleInfo.hapModuleInfos.back().isModuleJson) {
    //         srcPath.append(args->GetTestModuleName());
    //         if (args->GetTestRunnerClassName().find("/") == std::string::npos) {
    //             srcPath.append(LOWERCASETESTRUNNER);
    //         }
    //         moduleName = args->GetTestModuleName();
    //     } else {
    //         srcPath.append(args->GetTestPackageName());
    //         srcPath.append("/assets/sts/TestRunner/");
    //         moduleName = args->GetTestPackageName();
    //     }
    //     srcPath.append(args->GetTestRunnerClassName());
    //     srcPath.append(".abc");
    //     srcPath_ = srcPath;
    // }
    // TAG_LOGD(AAFwkTag::DELEGATOR, "srcPath: %{public}s", srcPath_.c_str());

    // if (!moduleName.empty()) {
    //     for (auto hapModuleInfo : bundleInfo.hapModuleInfos) {
    //         if ((hapModuleInfo.isModuleJson && hapModuleInfo.name == moduleName) ||
    //             hapModuleInfo.package == moduleName) {
    //             hapPath_ = hapModuleInfo.hapPath;
    //             break;
    //         }
    //     }
    // } else {
    //     hapPath_ = bundleInfo.hapModuleInfos.back().hapPath;
    // }
    // AppExecFwk::HapModuleInfo entryHapModuleInfo;
    // if (!bundleInfo.hapModuleInfos.empty()) {
    //     for (auto hapModuleInfo : bundleInfo.hapModuleInfos) {
    //         if (hapModuleInfo.moduleType == AppExecFwk::ModuleType::ENTRY) {
    //             entryHapModuleInfo = hapModuleInfo;
    //             break;
    //         }
    //     }
    // }
    // TAG_LOGD(AAFwkTag::DELEGATOR, "hapPath: %{public}s", hapPath_.c_str());
    // moduleName.append("::").append("TestRunner");
    // stsTestRunnerObj_ = stsRuntime_.LoadModule(moduleName, srcPath_, hapPath_,
    //     bundleInfo.hapModuleInfos.back().compileMode == AppExecFwk::CompileMode::ES_MODULE, false, entryHapModuleInfo.srcEntrance);
    // if (!stsTestRunnerObj_ && srcPath_.find(LOWERCASETESTRUNNER) != std::string::npos) {
    //     TAG_LOGI(AAFwkTag::DELEGATOR, "not found %{public}s , retry load capital address", srcPath_.c_str());
    //     std::regex src_pattern(LOWERCASETESTRUNNER);
    //     srcPath_ = std::regex_replace(srcPath_, src_pattern, CAPITALTESTRUNNER);
    //     TAG_LOGD(AAFwkTag::DELEGATOR, "capital address is %{public}s", srcPath_.c_str());
    //     stsTestRunnerObj_ = stsRuntime_.LoadModule(moduleName, srcPath_, hapPath_,
    //         bundleInfo.hapModuleInfos.back().compileMode == AppExecFwk::CompileMode::ES_MODULE, false, entryHapModuleInfo.srcEntrance);
    // }
}

STSTestRunner::~STSTestRunner() = default;

bool STSTestRunner::Initialize()
{
    return true;
}

void STSTestRunner::Prepare()
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "Enter");
}

void STSTestRunner::Run()
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "Enter");
}
}  // namespace RunnerRuntime
}  // namespace OHOS
