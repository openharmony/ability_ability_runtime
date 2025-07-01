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
#include "runner_runtime/ets_test_runner.h"

#ifdef WINDOWS_PLATFORM
#define ETS_EXPORT __declspec(dllexport)
#else
#define ETS_EXPORT __attribute__((visibility("default")))
#endif

namespace OHOS {
namespace RunnerRuntime {
namespace {
const std::string CAPITALTESTRUNNER = "/ets/TestRunner/";
const std::string LOWERCASETESTRUNNER = "/ets/testrunner/";
} // namespace

TestRunner *ETSTestRunner::Create(const std::unique_ptr<Runtime> &runtime,
    const std::shared_ptr<AbilityDelegatorArgs> &args, const AppExecFwk::BundleInfo &bundleInfo)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "ETSTestRunner Create");
    if (!runtime) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid runtime");
        return nullptr;
    }

    if (!args) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "invalid args");
        return nullptr;
    }

    auto pTestRunner = new (std::nothrow) ETSTestRunner(static_cast<ETSRuntime &>(*runtime), args, bundleInfo);
    if (!pTestRunner) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "null testRunner");
        return nullptr;
    }

    return pTestRunner;
}

ETSTestRunner::ETSTestRunner(
    ETSRuntime &etsRuntime, const std::shared_ptr<AbilityDelegatorArgs> &args, const AppExecFwk::BundleInfo &bundleInfo)
    : etsRuntime_(etsRuntime)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "ETSTestRunner constructor");
    std::string moduleName;
    if (args) {
        std::string srcPath;
        if (bundleInfo.hapModuleInfos.back().isModuleJson) {
            srcPath.append(args->GetTestModuleName());
            if (args->GetTestRunnerClassName().find("/") == std::string::npos) {
                srcPath.append(LOWERCASETESTRUNNER);
            }
            moduleName = args->GetTestModuleName();
        } else {
            srcPath.append(args->GetTestPackageName());
            srcPath.append("/assets/sts/TestRunner/");
            moduleName = args->GetTestPackageName();
        }
        srcPath.append(args->GetTestRunnerClassName());
        srcPath.append(".abc");
        srcPath_ = srcPath;
    }
    TAG_LOGI(AAFwkTag::DELEGATOR, "srcPath: %{public}s", srcPath_.c_str());

    if (!moduleName.empty()) {
        for (auto hapModuleInfo : bundleInfo.hapModuleInfos) {
            if ((hapModuleInfo.isModuleJson && hapModuleInfo.name == moduleName) ||
                hapModuleInfo.package == moduleName) {
                hapPath_ = hapModuleInfo.hapPath;
                break;
            }
        }
    } else {
        hapPath_ = bundleInfo.hapModuleInfos.back().hapPath;
    }
    AppExecFwk::HapModuleInfo entryHapModuleInfo;
    if (!bundleInfo.hapModuleInfos.empty()) {
        for (auto hapModuleInfo : bundleInfo.hapModuleInfos) {
            if (hapModuleInfo.moduleType == AppExecFwk::ModuleType::ENTRY) {
                entryHapModuleInfo = hapModuleInfo;
                break;
            }
        }
    }
    TAG_LOGI(AAFwkTag::DELEGATOR, "hapPath: %{public}s", hapPath_.c_str());
    moduleName.append("::").append("TestRunner");
    etsTestRunnerObj_ = etsRuntime_.LoadModule(moduleName, srcPath_, hapPath_,
        bundleInfo.hapModuleInfos.back().compileMode == AppExecFwk::CompileMode::ES_MODULE,
        false, srcPath_);
    if (!etsTestRunnerObj_ && srcPath_.find(LOWERCASETESTRUNNER) != std::string::npos) {
        TAG_LOGI(AAFwkTag::DELEGATOR, "not found %{public}s , retry load capital address", srcPath_.c_str());
        std::regex src_pattern(LOWERCASETESTRUNNER);
        srcPath_ = std::regex_replace(srcPath_, src_pattern, CAPITALTESTRUNNER);
        TAG_LOGI(AAFwkTag::DELEGATOR, "capital address is %{public}s", srcPath_.c_str());
        etsTestRunnerObj_ = etsRuntime_.LoadModule(moduleName, srcPath_, hapPath_,
            bundleInfo.hapModuleInfos.back().compileMode == AppExecFwk::CompileMode::ES_MODULE,
            false, srcPath_);
    }
}

ETSTestRunner::~ETSTestRunner() = default;

void ETSTestRunner::Prepare()
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "ETSTestRunner Prepare");
    if (etsTestRunnerObj_ != nullptr) {
        TAG_LOGI(AAFwkTag::DELEGATOR, "use etsTestRunnerObj_");
        auto env = etsRuntime_.GetAniEnv();
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "null env");
            return;
        }
        if (env->ResetError() != ANI_OK) {
            TAG_LOGE(AAFwkTag::ETSRUNTIME, "ResetError failed");
        }
        ani_method method;
        ani_status status = ANI_ERROR;
        status = env->Class_FindMethod(etsTestRunnerObj_->aniCls, "onPrepare", ":V", &method);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "get onPrepare failed status : %{public}d", status);
            return;
        }
        TAG_LOGI(AAFwkTag::DELEGATOR, "get onPrepare success");

        ani_int result;
        status = env->Object_CallMethod_Void(etsTestRunnerObj_->aniObj, method, &result);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void onPrepare failed status : %{public}d", status);
        } else {
            TAG_LOGI(AAFwkTag::DELEGATOR, "Object_CallMethod_Void onPrepare success");
        }
    }
}

void ETSTestRunner::Run()
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "ETSTestRunner Run");
    if (etsTestRunnerObj_ != nullptr) {
        TAG_LOGI(AAFwkTag::DELEGATOR, "use etsTestRunnerObj_");
        auto env = etsRuntime_.GetAniEnv();
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "null env");
            return;
        }
        if (env->ResetError() != ANI_OK) {
            TAG_LOGE(AAFwkTag::ETSRUNTIME, "ResetError failed");
        }
        ani_method method;
        ani_status status = ANI_ERROR;
        status = env->Class_FindMethod(etsTestRunnerObj_->aniCls, "onRun", ":V", &method);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "get onRun failed status : %{public}d", status);
            return;
        }
        TAG_LOGI(AAFwkTag::DELEGATOR, "get onRun success");

        ani_int result;
        status = env->Object_CallMethod_Void(etsTestRunnerObj_->aniObj, method, &result);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void onRun failed status : %{public}d", status);
        } else {
            TAG_LOGI(AAFwkTag::DELEGATOR, "Object_CallMethod_Void onRun success");
        }
    }
}
} // namespace RunnerRuntime
} // namespace OHOS

ETS_EXPORT extern "C" OHOS::AppExecFwk::TestRunner *OHOS_ETS_Test_Runner_Create(
    const std::unique_ptr<OHOS::AbilityRuntime::Runtime> &runtime,
    const std::shared_ptr<OHOS::AppExecFwk::AbilityDelegatorArgs> &args,
    const OHOS::AppExecFwk::BundleInfo &bundleInfo)
{
    return OHOS::RunnerRuntime::ETSTestRunner::Create(runtime, args, bundleInfo);
}