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
#include "ani_common_util.h"
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
constexpr int32_t ARGC_ZERO = 0;
}

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
            srcPath.append(args->GetTestRunnerPath());
            moduleName = args->GetTestModuleName();
        }
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
    if (!etsTestRunnerObj_) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "load testrunner failed");
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
        ani_ref funRef;
        ani_status status = ANI_ERROR;
        status = env->Object_GetPropertyByName_Ref(etsTestRunnerObj_->aniObj, "onPrepare", &funRef);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "get onPrepare failed status : %{public}d", status);
            return;
        }
        TAG_LOGI(AAFwkTag::DELEGATOR, "get onPrepare success");
        if (!IsValidProperty(env, funRef)) {
            TAG_LOGI(AAFwkTag::DELEGATOR, "invalid onPrepare property");
            return;
        }

        ani_ref result;
        status = env->FunctionalObject_Call(reinterpret_cast<ani_fn_object>(funRef), ARGC_ZERO, nullptr, &result);
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
        ani_ref funRef;
        ani_status status = ANI_ERROR;
        status = env->Object_GetPropertyByName_Ref(etsTestRunnerObj_->aniObj, "onRun", &funRef);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "get onRun failed status : %{public}d", status);
            return;
        }
        TAG_LOGI(AAFwkTag::DELEGATOR, "get onRun success");
        if (!IsValidProperty(env, funRef)) {
            TAG_LOGI(AAFwkTag::DELEGATOR, "invalid onRun property");
            return;
        }
        ani_boolean errorExists;
        env->ExistUnhandledError(&errorExists);
        
        TAG_LOGE(AAFwkTag::DELEGATOR, "onrun error check : %{public}d", (int)errorExists);
        ani_ref result;
        status = env->FunctionalObject_Call(reinterpret_cast<ani_fn_object>(funRef), ARGC_ZERO, nullptr, &result);
        if (status != ANI_OK) {
            std::ostringstream buffer;
            std::streambuf *oldStderr = std::cerr.rdbuf(buffer.rdbuf());
            ani_status status = env->DescribeError();
            std::cerr.rdbuf(oldStderr);
            std::string output = buffer.str();
            TAG_LOGE(AAFwkTag::DELEGATOR, "onrun error check : %{public}s", output.c_str());
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