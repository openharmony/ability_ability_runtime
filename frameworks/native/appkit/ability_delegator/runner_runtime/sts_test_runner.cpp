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
// TODO: for test, cause namespace don't support static loadlibrary
#include "sts_ability_delegator_registry.h"

namespace OHOS {
namespace RunnerRuntime {
namespace {
const std::string CAPITALTESTRUNNER = "/ets/TestRunner/";
const std::string LOWERCASETESTRUNNER = "/ets/testrunner/";
}  // namespace

std::unique_ptr<TestRunner> STSTestRunner::Create(const std::unique_ptr<Runtime> &runtime,
    const std::shared_ptr<AbilityDelegatorArgs> &args, const AppExecFwk::BundleInfo &bundleInfo)
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "STSTestRunner Create");
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
    TAG_LOGI(AAFwkTag::DELEGATOR, "STSTestRunner constructor");
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
    stsTestRunnerObj_ = stsRuntime_.LoadModule(moduleName, srcPath_, hapPath_,
        bundleInfo.hapModuleInfos.back().compileMode == AppExecFwk::CompileMode::ES_MODULE,
        false, entryHapModuleInfo.srcEntrance);
    if (!stsTestRunnerObj_ && srcPath_.find(LOWERCASETESTRUNNER) != std::string::npos) {
        TAG_LOGI(AAFwkTag::DELEGATOR, "not found %{public}s , retry load capital address", srcPath_.c_str());
        std::regex src_pattern(LOWERCASETESTRUNNER);
        srcPath_ = std::regex_replace(srcPath_, src_pattern, CAPITALTESTRUNNER);
        TAG_LOGI(AAFwkTag::DELEGATOR, "capital address is %{public}s", srcPath_.c_str());
        stsTestRunnerObj_ = stsRuntime_.LoadModule(moduleName, srcPath_, hapPath_,
            bundleInfo.hapModuleInfos.back().compileMode == AppExecFwk::CompileMode::ES_MODULE,
            false, entryHapModuleInfo.srcEntrance);
    }

    // TODO: for test, cause namespace don't support static loadlibrary
    auto aniEnv = stsRuntime_.GetAniEnv();
    AbilityDelegatorSts::StsAbilityDelegatorRegistryInit(aniEnv);
}

STSTestRunner::~STSTestRunner() = default;

bool STSTestRunner::Initialize()
{
    return true;
}

void STSTestRunner::CallOnPrepareMethod(ani_env* aniEnv)
{
    if (aniEnv->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "ResetError failed");
    }

    TAG_LOGI(AAFwkTag::DELEGATOR, "get testrunner");
    // find testRunner class
    ani_class testRunner = nullptr;
    ani_status status = ANI_ERROR;
    status = aniEnv->FindClass("L@test/OHTestRunner;", &testRunner);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "find OHTestRunner failed status : %{public}d", status);
        return;
    }

    // find the target ctor method
    TAG_LOGI(AAFwkTag::DELEGATOR, "find OHTestRunner success");
    ani_method method = nullptr;
    status = aniEnv->Class_FindMethod(testRunner, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod ctor failed status : %{public}d", status);
        return;
    }

    // new a object
    TAG_LOGI(AAFwkTag::DELEGATOR, "Class_FindMethod ctor success");
    ani_object object = nullptr;
    status = aniEnv->Object_New(testRunner, method, &object);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_New failed status : %{public}d", status);
        return;
    }

    // find and call the method
    TAG_LOGI(AAFwkTag::DELEGATOR, "Object_New success");
    ani_method onPrepareMethod = nullptr;
    status = aniEnv->Class_FindMethod(testRunner, "onPrepare", ":V", &onPrepareMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "get onPrepare failed status : %{public}d", status);
        return;
    }

    TAG_LOGI(AAFwkTag::DELEGATOR, "get onPrepare success");
    ani_int result;
    status = aniEnv->Object_CallMethod_Void(object, onPrepareMethod, &result);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void failed status : %{public}d", status);
        return;
    }

    TAG_LOGI(AAFwkTag::DELEGATOR, "Object_CallMethod_Void success");
}

void STSTestRunner::CallOnRunMethod(ani_env* aniEnv)
{
    if (aniEnv->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "ResetError failed");
    }

    TAG_LOGI(AAFwkTag::DELEGATOR, "get testrunner");
    // find testRunner class
    ani_class testRunner = nullptr;
    ani_status status = ANI_ERROR;
    status = aniEnv->FindClass("L@test/OHTestRunner;", &testRunner);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "find OHTestRunner failed status : %{public}d", status);
        return;
    }

    // find the target ctor method
    TAG_LOGI(AAFwkTag::DELEGATOR, "find OHTestRunner success");
    ani_method method = nullptr;
    status = aniEnv->Class_FindMethod(testRunner, "<ctor>", ":V", &method);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Class_FindMethod ctor failed status : %{public}d", status);
        return;
    }

    // new a object
    TAG_LOGI(AAFwkTag::DELEGATOR, "Class_FindMethod ctor success");
    ani_object object = nullptr;
    status = aniEnv->Object_New(testRunner, method, &object);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_New failed status : %{public}d", status);
        return;
    }

    // find and call the method
    TAG_LOGI(AAFwkTag::DELEGATOR, "Object_New success");
    ani_method onRunMethod = nullptr;
    status = aniEnv->Class_FindMethod(testRunner, "onRun", ":V", &onRunMethod);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "get onRun failed status : %{public}d", status);
        return;
    }

    TAG_LOGI(AAFwkTag::DELEGATOR, "get onRun success");
    ani_int result;
    status = aniEnv->Object_CallMethod_Void(object, onRunMethod, &result);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void failed status : %{public}d", status);
        return;
    }

    TAG_LOGI(AAFwkTag::DELEGATOR, "Object_CallMethod_Void success");
}

void STSTestRunner::Prepare()
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "STSTestRunner Prepare");
    if (stsTestRunnerObj_ != nullptr) {
        TAG_LOGI(AAFwkTag::DELEGATOR, "use stsTestRunnerObj_");
        auto env = stsRuntime_.GetAniEnv();
        if (env->ResetError() != ANI_OK) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "ResetError failed");
        }
        ani_method method;
        ani_status status = ANI_ERROR;
        status = env->Class_FindMethod(stsTestRunnerObj_->aniCls, "onPrepare", ":V", &method);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "get onPrepare failed status : %{public}d", status);
            return;
        }
        TAG_LOGI(AAFwkTag::DELEGATOR, "get onPrepare success");

        ani_int result;
        status = env->Object_CallMethod_Void(stsTestRunnerObj_->aniObj, method, &result);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void onPrepare failed status : %{public}d", status);
        } else {
            TAG_LOGI(AAFwkTag::DELEGATOR, "Object_CallMethod_Void onPrepare success");
        }
    }

    // TODO: for test to support EntryAbility.sts
    TAG_LOGI(AAFwkTag::DELEGATOR, "use default entryability");
    auto aniEnv = stsRuntime_.GetAniEnv();
    CallOnPrepareMethod(aniEnv);
}

void STSTestRunner::Run()
{
    TAG_LOGI(AAFwkTag::DELEGATOR, "STSTestRunner Run");
    if (stsTestRunnerObj_ != nullptr) {
        TAG_LOGI(AAFwkTag::DELEGATOR, "use stsTestRunnerObj_");
        auto env = stsRuntime_.GetAniEnv();
        if (env->ResetError() != ANI_OK) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "ResetError failed");
        }
        ani_method method;
        ani_status status = ANI_ERROR;
        status = env->Class_FindMethod(stsTestRunnerObj_->aniCls, "onRun", ":V", &method);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "get onRun failed status : %{public}d", status);
            return;
        }
        TAG_LOGI(AAFwkTag::DELEGATOR, "get onRun success");

        ani_int result;
        status = env->Object_CallMethod_Void(stsTestRunnerObj_->aniObj, method, &result);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::DELEGATOR, "Object_CallMethod_Void onRun failed status : %{public}d", status);
        } else {
            TAG_LOGI(AAFwkTag::DELEGATOR, "Object_CallMethod_Void onRun success");
        }
    }

    // TODO: for test to support EntryAbility.sts
    TAG_LOGI(AAFwkTag::DELEGATOR, "use default entryability");
    auto aniEnv = stsRuntime_.GetAniEnv();
    CallOnRunMethod(aniEnv);
}
} // namespace RunnerRuntime
} // namespace OHOS
