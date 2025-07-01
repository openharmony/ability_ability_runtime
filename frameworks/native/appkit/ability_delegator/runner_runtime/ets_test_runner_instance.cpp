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

#include "runner_runtime/ets_test_runner_instance.h"

#include <cstddef>
#include <dlfcn.h>

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace RunnerRuntime {
namespace {
const char *ETS_ANI_LIBNAME = "libtest_runner_ani.z.so";
const char *ETS_ANI_Create_FUNC = "OHOS_ETS_Test_Runner_Create";
using CreateETSTestRunnerFunc = AppExecFwk::TestRunner*(*)(const std::unique_ptr<AbilityRuntime::Runtime>&,
    const std::shared_ptr<AppExecFwk::AbilityDelegatorArgs>&, const AppExecFwk::BundleInfo&);
CreateETSTestRunnerFunc g_etsCreateFunc = nullptr;
}

AppExecFwk::TestRunner *CreateETSTestRunner(const std::unique_ptr<AbilityRuntime::Runtime> &runtime,
    const std::shared_ptr<AppExecFwk::AbilityDelegatorArgs> &args, const AppExecFwk::BundleInfo &bundleInfo)
{
    if (g_etsCreateFunc != nullptr) {
        return g_etsCreateFunc(runtime, args, bundleInfo);
    }
    auto handle = dlopen(ETS_ANI_LIBNAME, RTLD_LAZY);
    if (handle == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "dlopen failed %{public}s, %{public}s", ETS_ANI_LIBNAME, dlerror());
        return nullptr;
    }
    auto symbol = dlsym(handle, ETS_ANI_Create_FUNC);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::DELEGATOR, "dlsym failed %{public}s, %{public}s", ETS_ANI_Create_FUNC, dlerror());
        dlclose(handle);
        return nullptr;
    }
    g_etsCreateFunc = reinterpret_cast<CreateETSTestRunnerFunc>(symbol);
    return g_etsCreateFunc(runtime, args, bundleInfo);
}
} // namespace RunnerRuntime
} // namespace OHOS