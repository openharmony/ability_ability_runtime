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

#include "startup_task_instance.h"

#include <dlfcn.h>
#include <mutex>

#include "ets_runtime.h"
#include "hilog_tag_wrapper.h"
#include "js_runtime.h"
#include "js_startup_task.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
const char* ETS_STARTUP_TASK_LIBNAME = "libability_stage_ani.z.so";
const char* CREATE_ETS_STARTUP_TASK_FUNC = "OHOS_CreateEtsStartupTask";
using CreateEtsStartupTaskFunc = AppStartupTask*(*)(const std::unique_ptr<Runtime> &runtime,
    const StartupTaskInfo &info, bool lazyLoad);
CreateEtsStartupTaskFunc g_etsStartupTaskCreateFunc = nullptr;
std::mutex g_etsStartupTaskCreateFuncMutex;
}

const std::unique_ptr<Runtime> &StartupTaskInstance::GetSpecifiedRuntime(
    const std::unique_ptr<Runtime> &runtime, const std::string &arkTSMode)
{
    if (arkTSMode != AbilityRuntime::CODE_LANGUAGE_ARKTS_1_2 &&
        runtime != nullptr &&
        runtime->GetLanguage() == Runtime::Language::ETS) {
        return (static_cast<AbilityRuntime::ETSRuntime&>(*runtime)).GetJsRuntime();
    }
    return runtime;
}

std::shared_ptr<AppStartupTask> StartupTaskInstance::CreateStartupTask(const std::unique_ptr<Runtime> &runtime,
    const std::string &arkTSMode, const StartupTaskInfo &info, bool lazyLoad)
{
    auto &taskRuntime = GetSpecifiedRuntime(runtime, arkTSMode);
    if (taskRuntime == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null taskRuntime");
        return nullptr;
    }

    switch (taskRuntime->GetLanguage()) {
        case Runtime::Language::JS:
            return CreateJsStartupTask(taskRuntime, info, lazyLoad);
        case Runtime::Language::ETS:
            return CreateEtsStartupTask(taskRuntime, info, lazyLoad);
        default:
            TAG_LOGE(AAFwkTag::STARTUP, "unsupported runtime language: %{public}d",
                static_cast<int32_t>(taskRuntime->GetLanguage()));
            return nullptr;
    }
}

std::shared_ptr<AppStartupTask> StartupTaskInstance::CreateJsStartupTask(const std::unique_ptr<Runtime> &runtime,
    const StartupTaskInfo &info, bool lazyLoad)
{
    TAG_LOGD(AAFwkTag::STARTUP, "CreateJsStartupTask");
    if (runtime == nullptr) {
        return nullptr;
    }
    auto &jsRuntime = static_cast<JsRuntime &>(*runtime);
    return std::make_shared<JsStartupTask>(jsRuntime, info, lazyLoad);
}

std::shared_ptr<AppStartupTask> StartupTaskInstance::CreateEtsStartupTask(const std::unique_ptr<Runtime> &runtime,
    const StartupTaskInfo &info, bool lazyLoad)
{
    TAG_LOGD(AAFwkTag::STARTUP, "CreateEtsStartupTask");
    std::lock_guard<std::mutex> lock(g_etsStartupTaskCreateFuncMutex);
    if (g_etsStartupTaskCreateFunc != nullptr) {
        auto taskPtr = g_etsStartupTaskCreateFunc(runtime, info, lazyLoad);
        return std::shared_ptr<AppStartupTask>(taskPtr);
    }

    auto handle = dlopen(ETS_STARTUP_TASK_LIBNAME, RTLD_LAZY);
    if (handle == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "dlopen failed %{public}s, %{public}s", ETS_STARTUP_TASK_LIBNAME, dlerror());
        return nullptr;
    }

    auto symbol = dlsym(handle, CREATE_ETS_STARTUP_TASK_FUNC);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "dlsym failed %{public}s, %{public}s", CREATE_ETS_STARTUP_TASK_FUNC, dlerror());
        dlclose(handle);
        return nullptr;
    }

    g_etsStartupTaskCreateFunc = reinterpret_cast<CreateEtsStartupTaskFunc>(symbol);
    auto taskPtr = g_etsStartupTaskCreateFunc(runtime, info, lazyLoad);
    return std::shared_ptr<AppStartupTask>(taskPtr);
}
} // namespace AbilityRuntime
} // namespace OHOS