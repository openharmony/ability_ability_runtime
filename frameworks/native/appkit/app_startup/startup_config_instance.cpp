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

#include "startup_config_instance.h"

#include <dlfcn.h>
#include <mutex>

#include "ets_runtime.h"
#include "hilog_tag_wrapper.h"
#include "js_runtime.h"
#include "js_startup_config.h"
#include "startup_task_instance.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
const char* ETS_STARTUP_CONFIG_LIBNAME = "libability_stage_ani.z.so";
const char* CREATE_ETS_STARTUP_CONFIG_FUNC = "OHOS_CreateEtsStartupConfig";
using CreateEtsStartupConfigFunc = StartupConfig*(*)(ani_env* env);
CreateEtsStartupConfigFunc g_etsStartupConfigCreateFunc = nullptr;
std::mutex g_etsStartupConfigCreateFuncMutex;
}

std::shared_ptr<StartupConfig> StartupConfigInstance::CreateStartupConfig(const std::unique_ptr<Runtime> &runtime,
    const std::string &arkTSMode)
{
    auto &taskRuntime = StartupTaskInstance::GetSpecifiedRuntime(runtime, arkTSMode);
    if (taskRuntime == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null taskRuntime");
        return nullptr;
    }

    switch (taskRuntime->GetLanguage()) {
        case Runtime::Language::JS:
            return CreateJsStartupConfig(taskRuntime);
        case Runtime::Language::ETS:
            return CreateEtsStartupConfig(taskRuntime);
        default:
            TAG_LOGE(AAFwkTag::STARTUP, "unsupported runtime language: %{public}d",
                static_cast<int32_t>(runtime->GetLanguage()));
            return nullptr;
    }
}

std::shared_ptr<StartupConfig> StartupConfigInstance::CreateJsStartupConfig(const std::unique_ptr<Runtime> &runtime)
{
    TAG_LOGD(AAFwkTag::STARTUP, "CreateJsStartupConfig");
    if (runtime == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "null runtime or env");
        return nullptr;
    }
    auto &jsRuntime = static_cast<JsRuntime &>(*runtime);
    return std::make_shared<JsStartupConfig>(jsRuntime.GetNapiEnv());
}

std::shared_ptr<StartupConfig> StartupConfigInstance::CreateEtsStartupConfig(const std::unique_ptr<Runtime> &runtime)
{
    TAG_LOGD(AAFwkTag::STARTUP, "CreateEtsStartupConfig");
    std::lock_guard<std::mutex> lock(g_etsStartupConfigCreateFuncMutex);
    auto &etsRuntime = static_cast<ETSRuntime &>(*runtime);
    auto env = etsRuntime.GetAniEnv();
    if (g_etsStartupConfigCreateFunc != nullptr) {
        auto configPtr = g_etsStartupConfigCreateFunc(env);
        return std::shared_ptr<StartupConfig>(configPtr);
    }

    auto handle = dlopen(ETS_STARTUP_CONFIG_LIBNAME, RTLD_LAZY);
    if (handle == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "dlopen failed %{public}s, %{public}s", ETS_STARTUP_CONFIG_LIBNAME, dlerror());
        return nullptr;
    }

    auto symbol = dlsym(handle, CREATE_ETS_STARTUP_CONFIG_FUNC);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::STARTUP, "dlsym failed %{public}s, %{public}s", CREATE_ETS_STARTUP_CONFIG_FUNC, dlerror());
        dlclose(handle);
        return nullptr;
    }

    g_etsStartupConfigCreateFunc = reinterpret_cast<CreateEtsStartupConfigFunc>(symbol);
    auto configPtr = g_etsStartupConfigCreateFunc(env);
    return std::shared_ptr<StartupConfig>(configPtr);
}
} // namespace AbilityRuntime
} // namespace OHOS