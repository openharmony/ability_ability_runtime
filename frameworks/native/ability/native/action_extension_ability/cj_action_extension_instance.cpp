/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cj_action_extension_instance.h"

#include "hilog_tag_wrapper.h"
#include "action_extension.h"
#include "runtime.h"
#include <dlfcn.h>

namespace OHOS {
namespace AbilityRuntime {
namespace {
#if defined(WINDOWS_PLATFORM)
    constexpr char CJ_ACTION_EXT_LIB_NAME[] = "libcj_action_extension.dll";
#elif defined(MAC_PLATFORM)
    constexpr char CJ_ACTION_EXT_LIB_NAME[] = "libcj_action_extension.dylib";
#else
    constexpr char CJ_ACTION_EXT_LIB_NAME[] = "libcj_action_extension.z.so";
#endif

using CreateFunc = ActionExtension* (*)(void*);
static constexpr char CJ_ACTION_EXT_CREATE_FUNC[] = "OHOS_ABILITY_CJActionExtension";
} // namespace

ActionExtension* CreateCJActionExtension(const std::unique_ptr<Runtime> &runtime)
{
    std::unique_ptr<Runtime>* runtimePtr = const_cast<std::unique_ptr<Runtime>*>(&runtime);

    void* handle = dlopen(CJ_ACTION_EXT_LIB_NAME, RTLD_LAZY);
    if (handle == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "open cj_action_extension library %{public}s failed, reason: %{public}sn",
            CJ_ACTION_EXT_LIB_NAME, dlerror());
        return new (std::nothrow) ActionExtension();
    }

    auto entry = reinterpret_cast<CreateFunc>(dlsym(handle, CJ_ACTION_EXT_CREATE_FUNC));
    if (entry == nullptr) {
        dlclose(handle);
        TAG_LOGE(AAFwkTag::EXT, "get cj_action_extension symbol %{public}s in %{public}s failed",
            CJ_ACTION_EXT_CREATE_FUNC, CJ_ACTION_EXT_LIB_NAME);
        return new (std::nothrow) ActionExtension();
    }

    auto instance = entry(reinterpret_cast<void*>(runtimePtr));
    if (instance == nullptr) {
        dlclose(handle);
        TAG_LOGE(AAFwkTag::EXT, "get cj_action_extension instance in %{public}s failed",
            CJ_ACTION_EXT_LIB_NAME);
        return new (std::nothrow) ActionExtension();
    }

    return instance;
}
} // namespace AbilityRuntime
} // namespace OHOS
