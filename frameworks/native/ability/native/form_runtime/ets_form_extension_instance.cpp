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

#include "form_runtime/ets_form_extension_instance.h"

#include <dlfcn.h>

#include "form_extension.h"
#include "hilog_tag_wrapper.h"
#include "runtime.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
#if defined(WINDOWS_PLATFORM)
constexpr char ETS_FORM_EXT_LIB_NAME[] = "libets_form_extension.dll";
#elif defined(MAC_PLATFORM)
constexpr char ETS_FORM_EXT_LIB_NAME[] = "libets_form_extension.dylib";
#else
constexpr char ETS_FORM_EXT_LIB_NAME[] = "libets_form_extension.z.so";
#endif

using CreateFunc = FormExtension *(*)();
static constexpr char ETS_FORM_EXT_CREATE_FUNC[] = "OHOS_ABILITY_ETSFormExtension";

#ifndef ETS_EXPORT
#ifndef __WINDOWS__
#define ETS_EXPORT __attribute__((visibility("default")))
#else
#define ETS_EXPORT __declspec(dllexport)
#endif
#endif
} // namespace

FormExtension *CreateETSFormExtension(const std::unique_ptr<Runtime> &runtime)
{
    void *handle = dlopen(ETS_FORM_EXT_LIB_NAME, RTLD_LAZY);
    if (handle == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "open ets_form_extension library %{public}s failed, reason: %{public}sn",
                 ETS_FORM_EXT_LIB_NAME, dlerror());
        return new FormExtension();
    }

    auto entry = reinterpret_cast<CreateFunc>(dlsym(handle, ETS_FORM_EXT_CREATE_FUNC));
    if (entry == nullptr) {
        dlclose(handle);
        TAG_LOGE(AAFwkTag::FORM_EXT, "get ets_form_extension symbol %{public}s in %{public}s failed",
                 ETS_FORM_EXT_CREATE_FUNC, ETS_FORM_EXT_LIB_NAME);
        return new FormExtension();
    }

    auto instance = entry();
    if (instance == nullptr) {
        dlclose(handle);
        TAG_LOGE(AAFwkTag::FORM_EXT, "get ets_form_extension instance in %{public}s failed", ETS_FORM_EXT_LIB_NAME);
        return new FormExtension();
    }

    return instance;
}
} // namespace AbilityRuntime
} // namespace OHOS