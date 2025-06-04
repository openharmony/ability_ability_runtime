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

#include "form_runtime/cj_form_extension_instance.h"

#include "hilog_tag_wrapper.h"
#include "form_extension.h"
#include <dlfcn.h>

namespace OHOS {
namespace AbilityRuntime {
namespace {
#if defined(WINDOWS_PLATFORM)
    constexpr char CJ_FORM_EXT_LIB_NAME[] = "libcj_form_extension.dll";
#elif defined(MAC_PLATFORM)
    constexpr char CJ_FORM_EXT_LIB_NAME[] = "libcj_form_extension.dylib";
#else
    constexpr char CJ_FORM_EXT_LIB_NAME[] = "libcj_form_extension.z.so";
#endif

using CreateFunc = FormExtension* (*)();
static constexpr char CJ_FORM_EXT_CREATE_FUNC[] = "OHOS_ABILITY_CJFormExtension";

#ifndef CJ_EXPORT
#ifndef __WINDOWS__
#define CJ_EXPORT __attribute__((visibility("default")))
#else
#define CJ_EXPORT __declspec(dllexport)
#endif
#endif
} // namespace

FormExtension* CreateCJFormExtension()
{
    void* handle = dlopen(CJ_FORM_EXT_LIB_NAME, RTLD_LAZY);
    if (handle == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "open cj_form_extension library %{public}s failed, reason: %{public}sn",
            CJ_FORM_EXT_LIB_NAME, dlerror());
        return new FormExtension();
    }

    auto entry = reinterpret_cast<CreateFunc>(dlsym(handle, CJ_FORM_EXT_CREATE_FUNC));
    if (entry == nullptr) {
        dlclose(handle);
        TAG_LOGE(AAFwkTag::FORM_EXT, "get cj_form_extension symbol %{public}s in %{public}s failed",
            CJ_FORM_EXT_CREATE_FUNC, CJ_FORM_EXT_LIB_NAME);
        return new FormExtension();
    }

    auto instance = entry();
    if (instance == nullptr) {
        dlclose(handle);
        TAG_LOGE(AAFwkTag::FORM_EXT, "get cj_form_extension instance in %{public}s failed",
            CJ_FORM_EXT_LIB_NAME);
        return new FormExtension();
    }

    return instance;
}
} // namespace AbilityRuntime
} // namespace OHOS