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

#include "ets_embedded_ui_extension_instance.h"

#include <cstddef>
#include <dlfcn.h>

#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "string_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* ETS_ANI_LIBNAME = "libembedded_ui_extension_ani.z.so";
constexpr const char* ETS_ANI_CREATE_FUNC = "OHOS_ETS_Embedded_Extension_Create";
using CreateETSEmbeddedUIExtensionFunc = EmbeddedUIExtension*(*)(const std::unique_ptr<Runtime>&);
CreateETSEmbeddedUIExtensionFunc g_etsCreateFunc = nullptr;
}

EmbeddedUIExtension *CreateETSEmbeddedUIExtension(const std::unique_ptr<Runtime> &runtime)
{
    if (g_etsCreateFunc != nullptr) {
        return g_etsCreateFunc(runtime);
    }
    auto handle = dlopen(ETS_ANI_LIBNAME, RTLD_LAZY);
    if (handle == nullptr) {
        TAG_LOGE(AAFwkTag::EMBEDDED_EXT, "dlopen failed %{public}s, %{public}s", ETS_ANI_LIBNAME, dlerror());
        return nullptr;
    }
    auto symbol = dlsym(handle, ETS_ANI_CREATE_FUNC);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::EMBEDDED_EXT, "dlsym failed %{public}s, %{public}s", ETS_ANI_CREATE_FUNC, dlerror());
        dlclose(handle);
        return nullptr;
    }
    g_etsCreateFunc = reinterpret_cast<CreateETSEmbeddedUIExtensionFunc>(symbol);
    return g_etsCreateFunc(runtime);
}
} // namespace AbilityRuntime
} // namespace OHOS