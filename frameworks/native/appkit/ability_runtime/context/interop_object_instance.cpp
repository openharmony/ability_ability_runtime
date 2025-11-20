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

#include "interop_object_instance.h"

#include <dlfcn.h>
#include <mutex>

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
const char* ETS_ANI_COMMON_LIBNAME = "libani_common.z.so";
const char* CREATE_ETS_INTEROP_OBJECT_FUNC = "OHOS_CreateEtsInteropObject";
using CreateEtsInteropObjectFunc = InteropObject*(*)(const Runtime &runtime, const AbilityLifecycleCallbackArgs &arg);
CreateEtsInteropObjectFunc g_etsInteropObjectCreateFunc = nullptr;
std::mutex g_etsInteropObjectCreateFuncMutex;
}

std::shared_ptr<InteropObject> InteropObjectInstance::CreateInteropObject(const Runtime &runtime,
    const AbilityLifecycleCallbackArgs &arg)
{
    if (runtime.GetLanguage() == Runtime::Language::JS) {
            return CreateEtsInteropObject(runtime, arg);
    }
    return nullptr;
}

std::shared_ptr<InteropObject> InteropObjectInstance::CreateEtsInteropObject(const Runtime &runtime,
    const AbilityLifecycleCallbackArgs &arg)
{
    TAG_LOGD(AAFwkTag::APPKIT, "CreateEtsInteropObject");
    std::lock_guard<std::mutex> lock(g_etsInteropObjectCreateFuncMutex);
    if (g_etsInteropObjectCreateFunc != nullptr) {
        return std::shared_ptr<InteropObject>(g_etsInteropObjectCreateFunc(runtime, arg));
    }

    auto handle = dlopen(ETS_ANI_COMMON_LIBNAME, RTLD_LAZY);
    if (handle == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "dlopen failed %{public}s, %{public}s", ETS_ANI_COMMON_LIBNAME, dlerror());
        return nullptr;
    }

    auto symbol = dlsym(handle, CREATE_ETS_INTEROP_OBJECT_FUNC);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "dlsym failed %{public}s, %{public}s", CREATE_ETS_INTEROP_OBJECT_FUNC, dlerror());
        dlclose(handle);
        return nullptr;
    }

    g_etsInteropObjectCreateFunc = reinterpret_cast<CreateEtsInteropObjectFunc>(symbol);
    auto interopObjectPtr = g_etsInteropObjectCreateFunc(runtime, arg);
    return std::shared_ptr<InteropObject>(interopObjectPtr);
}
} // namespace AbilityRuntime
} // namespace OHOS