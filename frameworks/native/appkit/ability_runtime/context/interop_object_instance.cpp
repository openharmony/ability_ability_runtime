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
const char* CREATE_JS_INTEROP_OBJECT_FUNC = "OHOS_CreateJsInteropObject";
const char* CREATE_JS_INTEROP_ABILITY_LIFECYCLE_CALLBACK_FUNC = "OHOS_CreateJsInteropAbilityLifecycleCallback";
using CreateInteropObjectFunc = InteropObject*(*)(const Runtime &runtime, const AbilityLifecycleCallbackArgs &arg);
CreateInteropObjectFunc g_etsInteropObjectCreateFunc = nullptr;
std::mutex g_etsInteropObjectCreateFuncMutex;
CreateInteropObjectFunc g_jsInteropObjectCreateFunc = nullptr;
std::mutex g_jsInteropObjectCreateFuncMutex;
using CreateInteropAbilityLifecycleCallbackFunc = InteropAbilityLifecycleCallback*(*)(void *env);
CreateInteropAbilityLifecycleCallbackFunc g_jsInteropAbilityLifecycleCallbackCreateFunc = nullptr;
std::mutex g_jsInteropAbilityLifecycleCallbackCreateFuncMutex;
void *g_handle = nullptr;
std::mutex g_handleMutex;

void *GetDlSymbol(const char *funcName)
{
    std::lock_guard<std::mutex> lock(g_handleMutex);
    if (g_handle == nullptr) {
        g_handle = dlopen(ETS_ANI_COMMON_LIBNAME, RTLD_LAZY);
        if (g_handle == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "dlopen failed %{public}s, %{public}s", ETS_ANI_COMMON_LIBNAME, dlerror());
            return nullptr;
        }
    }

    auto symbol = dlsym(g_handle, funcName);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "dlsym failed %{public}s, %{public}s", funcName, dlerror());
        dlclose(g_handle);
        g_handle = nullptr;
        return nullptr;
    }
    return symbol;
}
}

std::shared_ptr<InteropObject> InteropObjectInstance::CreateInteropObject(const Runtime &runtime,
    const AbilityLifecycleCallbackArgs &arg)
{
    if (runtime.GetLanguage() == Runtime::Language::JS) {
        return CreateEtsInteropObject(runtime, arg);
    }
    if (runtime.GetLanguage() == Runtime::Language::ETS) {
        return CreateJsInteropObject(runtime, arg);
    }
    return nullptr;
}

std::shared_ptr<InteropObject> InteropObjectInstance::CreateEtsInteropObject(const Runtime &runtime,
    const AbilityLifecycleCallbackArgs &arg)
{
    TAG_LOGD(AAFwkTag::APPKIT, "CreateEtsInteropObject");
    {
        std::lock_guard<std::mutex> lock(g_etsInteropObjectCreateFuncMutex);
        if (g_etsInteropObjectCreateFunc != nullptr) {
            return std::shared_ptr<InteropObject>(g_etsInteropObjectCreateFunc(runtime, arg));
        }
    }

    auto symbol = GetDlSymbol(CREATE_ETS_INTEROP_OBJECT_FUNC);
    if (symbol == nullptr) {
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(g_etsInteropObjectCreateFuncMutex);
    g_etsInteropObjectCreateFunc = reinterpret_cast<CreateInteropObjectFunc>(symbol);
    return std::shared_ptr<InteropObject>(g_etsInteropObjectCreateFunc(runtime, arg));
}

std::shared_ptr<InteropObject> InteropObjectInstance::CreateJsInteropObject(const Runtime &runtime,
    const AbilityLifecycleCallbackArgs &arg)
{
    TAG_LOGD(AAFwkTag::APPKIT, "CreateJsInteropObject");
    {
        std::lock_guard<std::mutex> lock(g_jsInteropObjectCreateFuncMutex);
        if (g_jsInteropObjectCreateFunc != nullptr) {
            return std::shared_ptr<InteropObject>(g_jsInteropObjectCreateFunc(runtime, arg));
        }
    }

    auto symbol = GetDlSymbol(CREATE_JS_INTEROP_OBJECT_FUNC);
    if (symbol == nullptr) {
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(g_jsInteropObjectCreateFuncMutex);
    g_jsInteropObjectCreateFunc = reinterpret_cast<CreateInteropObjectFunc>(symbol);
    return std::shared_ptr<InteropObject>(g_jsInteropObjectCreateFunc(runtime, arg));
}

std::shared_ptr<InteropAbilityLifecycleCallback> InteropObjectInstance::CreateJsInteropAbilityLifecycleCallback(
    void *env)
{
    TAG_LOGD(AAFwkTag::APPKIT, "CreateJsInteropAbilityLifecycleCallback");
    {
        std::lock_guard<std::mutex> lock(g_jsInteropAbilityLifecycleCallbackCreateFuncMutex);
        if (g_jsInteropAbilityLifecycleCallbackCreateFunc != nullptr) {
            return std::shared_ptr<InteropAbilityLifecycleCallback>(
                g_jsInteropAbilityLifecycleCallbackCreateFunc(env));
        }
    }

    auto symbol = GetDlSymbol(CREATE_JS_INTEROP_ABILITY_LIFECYCLE_CALLBACK_FUNC);
    if (symbol == nullptr) {
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(g_jsInteropAbilityLifecycleCallbackCreateFuncMutex);
    g_jsInteropAbilityLifecycleCallbackCreateFunc =
        reinterpret_cast<CreateInteropAbilityLifecycleCallbackFunc>(symbol);
    return std::shared_ptr<InteropAbilityLifecycleCallback>(g_jsInteropAbilityLifecycleCallbackCreateFunc(env));
}
} // namespace AbilityRuntime
} // namespace OHOS