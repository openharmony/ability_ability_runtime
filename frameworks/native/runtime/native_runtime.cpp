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

#include "native_runtime.h"

#include "hilog_tag_wrapper.h"
#include "module_manager/native_module_manager.h"

namespace OHOS {
namespace AbilityRuntime {
const std::string DEFAULT_NAMESPACE = "default";
const char *OH_ABILITY_RUNTIME_ON_NATIVE_EXTENSION_CREATE = "OH_AbilityRuntime_OnNativeExtenSionCreate";

bool NativeRuntime::LoadModule(const std::string& bundleModuleName, const std::string& fileName,
    const std::string& abilityName, AbilityRuntime_ExtensionInstance &instance)
{
    auto moduleManager = NativeModuleManager::GetInstance();
    if (moduleManager == nullptr) {
        TAG_LOGE(AAFwkTag::JSRUNTIME, "null moduleManager");
        return false;
    }
    std::string namespaceName;
    if (!moduleManager->GetLdNamespaceName(bundleModuleName, namespaceName)) {
        if (!moduleManager->GetLdNamespaceName(DEFAULT_NAMESPACE, namespaceName)) {
            TAG_LOGE(AAFwkTag::JSRUNTIME, "GetLdNamespaceName failed");
            return false;
        }
    }
    Dl_namespace ns;
    if (dlns_get(namespaceName.data(), &ns) != 0) {
        TAG_LOGE(AAFwkTag::JSRUNTIME, "namespaceName not found: %{public}s", namespaceName.c_str());
        return false;
    }
    LIBHANDLE nativeHandle = nullptr;
    nativeHandle = dlopen_ns(&ns, fileName.c_str(), RTLD_LAZY);
    if (nativeHandle == nullptr) {
        TAG_LOGE(AAFwkTag::JSRUNTIME, "dlopen failed: %{public}s", fileName.c_str());
        return false;
    }
    auto symbol = LIBSYM(nativeHandle, OH_ABILITY_RUNTIME_ON_NATIVE_EXTENSION_CREATE);
    if (!symbol) {
        TAG_LOGE(AAFwkTag::JSRUNTIME, "dlsym failed");
        LIBFREE(nativeHandle);
        return false;
    }
    auto func = reinterpret_cast<void(*)(AbilityRuntime_ExtensionInstanceHandle, const char*)>(symbol);
    AbilityRuntime_ExtensionInstanceHandle handle = &instance;
    func(handle, abilityName.c_str());
    return true;
}
} // namespace AbilityRuntime
} // namespace OHOS