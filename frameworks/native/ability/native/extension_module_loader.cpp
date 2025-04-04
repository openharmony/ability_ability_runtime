/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "extension_module_loader.h"

#include <dlfcn.h>

#include "hilog_tag_wrapper.h"

namespace OHOS::AbilityRuntime {
namespace {
constexpr char EXTENSION_MODULE_ENTRY[] = "OHOS_EXTENSION_GetExtensionModule";

using DynamicEntry = void* (*)();

class DummyExtensionModuleLoader final : public ExtensionModuleLoader, public Singleton<DummyExtensionModuleLoader> {
    DECLARE_SINGLETON(DummyExtensionModuleLoader);

public:
    Extension* Create(const std::unique_ptr<Runtime>& runtime) const override
    {
        return nullptr;
    }

    std::map<std::string, std::string> GetParams() override
    {
        std::map<std::string, std::string> params;
        return params;
    }
};

DummyExtensionModuleLoader::DummyExtensionModuleLoader() = default;
DummyExtensionModuleLoader::~DummyExtensionModuleLoader() = default;

ExtensionModuleLoader& GetExtensionModuleLoader(const char* sharedLibrary)
{
    if (sharedLibrary == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "null sharedLibrary");
        return DummyExtensionModuleLoader::GetInstance();
    }

    void* handle = dlopen(sharedLibrary, RTLD_LAZY);
    if (handle == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "open extension library %{public}s failed, reason: %{public}sn", sharedLibrary,
            dlerror());
        return DummyExtensionModuleLoader::GetInstance();
    }

    auto entry = reinterpret_cast<DynamicEntry>(dlsym(handle, EXTENSION_MODULE_ENTRY));
    if (entry == nullptr) {
        dlclose(handle);
        TAG_LOGE(AAFwkTag::EXT, "get extension symbol %{public}s in %{public}s failed", EXTENSION_MODULE_ENTRY,
            sharedLibrary);
        return DummyExtensionModuleLoader::GetInstance();
    }

    auto loader = reinterpret_cast<ExtensionModuleLoader*>(entry());
    if (loader == nullptr) {
        dlclose(handle);
        TAG_LOGE(AAFwkTag::EXT, "get extension module loader in %{public}s failed", sharedLibrary);
        return DummyExtensionModuleLoader::GetInstance();
    }

    return *loader;
}
} // namespace

ExtensionModuleLoader& ExtensionModuleLoader::GetLoader(const char* sharedLibrary)
{
    return GetExtensionModuleLoader(sharedLibrary);
}

Extension *ExtensionModuleLoader::Create(const std::unique_ptr<Runtime>& runtime) const
{
    return nullptr;
}
}
