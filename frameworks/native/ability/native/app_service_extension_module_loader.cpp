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

#include "app_service_extension_module_loader.h"
#include "app_service_extension.h"

namespace OHOS::AbilityRuntime {
AppServiceExtensionModuleLoader::AppServiceExtensionModuleLoader() = default;
AppServiceExtensionModuleLoader::~AppServiceExtensionModuleLoader() = default;

Extension *AppServiceExtensionModuleLoader::Create(const std::unique_ptr<Runtime>& runtime) const
{
    return AppServiceExtension::Create(runtime);
}

std::map<std::string, std::string> AppServiceExtensionModuleLoader::GetParams()
{
    std::map<std::string, std::string> params;
    // type means extension type in ExtensionAbilityType of extension_ability_info.h, 29 means app service.
    params.insert(std::pair<std::string, std::string>("type", "29"));
    // extension name
    params.insert(std::pair<std::string, std::string>("name", "AppServiceExtension"));
    return params;
}

extern "C" __attribute__((visibility("default"))) void* OHOS_EXTENSION_GetExtensionModule()
{
    return &AppServiceExtensionModuleLoader::GetInstance();
}
} // namespace OHOS::AbilityRuntime
