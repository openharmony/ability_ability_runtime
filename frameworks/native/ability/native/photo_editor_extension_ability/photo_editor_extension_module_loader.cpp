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

#include "photo_editor_extension_module_loader.h"
#include "hilog_tag_wrapper.h"
#include "photo_editor_extension.h"

namespace OHOS {
namespace AbilityRuntime {
PhotoEditorExtensionModuleLoader::PhotoEditorExtensionModuleLoader() = default;
PhotoEditorExtensionModuleLoader::~PhotoEditorExtensionModuleLoader() = default;

Extension *PhotoEditorExtensionModuleLoader::Create(const std::unique_ptr<Runtime> &runtime) const
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    return PhotoEditorExtension::Create(runtime);
}

std::map<std::string, std::string> PhotoEditorExtensionModuleLoader::GetParams()
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    std::map<std::string, std::string> params;
    // type means extension type in ExtensionAbilityType of
    // extension_ability_info.h, 266 means photoEditorExtension.
    params.insert(std::pair<std::string, std::string>("type", "23"));
    params.insert(std::pair<std::string, std::string>("name", "PhotoEditorExtensionAbility"));
    return params;
}

extern "C" __attribute__((visibility("default"))) void *OHOS_EXTENSION_GetExtensionModule()
{
    return &PhotoEditorExtensionModuleLoader::GetInstance();
}
} // namespace AbilityRuntime
} // namespace OHOS