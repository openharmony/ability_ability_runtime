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

#ifndef MOCK_FOUNDATION_ABILITY_RUNTIME_SIMULATOR_COMMON_ABILITY_INFO_H
#define MOCK_FOUNDATION_ABILITY_RUNTIME_SIMULATOR_COMMON_ABILITY_INFO_H

#include <string>
#include <vector>
#include "application_info.h"
#include "extension_ability_info.h"
#include "skill.h"

namespace OHOS {
namespace AppExecFwk {
enum class DisplayOrientation {
    UNSPECIFIED = 0,
    LANDSCAPE,
    PORTRAIT,
    FOLLOWRECENT,
    LANDSCAPE_INVERTED,
    PORTRAIT_INVERTED,
    AUTO_ROTATION,
    AUTO_ROTATION_LANDSCAPE,
    AUTO_ROTATION_PORTRAIT,
    AUTO_ROTATION_RESTRICTED,
    AUTO_ROTATION_LANDSCAPE_RESTRICTED,
    AUTO_ROTATION_PORTRAIT_RESTRICTED,
    LOCKED,
};

enum class LaunchMode {
    SINGLETON = 0,
    STANDARD,  // support more than one instance
    SPECIFIED,
};

struct AbilityInfo {
    std::string name;
    std::string label;
    std::string description;
    std::string iconPath;
    int32_t labelId;
    int32_t descriptionId;
    int32_t iconId;
    std::string theme;
    ExtensionAbilityType extensionAbilityType = ExtensionAbilityType::UNSPECIFIED;
    DisplayOrientation orientation = DisplayOrientation::UNSPECIFIED;
    LaunchMode launchMode = LaunchMode::SINGLETON;
    std::string srcPath;
    std::vector<std::string> permissions;
    std::string uri;
    ApplicationInfo applicationInfo;
    bool enabled = false;
    MetaData metaData;
    std::string bundleName;
    std::string moduleName;       // the "module.name" in config.json
    std::string applicationName;  // the "bundlename" in config.json
    std::string codePath;         // ability main code path with name
    std::string hapPath;
    std::string srcEntrance;
    std::vector<Metadata> metadata;
    bool isStageBasedModel = false;
    std::vector<Skill> skills;
    int32_t uid = -1;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif