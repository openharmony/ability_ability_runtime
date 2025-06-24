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

#ifndef MOCK_FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_INFO_H
#define MOCK_FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_INFO_H

#include <string>
#include <vector>
#include "ability_info.h"
#include "application_info.h"

namespace OHOS {
namespace AppExecFwk {
enum BundleFlag {
    GET_BUNDLE_DEFAULT = 0x00000000,
    GET_BUNDLE_WITH_ABILITIES = 0x00000001,
    GET_BUNDLE_WITH_REQUESTED_PERMISSION = 0x00000010,
    GET_BUNDLE_WITH_EXTENSION_INFO = 0x00000020,
    GET_BUNDLE_WITH_HASH_VALUE = 0x00000030,
    GET_BUNDLE_WITH_MENU = 0x00000040,
    GET_BUNDLE_WITH_ROUTER_MAP = 0x00000080,
    GET_BUNDLE_WITH_SKILL = 0x00000800,
};

enum class GetBundleInfoFlag {
    GET_BUNDLE_INFO_DEFAULT = 0x00000000,
    GET_BUNDLE_INFO_WITH_APPLICATION = 0x00000001,
    GET_BUNDLE_INFO_WITH_HAP_MODULE = 0x00000002,
    GET_BUNDLE_INFO_WITH_ABILITY = 0x00000004,
    GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY = 0x00000008,
    GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION = 0x00000010,
    GET_BUNDLE_INFO_WITH_METADATA = 0x00000020,
    GET_BUNDLE_INFO_WITH_DISABLE = 0x00000040,
    GET_BUNDLE_INFO_WITH_SIGNATURE_INFO = 0x00000080,
    GET_BUNDLE_INFO_WITH_MENU = 0x00000100,
    GET_BUNDLE_INFO_WITH_ROUTER_MAP = 0x00000200,
    GET_BUNDLE_INFO_WITH_SKILL = 0x00000800,
    GET_BUNDLE_INFO_ONLY_WITH_LAUNCHER_ABILITY = 0x00001000,
    GET_BUNDLE_INFO_OF_ANY_USER = 0x00002000,
    GET_BUNDLE_INFO_EXCLUDE_CLONE = 0x00004000,
};

struct BundleInfo {
    bool singleton = false;
    uint32_t versionCode = 0;
    int32_t appIndex = 0;
    int uid = -1;
    int gid = -1;
    std::string name;
    std::string versionName;
    std::string appId;
    std::vector<AbilityInfo> abilityInfos;
    ApplicationInfo applicationInfo;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif