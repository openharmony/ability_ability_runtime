/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_ABILITY_RUNTIME_SIMULATOR_EXTENSION_ABILITY_INFO_H
#define FOUNDATION_ABILITY_RUNTIME_SIMULATOR_EXTENSION_ABILITY_INFO_H

#include <string>

#include "application_info.h"

namespace OHOS {
namespace AppExecFwk {
enum ExtensionAbilityInfoFlag {
    GET_EXTENSION_INFO_DEFAULT = 0x00000000,
    GET_EXTENSION_INFO_WITH_PERMISSION = 0x00000002,
    GET_EXTENSION_INFO_WITH_APPLICATION = 0x00000004,
    GET_EXTENSION_INFO_WITH_METADATA = 0x00000020,
};

enum class GetExtensionAbilityInfoFlag {
    GET_EXTENSION_ABILITY_INFO_DEFAULT = 0x00000000,
    GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION = 0x00000001,
    GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION = 0x00000002,
    GET_EXTENSION_ABILITY_INFO_WITH_METADATA = 0x00000004,
};

enum class ExtensionAbilityType {
    FORM = 0,
    WORK_SCHEDULER = 1,
    INPUTMETHOD = 2,
    SERVICE = 3,
    ACCESSIBILITY = 4,
    DATASHARE = 5,
    FILESHARE = 6,
    STATICSUBSCRIBER = 7,
    WALLPAPER = 8,
    BACKUP = 9,
    WINDOW = 10,
    ENTERPRISE_ADMIN = 11,
    FILEACCESS_EXTENSION = 12,
    THUMBNAIL = 13,
    PREVIEW_TYPE = 14,
    PRINT = 15,
    PUSH = 17,
    DRIVER = 18,
    APP_ACCOUNT_AUTHORIZATION = 19,
    FENCE = 24,
    DISTRIBUTED = 28,
    UNSPECIFIED = 255,
    UI = 256,
    HMS_ACCOUNT = 257,
    SYSDIALOG_USERAUTH = 300,
    SYSDIALOG_COMMON = 301,
    SYSDIALOG_ATOMICSERVICEPANEL = 302,
    SYSPICKER_MEDIACONTROL = 400,
    SYSPICKER_SHARE = 401
};

enum class CompileMode {
    JS_BUNDLE = 0,
    ES_MODULE,
};

struct SkillUriForAbilityAndExtension {
    std::string scheme;
    std::string host;
    std::string port;
    std::string path;
    std::string pathStartWith;
    std::string pathRegex;
    std::string type;
};

struct ExtensionAbilityInfo {
    std::string bundleName;
    std::string moduleName;
    std::string name;
    std::string srcEntrance;
    std::string icon;
    int32_t iconId = 0;
    std::string label;
    int32_t labelId = 0;
    std::string description;
    int32_t descriptionId = 0;
    int32_t priority = 0;
    std::vector<std::string> permissions;
    std::string readPermission;
    std::string writePermission;
    std::string uri;
    ExtensionAbilityType type;
    bool visible = false;
    std::vector<Metadata> metadata;
    ApplicationInfo applicationInfo;
    std::string resourcePath;
    std::string hapPath;
    bool enabled = true;
    std::string process;
    CompileMode compileMode = CompileMode::JS_BUNDLE;
    int32_t uid = -1;
    std::vector<SkillUriForAbilityAndExtension> skillUri;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_ABILITY_RUNTIME_SIMULATOR_EXTENSION_ABILITY_INFO_H