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

#ifndef OHOS_ABILITY_RUNTIME_MULTI_INSTANCE_UTILS_H
#define OHOS_ABILITY_RUNTIME_MULTI_INSTANCE_UTILS_H

#include <string>

#include "ability_record.h"
#include "application_info.h"
#include "extension_ability_info.h"
#include "want.h"

namespace OHOS {
namespace AAFwk {
/**
 * @class MultiInstanceUtils
 * provides multi-instance utilities.
 */
class MultiInstanceUtils {
public:
    /**
     * GetInstanceKey, get instance key of the given want.
     *
     * @param want The want param.
     * @return The instance key.
     */
    static std::string GetInstanceKey(const Want& want);

    /**
     * GetValidExtensionInstanceKey, get valid extension instance key.
     *
     * @param abilityRequest The ability request.
     * @return The instance key.
     */
    static std::string GetValidExtensionInstanceKey(const AbilityRequest &abilityRequest);

    /**
     * GetValidExtensionInstanceKey, get valid extension instance key.
     *
     * @param abilityRequest The ability request.
     * @return The instance key.
     */
    static std::string GetSelfCallerInstanceKey(const AbilityRequest &abilityRequest);

    /**
     * IsDefaultInstanceKey, check if the key is the default instance key.
     *
     * @param key The key to be queried.
     * @return Whether the instance key is the default.
     */
    static bool IsDefaultInstanceKey(const std::string& key);

    /**
     * IsMultiInstanceApp, check if the app is the default multi-instance app.
     *
     * @param appInfo The app info to be queried.
     * @return Whether the app is the default multi-instance app.
     */
    static bool IsMultiInstanceApp(AppExecFwk::ApplicationInfo appInfo);

    /**
     * IsSupportedExtensionType, check if the type supports extension type.
     *
     * @param type The extension ability type.
     * @return Whether the type supports extension type.
     */
    static bool IsSupportedExtensionType(AppExecFwk::ExtensionAbilityType type);

    /**
     * IsInstanceKeyExist, check if the instance key exists.
     *
     * @param bundleName The bundle name.
     * @param key The instance key to be queried.
     * @return Whether the instance key exists.
     */
    static bool IsInstanceKeyExist(const std::string& bundleName, const std::string& key);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_MULTI_INSTANCE_UTILS_H
