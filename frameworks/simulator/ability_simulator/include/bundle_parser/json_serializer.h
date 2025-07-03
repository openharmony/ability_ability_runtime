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

#ifndef OHOS_ABILITY_RUNTIME_SIMULATOR_JSON_SERIALIZER_H
#define OHOS_ABILITY_RUNTIME_SIMULATOR_JSON_SERIALIZER_H

#include "ability_info.h"
#include "application_info.h"
#include "bundle_info.h"
#include "extension_ability_info.h"
#include "hap_module_info.h"
#include "module_info.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppExecFwk {
/*
 * form_json and to_json is global static overload method, which need callback by json library,
 * and can not rename this function, so don't named according UpperCamelCase style
 */
void to_json(nlohmann::json &jsonObject, const CustomizeData &customizeData);
void to_json(nlohmann::json &jsonObject, const MetaData &metaData);
void to_json(nlohmann::json &jsonObject, const Metadata &metadata);
void to_json(nlohmann::json &jsonObject, const AbilityInfo &abilityInfo);
void from_json(const nlohmann::json &jsonObject, CustomizeData &customizeData);
void from_json(const nlohmann::json &jsonObject, MetaData &metaData);
void from_json(const nlohmann::json &jsonObject, Metadata &metadata);
void from_json(const nlohmann::json &jsonObject, AbilityInfo &abilityInfo);
void from_json(const nlohmann::json &jsonObject, ApplicationInfo &applicationInfo);
void to_json(nlohmann::json &jsonObject, const ApplicationInfo &applicationInfo);
void from_json(const nlohmann::json &jsonObject, Resource &resource);
void to_json(nlohmann::json &jsonObject, const Resource &resource);
void from_json(const nlohmann::json &jsonObject, HapModuleInfo &hapModuleInfo);
void to_json(nlohmann::json &jsonObject, const HapModuleInfo &hapModuleInfo);
void from_json(const nlohmann::json &jsonObject, ProxyData &proxyData);
void to_json(nlohmann::json &jsonObject, const ProxyData &proxyData);
void from_json(const nlohmann::json &jsonObject, Dependency &dependency);
void to_json(nlohmann::json &jsonObject, const Dependency &dependency);
void from_json(const nlohmann::json &jsonObject, PreloadItem &preloadItem);
void to_json(nlohmann::json &jsonObject, const PreloadItem &preloadItem);
void from_json(const nlohmann::json &jsonObject, ModuleInfo &moduleInfo);
void to_json(nlohmann::json &jsonObject, const ModuleInfo &moduleInfo);
void from_json(const nlohmann::json &jsonObject, ExtensionAbilityInfo &extensionInfo);
void to_json(nlohmann::json &jsonObject, const ExtensionAbilityInfo &extensionInfo);
void from_json(const nlohmann::json &jsonObject, HnpPackage &hnpPackage);
void to_json(nlohmann::json &jsonObject, const HnpPackage &hnpPackage);
void from_json(const nlohmann::json &jsonObject, MultiAppModeData &multiAppMode);
void to_json(nlohmann::json &jsonObject, const MultiAppModeData &multiAppMode);
void from_json(const nlohmann::json &jsonObject, ApplicationEnvironment &applicationEnvironment);
void to_json(nlohmann::json &jsonObject, const ApplicationEnvironment &applicationEnvironment);
void from_json(const nlohmann::json &jsonObject, HqfInfo &hqfInfo);
void to_json(nlohmann::json &jsonObject, const HqfInfo &hqfInfo);
void from_json(const nlohmann::json &jsonObject, AppqfInfo &appqfInfo);
void to_json(nlohmann::json &jsonObject, const AppqfInfo &appqfInfo);
void from_json(const nlohmann::json &jsonObject, AppQuickFix &appQuickFix);
void to_json(nlohmann::json &jsonObject, const AppQuickFix &appQuickFix);
void from_json(const nlohmann::json &jsonObject, StartWindowResource &startWindowResource);
void to_json(nlohmann::json &jsonObject, const StartWindowResource &startWindowResource);
void from_json(const nlohmann::json &jsonObject, OverlayModuleInfo &overlayModuleInfo);
void to_json(nlohmann::json &jsonObject, const OverlayModuleInfo &overlayModuleInfo);
void from_json(const nlohmann::json &jsonObject, RouterItem &routerItem);
void to_json(nlohmann::json &jsonObject, const RouterItem &routerItem);
void from_json(const nlohmann::json &jsonObject, AppEnvironment &appEnvironment);
void to_json(nlohmann::json &jsonObject, const AppEnvironment &appEnvironment);
void to_json(nlohmann::json &jsonObject, const BundleInfo &bundleInfo);
void from_json(const nlohmann::json &jsonObject, BundleInfo &bundleInfo);
void to_json(nlohmann::json &jsonObject, const OverlayBundleInfo &overlayBundleInfo);
void from_json(const nlohmann::json &jsonObject, OverlayBundleInfo &overlayBundleInfo);
void to_json(nlohmann::json &jsonObject, const RequestPermissionUsedScene &usedScene);
void from_json(const nlohmann::json &jsonObject, RequestPermissionUsedScene &usedScene);
void to_json(nlohmann::json &jsonObject, const RequestPermission &requestPermission);
void from_json(const nlohmann::json &jsonObject, RequestPermission &requestPermission);
void to_json(nlohmann::json &jsonObject, const SignatureInfo &signatureInfo);
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_SIMULATOR_JSON_SERIALIZER_H
