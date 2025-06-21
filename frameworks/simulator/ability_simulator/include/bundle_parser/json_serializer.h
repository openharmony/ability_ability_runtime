/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "cJSON.h"
#include "extension_ability_info.h"
#include "hap_module_info.h"
#include "module_info.h"

namespace OHOS {
namespace AppExecFwk {
/*
 * form_json and to_json is global static overload method, which need callback by json library,
 * and can not rename this function, so don't named according UpperCamelCase style
 */
bool to_json(cJSON *&jsonObject, const std::string &value);
bool to_json(cJSON *&jsonObject, const bool &value);
bool to_json(cJSON *&jsonObject, const OHOS::AppExecFwk::SupportWindowMode &value);

template<typename T>
bool to_json(cJSON *&jsonObject, const std::vector<T> &values)
{
    jsonObject = cJSON_CreateArray();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json array failed");
        return false;
    }
    for (auto& value : values) {
        cJSON *valueItem = nullptr;
        if (!to_json(valueItem, value)) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json failed");
            cJSON_Delete(jsonObject);
            return false;
        }
        cJSON_AddItemToArray(jsonObject, valueItem);
    }
    return true;
}

template<typename T>
bool to_json(cJSON *&jsonObject, const std::unordered_set<T> &values)
{
    jsonObject = cJSON_CreateArray();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json array failed");
        return false;
    }
    for (auto& value : values) {
        cJSON *valueItem = nullptr;
        if (!to_json(valueItem, value)) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "to_json failed");
            cJSON_Delete(jsonObject);
            return false;
        }
        cJSON_AddItemToArray(jsonObject, valueItem);
    }
    return true;
}

template<typename T>
bool to_json(cJSON *&jsonObject, const std::map<std::string, T> &valueMap)
{
    jsonObject = cJSON_CreateArray();
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json array failed");
        return false;
    }
    for (const auto& [key, values] : valueMap) {
        cJSON *valuesObject = cJSON_CreateObject();
        cJSON *valuesItem = nullptr;
        if (!to_json(valuesItem, values)) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "create json array failed");
            return false;
        }
        cJSON_AddItemToObject(valuesObject, key.c_str(), valuesObject);
        cJSON_AddItemToArray(jsonObject, valuesObject);
    }
    return true;
}

void from_json(const cJSON *jsonObject, std::string &value);

void from_json(const cJSON *jsonObject, bool &value);

template<typename T>
void from_json(const cJSON *jsonObject, std::vector<T> &values)
{
    if (jsonObject == nullptr || !cJSON_IsArray(jsonObject)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "type not array");
        return;
    }
    int size = cJSON_GetArraySize(jsonObject);
    for (int i = 0; i < size; i++) {
        cJSON *valueItem = cJSON_GetArrayItem(jsonObject, i);
        if (valueItem != nullptr) {
            T value;
            from_json(valueItem, value);
            values.push_back(value);
        }
    }
}

template<typename T>
void from_json(const cJSON *jsonObject, std::unordered_set<T> &values)
{
    if (jsonObject == nullptr || !cJSON_IsArray(jsonObject)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "type not array");
        return;
    }
    int size = cJSON_GetArraySize(jsonObject);
    for (int i = 0; i < size; i++) {
        cJSON *valueItem = cJSON_GetArrayItem(jsonObject, i);
        if (valueItem != nullptr) {
            T value;
            from_json(valueItem, value);
            values.emplace(value);
        }
    }
}

// ability_info
bool to_json(cJSON *&jsonObject, const CustomizeData &customizeData);
bool to_json(cJSON *&jsonObject, const MetaData &metaData);
bool to_json(cJSON *&jsonObject, const Metadata &metadata);
bool to_json(cJSON *&jsonObject, const StartWindowResource &startWindowResource);
bool to_json(cJSON *&jsonObject, const AbilityInfo &abilityInfo);

void from_json(const cJSON *jsonObject, CustomizeData &customizeData);
void from_json(const cJSON *jsonObject, MetaData &metaData);
void from_json(const cJSON *jsonObject, Metadata &metadata);
void from_json(const cJSON *jsonObject, StartWindowResource &startWindowResource);
void from_json(const cJSON *jsonObject, AbilityInfo &abilityInfo);

// application_info
bool to_json(cJSON *&jsonObject, const Resource &resource);
bool to_json(cJSON *&jsonObject, const HnpPackage &hnpPackage);
bool to_json(cJSON *&jsonObject, const MultiAppModeData &multiAppMode);
bool to_json(cJSON *&jsonObject, const ApplicationEnvironment &applicationEnvironment);
bool to_json(cJSON *&jsonObject, const HqfInfo &hqfInfo);
bool to_json(cJSON *&jsonObject, const AppqfInfo &appqfInfo);
bool to_json(cJSON *&jsonObject, const AppQuickFix &appQuickFix);
bool to_json(cJSON *&jsonObject, const ApplicationInfo &applicationInfo);

void from_json(const cJSON *jsonObject, Resource &resource);
void from_json(const cJSON *jsonObject, HnpPackage &hnpPackage);
void from_json(const cJSON *jsonObject, MultiAppModeData &multiAppMode);
void from_json(const cJSON *jsonObject, ApplicationEnvironment &applicationEnvironment);
void from_json(const cJSON *jsonObject, HqfInfo &hqfInfo);
void from_json(const cJSON *jsonObject, AppqfInfo &appqfInfo);
void from_json(const cJSON *jsonObject, AppQuickFix &appQuickFix);
void from_json(const cJSON *jsonObject, ApplicationInfo &applicationInfo);

// extension_ability_info
bool to_json(cJSON *&jsonObject, const ExtensionAbilityInfo &extensionInfo);

void from_json(const cJSON *jsonObject, ExtensionAbilityInfo &extensionInfo);

// inner_bundle_info
bool to_json(cJSON *&jsonObject, const Dependency &dependency);

void from_json(const cJSON *jsonObject, Dependency &dependency);

// module_info
bool to_json(cJSON *&jsonObject, const ModuleInfo &moduleInfo);

void from_json(const cJSON *jsonObject, ModuleInfo &moduleInfo);

// hap_module_info
bool to_json(cJSON *&jsonObject, const PreloadItem &preloadItem);
bool to_json(cJSON *&jsonObject, const ProxyData &proxyData);
bool to_json(cJSON *&jsonObject, const OverlayModuleInfo &overlayModuleInfo);
bool to_json(cJSON *&jsonObject, const RouterItem &routerItem);
bool to_json(cJSON *&jsonObject, const AppEnvironment &appEnvironment);
bool to_json(cJSON *&jsonObject, const HapModuleInfo &hapModuleInfo);

void from_json(const cJSON *jsonObject, PreloadItem &preloadItem);
void from_json(const cJSON *jsonObject, ProxyData &proxyData);
void from_json(const cJSON *jsonObject, OverlayModuleInfo &overlayModuleInfo);
void from_json(const cJSON *jsonObject, RouterItem &routerItem);
void from_json(const cJSON *jsonObject, AppEnvironment &appEnvironment);
void from_json(const cJSON *jsonObject, HapModuleInfo &hapModuleInfo);

// bundle_info
bool to_json(cJSON *&jsonObject, const RequestPermissionUsedScene &usedScene);
bool to_json(cJSON *&jsonObject, const RequestPermission &requestPermission);
bool to_json(cJSON *&jsonObject, const SignatureInfo &signatureInfo);
bool to_json(cJSON *&jsonObject, const BundleInfo &bundleInfo);

void from_json(const cJSON *jsonObject, RequestPermissionUsedScene &usedScene);
void from_json(const cJSON *jsonObject, RequestPermission &requestPermission);
void from_json(const cJSON *jsonObject, SignatureInfo &signatureInfo);
void from_json(const cJSON *jsonObject, BundleInfo &bundleInfo);

// overlay_bundle_info
bool to_json(cJSON *&jsonObject, const OverlayBundleInfo &overlayBundleInfo);

void from_json(const cJSON *jsonObject, OverlayBundleInfo &overlayBundleInfo);

} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_SIMULATOR_JSON_SERIALIZER_H
