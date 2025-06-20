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

#ifndef OHOS_ABILITY_RUNTIME_INSIGHT_INTENT_JSON_UTIL_H
#define OHOS_ABILITY_RUNTIME_INSIGHT_INTENT_JSON_UTIL_H

#include <map>
#include <string>
#include <vector>

#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "cJSON.h"
#include "hilog_tag_wrapper.h"
#include "json_serializer.h"

namespace OHOS {
namespace AbilityRuntime {

bool to_json(cJSON *&jsonObject, const std::string &value);
bool to_json(cJSON *&jsonObject, const int &value);
bool to_json(cJSON *&jsonObject, const bool &value);

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

void from_json(const cJSON *jsonObject, int &value);

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

void GetStringValueIfFindKey(const cJSON *jsonObject,
    const std::string &key, std::string &data,
    bool isNecessary, int32_t &parseResult);

void GetStringValuesIfFindKey(const cJSON *jsonObject,
    const std::string &key, std::vector<std::string> &data,
    bool isNecessary, int32_t &parseResult);

template<typename T>
void GetNumberValueIfFindKey(const cJSON *jsonObject,
    const std::string &key, T &data,
    bool isNecessary, int32_t &parseResult)
{
    if (parseResult) {
        return;
    }
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item == nullptr) {
        if (isNecessary) {
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "profile prop %{public}s is mission", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
        }
        return;
    }
    if (!cJSON_IsNumber(item)) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not number", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        return;
    }
    data = static_cast<T>(item->valuedouble);
}

template<typename T>
void GetNumberValuesIfFindKey(const cJSON *jsonObject,
    const std::string &key, std::vector<T> &data,
    bool isNecessary, int32_t &parseResult)
{
    if (parseResult) {
        return;
    }
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item == nullptr) {
        if (isNecessary) {
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "profile prop %{public}s is mission", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
        }
        return;
    }
    if (!cJSON_IsArray(item)) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not array", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        return;
    }
    int size = cJSON_GetArraySize(item);
    for (int i = 0; i < size; i++) {
        cJSON *childItem = cJSON_GetArrayItem(item, i);
        if (childItem == nullptr || !cJSON_IsNumber(childItem)) {
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not number list", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            return;
        }
        T value = static_cast<T>(childItem->valuedouble);
        data.push_back(value);
    }
}

void GetBoolValueIfFindKey(const cJSON *jsonObject,
    const std::string &key, bool &data,
    bool isNecessary, int32_t &parseResult);

void GetBoolValuesIfFindKey(const cJSON *jsonObject,
    const std::string &key, std::vector<bool> &data,
    bool isNecessary, int32_t &parseResult);

void GetBoolValueMapIfFindKey(const cJSON *jsonObject,
    const std::string &key, std::map<std::string, bool> &data,
    bool isNecessary, int32_t &parseResult);

void GetBoolValuesMapIfFindKey(const cJSON *jsonObject,
    const std::string &key, std::map<std::string, std::vector<bool>> &data,
    bool isNecessary, int32_t &parseResult);

template<typename T>
void GetObjectValueIfFindKey(const cJSON *jsonObject,
    const std::string &key, T &data,
    bool isNecessary, int32_t &parseResult)
{
    if (parseResult) {
        return;
    }
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item == nullptr) {
        if (isNecessary) {
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "profile prop %{public}s is mission", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
        }
        return;
    }
    if (!cJSON_IsObject(item)) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not object", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        return;
    }
    from_json(item, data);
}

template<typename T>
void GetObjectValuesIfFindKey(const cJSON *jsonObject,
    const std::string &key, std::vector<T> &data,
    bool isNecessary, int32_t &parseResult)
{
    if (parseResult) {
        return;
    }
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item == nullptr) {
        if (isNecessary) {
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "profile prop %{public}s is mission", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
        }
        return;
    }
    if (!cJSON_IsArray(item)) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not array", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        return;
    }
    int size = cJSON_GetArraySize(item);
    for (int i = 0; i < size; i++) {
        cJSON *childItem = cJSON_GetArrayItem(item, i);
        if (childItem == nullptr || !cJSON_IsObject(childItem)) {
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not object list", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            return;
        }
        T value;
        from_json(childItem, value);
        data.push_back(value);
    }
}

template<typename T>
void GetObjectValueMapIfFindKey(const cJSON *jsonObject,
    const std::string &key, std::map<std::string, T> &data,
    bool isNecessary, int32_t &parseResult)
{
    if (parseResult) {
        return;
    }
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item == nullptr) {
        if (isNecessary) {
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "profile prop %{public}s is mission", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
        }
        return;
    }
    if (!cJSON_IsArray(item)) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not array", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        return;
    }
    int size = cJSON_GetArraySize(item);
    for (int i = 0; i < size; i++) {
        cJSON *childItem = cJSON_GetArrayItem(item, i);
        if (childItem == nullptr || !cJSON_IsObject(childItem)) {
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not object list", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            return;
        }
        std::string key = childItem->string == nullptr ? "" : childItem->string;
        T value;
        from_json(childItem, value);
        data.emplace(key, value);
    }
}

template<typename T>
void GetObjectValuesMapIfFindKey(const cJSON *jsonObject,
    const std::string &key, std::map<std::string, std::vector<T>> &data,
    bool isNecessary, int32_t &parseResult)
{
    if (parseResult) {
        return;
    }
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item == nullptr) {
        if (isNecessary) {
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "profile prop %{public}s is mission", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
        }
        return;
    }
    if (!cJSON_IsArray(item)) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not array", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        return;
    }
    int size = cJSON_GetArraySize(item);
    for (int i = 0; i < size; i++) {
        cJSON *childItem = cJSON_GetArrayItem(item, i);
        if (childItem == nullptr || !cJSON_IsObject(childItem)) {
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not object list", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            return;
        }
        std::string key = childItem->string == nullptr ? "" : childItem->string;
        std::vector<T> value;
        from_json(childItem, value);
        data.emplace(key, value);
    }
}
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_INSIGHT_INTENT_JSON_UTIL_H