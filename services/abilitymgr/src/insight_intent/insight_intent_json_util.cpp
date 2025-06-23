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

#include "insight_intent_json_util.h"

namespace OHOS {
namespace AbilityRuntime {

bool to_json(cJSON *&jsonObject, const std::string &value)
{
    jsonObject = cJSON_CreateString(value.c_str());
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create string json failed");
        return false;
    }
    return true;
}

bool to_json(cJSON *&jsonObject, const int &value)
{
    jsonObject = cJSON_CreateNumber(static_cast<double>(value));
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create number json failed");
        return false;
    }
    return true;
}

bool to_json(cJSON *&jsonObject, const bool &value)
{
    jsonObject = cJSON_CreateBool(value);
    if (jsonObject == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "create bool json failed");
        return false;
    }
    return true;
}

void from_json(const cJSON *jsonObject, std::string &value)
{
    if (jsonObject == nullptr || !cJSON_IsString(jsonObject)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "type not string");
        return;
    }
    value = jsonObject->valuestring;
}

void from_json(const cJSON *jsonObject, int &value)
{
    if (jsonObject == nullptr || !cJSON_IsNumber(jsonObject)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "type not string");
        return;
    }
    value = static_cast<int>(jsonObject->valuedouble);
}

void from_json(const cJSON *jsonObject, bool &value)
{
    if (jsonObject == nullptr || !cJSON_IsBool(jsonObject)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "type not bool");
        return;
    }
    value = jsonObject->type == cJSON_True;
}

void GetStringValueIfFindKey(const cJSON *jsonObject,
    const std::string &key, std::string &data,
    bool isNecessary, int32_t &parseResult)
{
    if (parseResult) {
        return;
    }
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item == nullptr) {
        if (isNecessary) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "profile prop %{public}s is mission", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
        }
        return;
    }
    if (!cJSON_IsString(item)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "type:%{public}s not string", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        return;
    }
    data = item->valuestring;
}

void GetStringValuesIfFindKey(const cJSON *jsonObject,
    const std::string &key, std::vector<std::string> &data,
    bool isNecessary, int32_t &parseResult)
{
    if (parseResult) {
        return;
    }
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item == nullptr) {
        if (isNecessary) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "profile prop %{public}s is mission", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
        }
        return;
    }
    if (!cJSON_IsArray(item)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "type:%{public}s not array", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        return;
    }
    int size = cJSON_GetArraySize(item);
    for (int i = 0; i < size; i++) {
        cJSON *childItem = cJSON_GetArrayItem(item, i);
        if (childItem == nullptr || !cJSON_IsString(childItem)) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "type:%{public}s not string list", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            return;
        }
        std::string value = childItem->valuestring;
        data.push_back(value);
    }
}

void GetBoolValueIfFindKey(const cJSON *jsonObject,
    const std::string &key, bool &data,
    bool isNecessary, int32_t &parseResult)
{
    if (parseResult) {
        return;
    }
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item == nullptr) {
        if (isNecessary) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "profile prop %{public}s is mission", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
        }
        return;
    }
    if (!cJSON_IsBool(item)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "type:%{public}s not bool", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        return;
    }
    data = item->type == cJSON_True;
}

void GetBoolValuesIfFindKey(const cJSON *jsonObject,
    const std::string &key, std::vector<bool> &data,
    bool isNecessary, int32_t &parseResult)
{
    if (parseResult) {
        return;
    }
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item == nullptr) {
        if (isNecessary) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "profile prop %{public}s is mission", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
        }
        return;
    }
    if (!cJSON_IsArray(item)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "type:%{public}s not array", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        return;
    }
    int size = cJSON_GetArraySize(item);
    for (int i = 0; i < size; i++) {
        cJSON *childItem = cJSON_GetArrayItem(item, i);
        if (childItem == nullptr || !cJSON_IsBool(childItem)) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "type:%{public}s not bool list", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            return;
        }
        bool value = childItem->type == cJSON_True;
        data.push_back(value);
    }
}

void GetBoolValueMapIfFindKey(const cJSON *jsonObject,
    const std::string &key, std::map<std::string, bool> &data,
    bool isNecessary, int32_t &parseResult)
{
    if (parseResult) {
        return;
    }
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item == nullptr) {
        if (isNecessary) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "profile prop %{public}s is mission", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
        }
        return;
    }
    if (!cJSON_IsArray(item)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "type:%{public}s not array", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        return;
    }
    int size = cJSON_GetArraySize(item);
    for (int i = 0; i < size; i++) {
        cJSON *childItem = cJSON_GetArrayItem(item, i);
        if (childItem == nullptr || !cJSON_IsBool(childItem)) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "type:%{public}s not bool list", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            return;
        }
        std::string key = childItem->string == nullptr ? "" : childItem->string;
        bool value = childItem->type == cJSON_True;
        data.emplace(key, value);
    }
}

void GetBoolValuesMapIfFindKey(const cJSON *jsonObject,
    const std::string &key, std::map<std::string, std::vector<bool>> &data,
    bool isNecessary, int32_t &parseResult)
{
    if (parseResult) {
        return;
    }
    cJSON *item = cJSON_GetObjectItem(jsonObject, key.c_str());
    if (item == nullptr) {
        if (isNecessary) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "profile prop %{public}s is mission", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
        }
        return;
    }
    if (!cJSON_IsArray(item)) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "type:%{public}s not array", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        return;
    }
    int size = cJSON_GetArraySize(item);
    for (int i = 0; i < size; i++) {
        cJSON *childItem = cJSON_GetArrayItem(item, i);
        if (childItem == nullptr || !cJSON_IsBool(childItem)) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "type:%{public}s not bool list", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            return;
        }
        std::string key = childItem->string == nullptr ? "" : childItem->string;
        std::vector<bool> value;
        from_json(childItem, value);
        data.emplace(key, value);
    }
}
} // namespace AppExecFwk
} // namespace OHOS