/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_SIMULATOR_JSON_UTIL_H
#define OHOS_ABILITY_RUNTIME_SIMULATOR_JSON_UTIL_H

#include <string>

#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "hilog_tag_wrapper.h"
#include "json_serializer.h"

namespace OHOS {
namespace AppExecFwk {
enum class JsonType {
    NULLABLE,
    BOOLEAN,
    NUMBER,
    OBJECT,
    ARRAY,
    STRING,
};

enum class ArrayType {
    NUMBER,
    OBJECT,
    STRING,
    NOT_ARRAY,
};

class JsonUtil {
public:
    static bool CheckArrayValueType(const nlohmann::json &value, ArrayType arrayType);
    static bool CheckMapValueType(const nlohmann::json &value, JsonType valueType, ArrayType arrayType);
};

template<typename T, typename dataType>
void CheckArrayType(
    const nlohmann::json &jsonObject, const std::string &key, dataType &data, ArrayType arrayType, int32_t &parseResult)
{
    auto arrays = jsonObject.at(key);
    if (arrays.empty()) {
        return;
    }
    if (arrays.size() > Constants::MAX_JSON_ARRAY_LENGTH) {
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR;
        return;
    }
    switch (arrayType) {
        case ArrayType::STRING:
            for (const auto &array : arrays) {
                if (!array.is_string()) {
                    TAG_LOGD(AAFwkTag::ABILITY_SIM, "array %{public}s not string", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                }
            }
            if (parseResult == ERR_OK) {
                data = jsonObject.at(key).get<T>();
            }
            break;
        case ArrayType::OBJECT:
            for (const auto &array : arrays) {
                if (!array.is_object()) {
                    TAG_LOGD(AAFwkTag::ABILITY_SIM, "array %{public}s not object", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                    break;
                }
            }
            if (parseResult == ERR_OK) {
                data = jsonObject.at(key).get<T>();
            }
            break;
        case ArrayType::NUMBER:
            for (const auto &array : arrays) {
                if (!array.is_number()) {
                    TAG_LOGD(AAFwkTag::ABILITY_SIM, "array %{public}s not number", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                }
            }
            if (parseResult == ERR_OK) {
                data = jsonObject.at(key).get<T>();
            }
            break;
        case ArrayType::NOT_ARRAY:
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "array %{public}s not string", key.c_str());
            break;
        default:
            TAG_LOGD(AAFwkTag::ABILITY_SIM, "array %{public}s type error", key.c_str());
            break;
    }
}

template<typename T, typename dataType>
void GetValueIfFindKey(const nlohmann::json &jsonObject, const nlohmann::detail::iter_impl<const nlohmann::json> &end,
    const std::string &key, dataType &data, JsonType jsonType, bool isNecessary, int32_t &parseResult,
    ArrayType arrayType)
{
    if (parseResult) {
        return;
    }
    if (jsonObject.find(key) != end) {
        switch (jsonType) {
            case JsonType::BOOLEAN:
                if (!jsonObject.at(key).is_boolean()) {
                    TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not bool", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                    break;
                }
                data = jsonObject.at(key).get<T>();
                break;
            case JsonType::NUMBER:
                if (!jsonObject.at(key).is_number()) {
                    TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not number", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                    break;
                }
                data = jsonObject.at(key).get<T>();
                break;
            case JsonType::OBJECT:
                if (!jsonObject.at(key).is_object()) {
                    TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not object", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                    break;
                }
                data = jsonObject.at(key).get<T>();
                break;
            case JsonType::ARRAY:
                if (!jsonObject.at(key).is_array()) {
                    TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not array", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                    break;
                }
                CheckArrayType<T>(jsonObject, key, data, arrayType, parseResult);
                break;
            case JsonType::STRING:
                if (!jsonObject.at(key).is_string()) {
                    TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not string", key.c_str());
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                    break;
                }
                data = jsonObject.at(key).get<T>();
                if (jsonObject.at(key).get<std::string>().length() > Constants::MAX_JSON_ELEMENT_LENGTH) {
                    parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_SIZE_CHECK_ERROR;
                }
                break;
            case JsonType::NULLABLE:
                TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s is nullable", key.c_str());
                break;
            default:
                TAG_LOGD(AAFwkTag::ABILITY_SIM, "type:%{public}s not jsonType", key.c_str());
                parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
        }
        return;
    }
    if (isNecessary) {
        TAG_LOGD(AAFwkTag::ABILITY_SIM, "profile prop %{public}s is mission", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
    }
}

template<typename T>
const std::string GetJsonStrFromInfo(T &t)
{
    nlohmann::json json = t;
    return json.dump();
}

/**
 * @brief Retrieves a map value from a JSON object if the specified key exists, with type validation.
 * @param valueType The expected type of map values.
 *                  Supported types: [BOOLEAN, NUMBER, STRING, ARRAY]. Returns an error if the type is not supported.
 * @param arrayType If valueType is ARRAY, specifies the expected type of array items.
 *                  Supported types: [NUMBER, STRING]. Returns an error if the type is not supported.
 */
template<typename T, typename dataType>
void GetMapValueIfFindKey(const nlohmann::json &jsonObject,
    const nlohmann::detail::iter_impl<const nlohmann::json> &end, const std::string &key, dataType &data,
    bool isNecessary, int32_t &parseResult, JsonType valueType, ArrayType arrayType)
{
    if (parseResult != ERR_OK) {
        return;
    }
    if (jsonObject.find(key) != end) {
        if (!jsonObject.at(key).is_object()) {
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "type error %{public}s not map object", key.c_str());
            parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
            return;
        }
        for (const auto& [mapKey, mapValue] : jsonObject.at(key).items()) {
            if (!JsonUtil::CheckMapValueType(mapValue, valueType, arrayType)) {
                TAG_LOGE(AAFwkTag::ABILITY_SIM, "type error key:%{public}s", mapKey.c_str());
                parseResult = ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR;
                return;
            }
        }
        data = jsonObject.at(key).get<T>();
        return;
    }
    if (isNecessary) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "profile prop %{public}s missing", key.c_str());
        parseResult = ERR_APPEXECFWK_PARSE_PROFILE_MISSING_PROP;
    }
}
} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_SIMULATOR_JSON_UTIL_H