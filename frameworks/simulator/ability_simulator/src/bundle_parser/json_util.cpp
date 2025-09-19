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
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
bool JsonUtil::CheckArrayValueType(const nlohmann::json &value, ArrayType arrayType)
{
    if (!value.is_array()) {
        TAG_LOGE(AAFwkTag::ABILITY_SIM, "not array");
        return false;
    }
    switch (arrayType) {
        case ArrayType::NUMBER:
            for (const auto &item : value) {
                if (!item.is_number()) {
                    TAG_LOGE(AAFwkTag::ABILITY_SIM, "array item not number");
                    return false;
                }
            }
            return true;
        case ArrayType::STRING:
            for (const auto &item : value) {
                if (!item.is_string()) {
                    TAG_LOGE(AAFwkTag::ABILITY_SIM, "array item not string");
                    return false;
                }
            }
            return true;
        default:
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "not support arrayType: %{public}d", static_cast<int32_t>(arrayType));
            return false;
    }
}

bool JsonUtil::CheckMapValueType(const nlohmann::json &value, JsonType valueType, ArrayType arrayType)
{
    switch (valueType) {
        case JsonType::BOOLEAN:
            return value.is_boolean();
        case JsonType::NUMBER:
            return value.is_number();
        case JsonType::STRING:
            return value.is_string();
        case JsonType::ARRAY:
            return CheckArrayValueType(value, arrayType);
        default:
            TAG_LOGE(AAFwkTag::ABILITY_SIM, "not support valueType: %{public}d", static_cast<int32_t>(valueType));
            return false;
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS