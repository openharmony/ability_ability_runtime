/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

#ifndef OHOS_ABILITY_RUNTIME_ARG_MAPPING_H
#define OHOS_ABILITY_RUNTIME_ARG_MAPPING_H

#include <memory>
#include <nlohmann/json.hpp>
#include <parcel.h>
#include <string>

namespace OHOS {
namespace CliTool {

/**
 * @brief Enum for argument mapping type
 */
enum class ArgMappingType {
    FLAG = 0,
    POSITIONAL = 1,
    FLATTENED = 2,
    JSONSTRING = 3,
    MIXED = 4
};

/**
 * @brief Argument mapping structure
 */
class ArgMapping : public Parcelable {
public:
    ArgMappingType type = ArgMappingType::FLAG;
    std::string separator;
    std::string order;
    std::string templates;      // JSON string

    ArgMapping() = default;
    ~ArgMapping() = default;

    bool Marshalling(Parcel &parcel) const override;
    static ArgMapping *Unmarshalling(Parcel &parcel);

    /**
     * @brief Parse ArgMapping from JSON object
     */
    static std::shared_ptr<ArgMapping> ParseFromJson(const nlohmann::json &json);

    /**
     * @brief Convert ArgMapping to JSON object
     */
    nlohmann::json ParseToJson() const;
};

} // namespace CliTool
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_ARG_MAPPING_H