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

#include "arg_mapping.h"

namespace OHOS {
namespace CliTool {

bool ArgMapping::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteInt32(static_cast<int32_t>(type))) {
        return false;
    }
    if (!parcel.WriteString(separator)) {
        return false;
    }
    if (!parcel.WriteString(order)) {
        return false;
    }
    if (!parcel.WriteString(templates)) {
        return false;
    }
    return true;
}

ArgMapping *ArgMapping::Unmarshalling(Parcel &parcel)
{
    auto mapping = std::make_unique<ArgMapping>();

    int32_t typeValue = 0;
    if (!parcel.ReadInt32(typeValue)) {
        return nullptr;
    }
    if (!parcel.ReadString(mapping->separator)) {
        return nullptr;
    }
    if (!parcel.ReadString(mapping->order)) {
        return nullptr;
    }
    if (!parcel.ReadString(mapping->templates)) {
        return nullptr;
    }

    mapping->type = static_cast<ArgMappingType>(typeValue);
    return mapping.release();
}

std::shared_ptr<ArgMapping> ArgMapping::ParseFromJson(const nlohmann::json &json)
{
    auto argMapping = std::make_shared<ArgMapping>();
    if (json.contains("type") && json["type"].is_string()) {
        std::string typeStr = json["type"];
        if (typeStr == "flag") {
            argMapping->type = ArgMappingType::FLAG;
        } else if (typeStr == "positional") {
            argMapping->type = ArgMappingType::POSITIONAL;
        } else if (typeStr == "flattened") {
            argMapping->type = ArgMappingType::FLATTENED;
        } else if (typeStr == "jsonString") {
            argMapping->type = ArgMappingType::JSONSTRING;
        } else if (typeStr == "mixed") {
            argMapping->type = ArgMappingType::MIXED;
        }
    }
    if (json.contains("separator") && json["separator"].is_string()) {
        argMapping->separator = json["separator"];
    }
    if (json.contains("order") && json["order"].is_string()) {
        argMapping->order = json["order"];
    }
    if (json.contains("templates") && json["templates"].is_object()) {
        argMapping->templates = json["templates"].dump();
    }
    return argMapping;
}

nlohmann::json ArgMapping::ParseToJson() const
{
    nlohmann::json j;
    switch (type) {
        case ArgMappingType::FLAG:
            j["type"] = "flag";
            break;
        case ArgMappingType::POSITIONAL:
            j["type"] = "positional";
            break;
        case ArgMappingType::FLATTENED:
            j["type"] = "flattened";
            break;
        case ArgMappingType::JSONSTRING:
            j["type"] = "jsonString";
            break;
        case ArgMappingType::MIXED:
            j["type"] = "mixed";
            break;
    }
    if (!separator.empty()) {
        j["separator"] = separator;
    }
    if (!order.empty()) {
        j["order"] = order;
    }
    if (!templates.empty()) {
        nlohmann::json templatesJson = nlohmann::json::parse(templates, nullptr, false);
        if (!templatesJson.is_discarded()) {
            j["templates"] = templatesJson;
        } else {
            j["templates"] = templates;
        }
    }
    return j;
}

} // namespace CliTool
} // namespace OHOS