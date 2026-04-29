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

#include "sub_command_info.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace CliTool {

bool SubCommandInfo::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteString(description)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to write description");
        return false;
    }
    if (!parcel.WriteStringVector(requirePermissions)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to write requirePermissions");
        return false;
    }
    if (!parcel.WriteString(inputSchema)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to write inputSchema");
        return false;
    }
    if (!parcel.WriteString(outputSchema)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to write outputSchema");
        return false;
    }
    if (!parcel.WriteBool(argMapping != nullptr)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to write hasArgMapping flag");
        return false;
    }
    if (argMapping != nullptr && !argMapping->Marshalling(parcel)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to write argMapping");
        return false;
    }
    if (!parcel.WriteStringVector(eventTypes)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to write eventTypes");
        return false;
    }
    if (!parcel.WriteString(eventSchemas)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to write eventSchemas");
        return false;
    }
    return true;
}

SubCommandInfo *SubCommandInfo::Unmarshalling(Parcel &parcel)
{
    auto *subCmd = new (std::nothrow) SubCommandInfo();
    if (subCmd == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to allocate SubCommandInfo");
        return nullptr;
    }

    bool hasArgMapping = false;
    if (!parcel.ReadString(subCmd->description)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to read description");
        delete subCmd;
        return nullptr;
    }
    if (!parcel.ReadStringVector(&subCmd->requirePermissions)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to read requirePermissions");
        delete subCmd;
        return nullptr;
    }
    if (!parcel.ReadString(subCmd->inputSchema)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to read inputSchema");
        delete subCmd;
        return nullptr;
    }
    if (!parcel.ReadString(subCmd->outputSchema)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to read outputSchema");
        delete subCmd;
        return nullptr;
    }
    if (!parcel.ReadBool(hasArgMapping)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to read hasArgMapping flag");
        delete subCmd;
        return nullptr;
    }

    if (hasArgMapping) {
        subCmd->argMapping.reset(ArgMapping::Unmarshalling(parcel));
        if (subCmd->argMapping == nullptr) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to unmarshal argMapping");
            delete subCmd;
            return nullptr;
        }
    }

    if (!parcel.ReadStringVector(&subCmd->eventTypes)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to read eventTypes");
        delete subCmd;
        return nullptr;
    }
    if (!parcel.ReadString(subCmd->eventSchemas)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to read eventSchemas");
        delete subCmd;
        return nullptr;
    }

    return subCmd;
}

bool SubCommandInfo::ParseFromJson(const nlohmann::json &json, SubCommandInfo &subCmd)
{
    // description is required and must be non-empty
    if (!json.contains("description") || !json["description"].is_string()) {
        return false;
    }
    std::string description = json["description"];
    if (description.empty()) {
        return false;
    }
    subCmd.description = description;

    // requirePermissions is optional, but if present must be array of strings
    if (json.contains("requirePermissions")) {
        if (!json["requirePermissions"].is_array()) {
            return false;
        }
        for (const auto &perm : json["requirePermissions"]) {
            if (!perm.is_string()) {
                return false;
            }
            std::string permStr = perm;
            if (!permStr.empty()) {
                subCmd.requirePermissions.push_back(std::move(permStr));
            }
        }
    }

    // inputSchema is required and must be JSON object
    if (!json.contains("inputSchema") || !json["inputSchema"].is_object()) {
        return false;
    }
    subCmd.inputSchema = json["inputSchema"].dump();

    // outputSchema is required and must be JSON object
    if (!json.contains("outputSchema") || !json["outputSchema"].is_object()) {
        return false;
    }
    subCmd.outputSchema = json["outputSchema"].dump();

    // argMapping is required
    if (!json.contains("argMapping") || !json["argMapping"].is_object()) {
        return false;
    }
    subCmd.argMapping = std::make_shared<ArgMapping>();
    if (!ArgMapping::ParseFromJson(json["argMapping"], *subCmd.argMapping)) {
        subCmd.argMapping = nullptr;
        return false;  // argMapping parse failed
    }

    // eventTypes is optional, but if present must be array of strings
    if (json.contains("eventTypes")) {
        if (!json["eventTypes"].is_array()) {
            return false;
        }
        for (const auto &evt : json["eventTypes"]) {
            if (!evt.is_string()) {
                return false;
            }
            std::string evtStr = evt;
            if (!evtStr.empty()) {
                subCmd.eventTypes.push_back(std::move(evtStr));
            }
        }
    }

    // eventSchemas is optional, but if present must be JSON object
    if (json.contains("eventSchemas")) {
        if (!json["eventSchemas"].is_object()) {
            return false;
        }
        subCmd.eventSchemas = json["eventSchemas"].dump();
    }

    return true;
}

nlohmann::json SubCommandInfo::ParseToJson() const
{
    nlohmann::json json;

    json["description"] = description;
    json["requirePermissions"] = requirePermissions;
    if (!inputSchema.empty()) {
        nlohmann::json inputSchemaJson = nlohmann::json::parse(inputSchema, nullptr, false);
        if (!inputSchemaJson.is_discarded()) {
            json["inputSchema"] = inputSchemaJson;
        } else {
            json["inputSchema"] = inputSchema;
        }
    }
    if (!outputSchema.empty()) {
        nlohmann::json outputSchemaJson = nlohmann::json::parse(outputSchema, nullptr, false);
        if (!outputSchemaJson.is_discarded()) {
            json["outputSchema"] = outputSchemaJson;
        } else {
            json["outputSchema"] = outputSchema;
        }
    }
    json["eventTypes"] = eventTypes;
    if (!eventSchemas.empty()) {
        nlohmann::json eventSchemasJson = nlohmann::json::parse(eventSchemas, nullptr, false);
        if (!eventSchemasJson.is_discarded()) {
            json["eventSchemas"] = eventSchemasJson;
        } else {
            json["eventSchemas"] = eventSchemas;
        }
    }
    if (argMapping != nullptr) {
        json["argMapping"] = argMapping->ParseToJson();
    }

    return json;
}

bool SubCommandInfo::Validate(const SubCommandInfo &subCmd)
{
    // description is required and must be non-empty
    if (subCmd.description.empty()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Validate failed: description is empty");
        return false;
    }

    // inputSchema is required and must be valid JSON object
    if (subCmd.inputSchema.empty()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Validate failed: inputSchema is empty");
        return false;
    }
    nlohmann::json inputSchemaJson = nlohmann::json::parse(subCmd.inputSchema, nullptr, false);
    if (inputSchemaJson.is_discarded() || !inputSchemaJson.is_object()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Validate failed: inputSchema is not a valid JSON object");
        return false;
    }

    // outputSchema is required and must be valid JSON object
    if (subCmd.outputSchema.empty()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Validate failed: outputSchema is empty");
        return false;
    }
    nlohmann::json outputSchemaJson = nlohmann::json::parse(subCmd.outputSchema, nullptr, false);
    if (outputSchemaJson.is_discarded() || !outputSchemaJson.is_object()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Validate failed: outputSchema is not a valid JSON object");
        return false;
    }

    // argMapping is required
    if (subCmd.argMapping == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Validate failed: argMapping is null");
        return false;
    }
    if (!ArgMapping::Validate(*subCmd.argMapping)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Validate failed: argMapping validation failed");
        return false;
    }

    // eventSchemas: if not empty, must be valid JSON object
    if (!subCmd.eventSchemas.empty()) {
        nlohmann::json eventSchemasJson = nlohmann::json::parse(subCmd.eventSchemas, nullptr, false);
        if (eventSchemasJson.is_discarded() || !eventSchemasJson.is_object()) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Validate failed: eventSchemas is not a valid JSON object");
            return false;
        }
    }

    return true;
}

} // namespace CliTool
} // namespace OHOS
