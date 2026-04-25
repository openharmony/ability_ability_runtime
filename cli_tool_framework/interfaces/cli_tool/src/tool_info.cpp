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

#include "tool_info.h"

#include <nlohmann/json.hpp>

namespace OHOS {
namespace CliTool {

// ToolInfo implementation
bool ToolInfo::Marshalling(Parcel &parcel) const
{
    // Serialize subcommands map to JSON string using SubCommandInfo::ParseToJson
    std::string subcommandsJson;
    if (!subcommands.empty()) {
        nlohmann::json j;
        for (const auto &pair : subcommands) {
            j[pair.first] = pair.second.ParseToJson();
        }
        subcommandsJson = j.dump();
    }

    return parcel.WriteString(name) &&
           parcel.WriteString(version) &&
           parcel.WriteString(description) &&
           parcel.WriteString(executablePath) &&
           parcel.WriteStringVector(requirePermissions) &&
           parcel.WriteString(inputSchema) &&
           parcel.WriteString(outputSchema) &&
           parcel.WriteBool(argMapping != nullptr) &&
           (argMapping == nullptr || argMapping->Marshalling(parcel)) &&
           parcel.WriteString(eventSchemas) &&
           parcel.WriteInt32(timeout) &&
           parcel.WriteStringVector(eventTypes) &&
           parcel.WriteBool(hasSubCommand) &&
           parcel.WriteString(subcommandsJson);
}

ToolInfo *ToolInfo::Unmarshalling(Parcel &parcel)
{
    auto *tool = new (std::nothrow) ToolInfo();
    if (tool == nullptr) {
        return nullptr;
    }

    bool hasArgMapping = false;
    std::string subcommandsJson;
    if (!parcel.ReadString(tool->name) ||
        !parcel.ReadString(tool->version) ||
        !parcel.ReadString(tool->description) ||
        !parcel.ReadString(tool->executablePath) ||
        !parcel.ReadStringVector(&tool->requirePermissions) ||
        !parcel.ReadString(tool->inputSchema) ||
        !parcel.ReadString(tool->outputSchema) ||
        !parcel.ReadBool(hasArgMapping)) {
        delete tool;
        return nullptr;
    }

    if (hasArgMapping) {
        tool->argMapping.reset(ArgMapping::Unmarshalling(parcel));
        if (tool->argMapping == nullptr) {
            delete tool;
            return nullptr;
        }
    }

    if (!parcel.ReadString(tool->eventSchemas) ||
        !parcel.ReadInt32(tool->timeout) ||
        !parcel.ReadStringVector(&tool->eventTypes) ||
        !parcel.ReadBool(tool->hasSubCommand) ||
        !parcel.ReadString(subcommandsJson)) {
        delete tool;
        return nullptr;
    }

    // Parse subcommands JSON string to map using SubCommandInfo::ParseFromJson
    if (!subcommandsJson.empty()) {
        nlohmann::json j = nlohmann::json::parse(subcommandsJson, nullptr, false);
        if (!j.is_discarded() && j.is_object()) {
            for (auto it = j.begin(); it != j.end(); ++it) {
                SubCommandInfo subCmd;
                if (!SubCommandInfo::ParseFromJson(it.value(), subCmd)) {
                    delete tool;
                    return nullptr;  // subcommand parse failed
                }
                tool->subcommands[it.key()] = std::move(subCmd);
            }
        }
    }

    return tool;
}

bool ToolInfo::ValidateName(const std::string &name)
{
    if (name.empty()) {
        return false;
    }

    // Must start with "ohos-" or "hms-"
    const std::string OHOS_PREFIX = "ohos-";
    const std::string HMS_PREFIX = "hms-";
    const size_t MAX_SUFFIX_LENGTH = 16;

    bool hasValidPrefix = false;
    size_t suffixStart = 0;

    if (name.compare(0, OHOS_PREFIX.size(), OHOS_PREFIX) == 0) {
        hasValidPrefix = true;
        suffixStart = OHOS_PREFIX.size();
    } else if (name.compare(0, HMS_PREFIX.size(), HMS_PREFIX) == 0) {
        hasValidPrefix = true;
        suffixStart = HMS_PREFIX.size();
    }

    if (!hasValidPrefix) {
        return false;
    }

    // Suffix must not exceed 16 characters
    std::string suffix = name.substr(suffixStart);
    if (suffix.empty() || suffix.size() > MAX_SUFFIX_LENGTH) {
        return false;
    }

    return true;
}

bool ToolInfo::ValidateExecutablePath(const std::string &path)
{
    if (path.empty()) {
        return false;
    }

    // Must be absolute path (start with '/')
    if (path[0] != '/') {
        return false;
    }

    return true;
}

bool ToolInfo::ParseFromJson(const nlohmann::json &json, ToolInfo &tool)
{
    // name is required and must be valid
    if (!json.contains("name") || !json["name"].is_string()) {
        return false;
    }

    std::string name = json["name"];
    if (!ValidateName(name)) {
        return false;
    }
    tool.name = name;

    // version is required and must be non-empty
    if (!json.contains("version") || !json["version"].is_string()) {
        return false;
    }
    std::string version = json["version"];
    if (version.empty()) {
        return false;
    }
    tool.version = version;

    // description is required and must be non-empty
    if (!json.contains("description") || !json["description"].is_string()) {
        return false;
    }
    std::string description = json["description"];
    if (description.empty()) {
        return false;
    }
    tool.description = description;

    // executablePath is required and must be absolute path
    if (!json.contains("executablePath") || !json["executablePath"].is_string()) {
        return false;
    }
    std::string executablePath = json["executablePath"];
    if (!ValidateExecutablePath(executablePath)) {
        return false;
    }
    tool.executablePath = executablePath;

    if (json.contains("requirePermissions") && json["requirePermissions"].is_array()) {
        tool.requirePermissions = json["requirePermissions"];
    }
    if (json.contains("inputSchema") && json["inputSchema"].is_object()) {
        tool.inputSchema = json["inputSchema"].dump();
    }
    if (json.contains("outputSchema") && json["outputSchema"].is_object()) {
        tool.outputSchema = json["outputSchema"].dump();
    }
    if (json.contains("argMapping") && json["argMapping"].is_object()) {
        tool.argMapping = std::make_shared<ArgMapping>();
        if (!ArgMapping::ParseFromJson(json["argMapping"], *tool.argMapping)) {
            tool.argMapping = nullptr;
            return false;  // argMapping parse failed
        }
    }
    if (json.contains("eventSchemas") && json["eventSchemas"].is_object()) {
        tool.eventSchemas = json["eventSchemas"].dump();
    }
    if (json.contains("timeout") && json["timeout"].is_number()) {
        tool.timeout = json["timeout"];
    }
    if (json.contains("eventTypes") && json["eventTypes"].is_array()) {
        tool.eventTypes = json["eventTypes"];
    }
    if (json.contains("hasSubCommand") && json["hasSubCommand"].is_boolean()) {
        tool.hasSubCommand = json["hasSubCommand"];
    }
    if (json.contains("subcommands") && json["subcommands"].is_object()) {
        for (auto it = json["subcommands"].begin(); it != json["subcommands"].end(); ++it) {
            SubCommandInfo subCmd;
            if (!SubCommandInfo::ParseFromJson(it.value(), subCmd)) {
                return false;  // subcommand parse failed
            }
            tool.subcommands[it.key()] = std::move(subCmd);
        }
    }

    return true;
}

nlohmann::json ToolInfo::ParseToJson() const
{
    nlohmann::json j;

    j["name"] = name;
    j["version"] = version;
    j["description"] = description;
    j["executablePath"] = executablePath;
    j["requirePermissions"] = requirePermissions;
    if (!inputSchema.empty()) {
        nlohmann::json inputSchemaJson = nlohmann::json::parse(inputSchema, nullptr, false);
        if (!inputSchemaJson.is_discarded()) {
            j["inputSchema"] = inputSchemaJson;
        } else {
            j["inputSchema"] = inputSchema;
        }
    }
    if (!outputSchema.empty()) {
        nlohmann::json outputSchemaJson = nlohmann::json::parse(outputSchema, nullptr, false);
        if (!outputSchemaJson.is_discarded()) {
            j["outputSchema"] = outputSchemaJson;
        } else {
            j["outputSchema"] = outputSchema;
        }
    }
    if (argMapping != nullptr) {
        j["argMapping"] = argMapping->ParseToJson();
    }
    if (!eventSchemas.empty()) {
        nlohmann::json eventSchemasJson = nlohmann::json::parse(eventSchemas, nullptr, false);
        if (!eventSchemasJson.is_discarded()) {
            j["eventSchemas"] = eventSchemasJson;
        } else {
            j["eventSchemas"] = eventSchemas;
        }
    }
    j["timeout"] = timeout;
    j["eventTypes"] = eventTypes;
    j["hasSubCommand"] = hasSubCommand;
    if (!subcommands.empty()) {
        nlohmann::json subcommandsJson;
        for (const auto &pair : subcommands) {
            subcommandsJson[pair.first] = pair.second.ParseToJson();
        }
        j["subcommands"] = subcommandsJson;
    }

    return j;
}

} // namespace CliTool
} // namespace OHOS