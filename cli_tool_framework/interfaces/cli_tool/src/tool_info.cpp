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
    // Serialize subcommands map to JSON string
    std::string subcommandsJson;
    if (!subcommands.empty()) {
        nlohmann::json j;
        for (const auto &pair : subcommands) {
            nlohmann::json subCmdJson;
            subCmdJson["description"] = pair.second.description;
            subCmdJson["requirePermissions"] = pair.second.requirePermissions;
            subCmdJson["inputSchema"] = pair.second.inputSchema;
            subCmdJson["outputSchema"] = pair.second.outputSchema;
            subCmdJson["eventTypes"] = pair.second.eventTypes;
            subCmdJson["eventSchemas"] = pair.second.eventSchemas;
            if (pair.second.argMapping != nullptr) {
                nlohmann::json argMappingJson;
                switch (pair.second.argMapping->type) {
                    case ArgMappingType::FLAG:
                        argMappingJson["type"] = "flag";
                        break;
                    case ArgMappingType::POSITIONAL:
                        argMappingJson["type"] = "positional";
                        break;
                    case ArgMappingType::FLATTENED:
                        argMappingJson["type"] = "flattened";
                        break;
                    case ArgMappingType::JSONSTRING:
                        argMappingJson["type"] = "jsonString";
                        break;
                    case ArgMappingType::MIXED:
                        argMappingJson["type"] = "mixed";
                        break;
                }
                if (!pair.second.argMapping->separator.empty()) {
                    argMappingJson["separator"] = pair.second.argMapping->separator;
                }
                if (!pair.second.argMapping->order.empty()) {
                    argMappingJson["order"] = pair.second.argMapping->order;
                }
                if (!pair.second.argMapping->templates.empty()) {
                    argMappingJson["templates"] = pair.second.argMapping->templates;
                }
                subCmdJson["argMapping"] = argMappingJson;
            }
            j[pair.first] = subCmdJson;
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

    // Parse subcommands JSON string to map
    if (!subcommandsJson.empty()) {
        nlohmann::json j = nlohmann::json::parse(subcommandsJson, nullptr, false);
        if (!j.is_discarded() && j.is_object()) {
            for (auto it = j.begin(); it != j.end(); ++it) {
                SubCommandInfo subCmd;
                auto &subJson = it.value();
                if (subJson.contains("description") && subJson["description"].is_string()) {
                    subCmd.description = subJson["description"];
                }
                if (subJson.contains("requirePermissions") && subJson["requirePermissions"].is_array()) {
                    for (const auto &perm : subJson["requirePermissions"]) {
                        if (perm.is_string()) {
                            subCmd.requirePermissions.push_back(perm);
                        }
                    }
                }
                if (subJson.contains("inputSchema") && subJson["inputSchema"].is_string()) {
                    subCmd.inputSchema = subJson["inputSchema"];
                }
                if (subJson.contains("outputSchema") && subJson["outputSchema"].is_string()) {
                    subCmd.outputSchema = subJson["outputSchema"];
                }
                if (subJson.contains("eventTypes") && subJson["eventTypes"].is_array()) {
                    for (const auto &evt : subJson["eventTypes"]) {
                        if (evt.is_string()) {
                            subCmd.eventTypes.push_back(evt);
                        }
                    }
                }
                if (subJson.contains("eventSchemas") && subJson["eventSchemas"].is_string()) {
                    subCmd.eventSchemas = subJson["eventSchemas"];
                }
                if (subJson.contains("argMapping") && subJson["argMapping"].is_object()) {
                    subCmd.argMapping = std::make_shared<ArgMapping>();
                    auto &argJson = subJson["argMapping"];
                    if (argJson.contains("type") && argJson["type"].is_string()) {
                        std::string typeStr = argJson["type"];
                        if (typeStr == "flag") {
                            subCmd.argMapping->type = ArgMappingType::FLAG;
                        } else if (typeStr == "positional") {
                            subCmd.argMapping->type = ArgMappingType::POSITIONAL;
                        } else if (typeStr == "flattened") {
                            subCmd.argMapping->type = ArgMappingType::FLATTENED;
                        } else if (typeStr == "jsonString") {
                            subCmd.argMapping->type = ArgMappingType::JSONSTRING;
                        } else if (typeStr == "mixed") {
                            subCmd.argMapping->type = ArgMappingType::MIXED;
                        }
                    }
                    if (argJson.contains("separator") && argJson["separator"].is_string()) {
                        subCmd.argMapping->separator = argJson["separator"];
                    }
                    if (argJson.contains("order") && argJson["order"].is_string()) {
                        subCmd.argMapping->order = argJson["order"];
                    }
                    if (argJson.contains("templates") && argJson["templates"].is_string()) {
                        subCmd.argMapping->templates = argJson["templates"];
                    }
                }
                tool->subcommands[it.key()] = subCmd;
            }
        }
    }

    return tool;
}

ToolInfo ToolInfo::ParseFromJson(const nlohmann::json &json)
{
    ToolInfo tool;

    if (json.contains("name") && json["name"].is_string()) {
        tool.name = json["name"];
    }
    if (json.contains("version") && json["version"].is_string()) {
        tool.version = json["version"];
    }
    if (json.contains("description") && json["description"].is_string()) {
        tool.description = json["description"];
    }
    if (json.contains("executablePath") && json["executablePath"].is_string()) {
        tool.executablePath = json["executablePath"];
    }
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
        tool.argMapping = ArgMapping::ParseFromJson(json["argMapping"]);
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
            tool.subcommands[it.key()] = SubCommandInfo::ParseFromJson(it.value());
        }
    }

    return tool;
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