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

SubCommandInfo SubCommandInfo::ParseFromJson(const nlohmann::json &json)
{
    SubCommandInfo subCmd;

    if (json.contains("description") && json["description"].is_string()) {
        subCmd.description = json["description"];
    }
    if (json.contains("requirePermissions") && json["requirePermissions"].is_array()) {
        for (const auto &perm : json["requirePermissions"]) {
            if (perm.is_string()) {
                subCmd.requirePermissions.push_back(perm);
            }
        }
    }
    if (json.contains("inputSchema") && json["inputSchema"].is_object()) {
        subCmd.inputSchema = json["inputSchema"].dump();
    }
    if (json.contains("outputSchema") && json["outputSchema"].is_object()) {
        subCmd.outputSchema = json["outputSchema"].dump();
    }
    if (json.contains("argMapping") && json["argMapping"].is_object()) {
        subCmd.argMapping = ArgMapping::ParseFromJson(json["argMapping"]);
    }
    if (json.contains("eventTypes") && json["eventTypes"].is_array()) {
        for (const auto &evt : json["eventTypes"]) {
            if (evt.is_string()) {
                subCmd.eventTypes.push_back(evt);
            }
        }
    }
    if (json.contains("eventSchemas") && json["eventSchemas"].is_object()) {
        subCmd.eventSchemas = json["eventSchemas"].dump();
    }

    return subCmd;
}

nlohmann::json SubCommandInfo::ParseToJson() const
{
    nlohmann::json json;

    json["description"] = description;
    json["requirePermissions"] = requirePermissions;
    json["inputSchema"] = inputSchema;
    json["outputSchema"] = outputSchema;
    json["eventTypes"] = eventTypes;
    json["eventSchemas"] = eventSchemas;
    if (argMapping != nullptr) {
        json["argMapping"] = argMapping->ParseToJson();
    }

    return json;
}

} // namespace CliTool
} // namespace OHOS
