/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "js_cli_manager_utils.h"

#include <nlohmann/json.hpp>

#include "cli_session_info.h"
#include "exec_options.h"
#include "hilog_tag_wrapper.h"
#include "napi_common_util.h"

using namespace OHOS::AbilityRuntime;

namespace OHOS {
namespace CliTool {
namespace {
const std::string ARG_MAPPING_TYPE_FLAG = "flag";
const std::string ARG_MAPPING_TYPE_POSITIONAL = "positional";
const std::string ARG_MAPPING_TYPE_FLATTENED = "flattened";
const std::string ARG_MAPPING_TYPE_JSONSTRING = "jsonString";
const std::string ARG_MAPPING_TYPE_MIXED = "mixed";

std::string ArgMappingTypeToString(ArgMappingType type)
{
    switch (type) {
        case ArgMappingType::FLAG:
            return ARG_MAPPING_TYPE_FLAG;
        case ArgMappingType::POSITIONAL:
            return ARG_MAPPING_TYPE_POSITIONAL;
        case ArgMappingType::FLATTENED:
            return ARG_MAPPING_TYPE_FLATTENED;
        case ArgMappingType::JSONSTRING:
            return ARG_MAPPING_TYPE_JSONSTRING;
        case ArgMappingType::MIXED:
            return ARG_MAPPING_TYPE_MIXED;
        default:
            return ARG_MAPPING_TYPE_FLAG;
    }
}

napi_value ParseJsonStringToJsObject(napi_env env, const std::string &jsonStr)
{
    napi_value jsObj = nullptr;
    napi_create_object(env, &jsObj);

    if (jsonStr.empty()) {
        return jsObj;
    }

    nlohmann::json jsonObj = nlohmann::json::parse(jsonStr, nullptr, false);
    if (jsonObj.is_discarded()) {
        return jsObj;
    }

    napi_value jsValue = nullptr;
    if (jsonObj.is_object()) {
        napi_create_object(env, &jsValue);
        for (auto it = jsonObj.begin(); it != jsonObj.end(); ++it) {
            napi_value jsItem = nullptr;
            if (it.value().is_string()) {
                jsItem = AppExecFwk::WrapStringToJS(env, it.value().get<std::string>());
            } else if (it.value().is_number_integer()) {
                jsItem = AppExecFwk::WrapInt32ToJS(env, it.value().get<int32_t>());
            } else if (it.value().is_boolean()) {
                jsItem = AppExecFwk::WrapBoolToJS(env, it.value().get<bool>());
            } else if (it.value().is_object() || it.value().is_array()) {
                jsItem = ParseJsonStringToJsObject(env, it.value().dump());
            } else {
                napi_get_undefined(env, &jsItem);
            }
            napi_set_named_property(env, jsValue, it.key().c_str(), jsItem);
        }
    } else if (jsonObj.is_array()) {
        napi_create_array(env, &jsValue);
        size_t index = 0;
        for (auto &item : jsonObj) {
            napi_value jsItem = nullptr;
            if (item.is_string()) {
                jsItem = AppExecFwk::WrapStringToJS(env, item.get<std::string>());
            } else if (item.is_number_integer()) {
                jsItem = AppExecFwk::WrapInt32ToJS(env, item.get<int32_t>());
            } else if (item.is_boolean()) {
                jsItem = AppExecFwk::WrapBoolToJS(env, item.get<bool>());
            } else if (item.is_object() || item.is_array()) {
                jsItem = ParseJsonStringToJsObject(env, item.dump());
            } else {
                napi_get_undefined(env, &jsItem);
            }
            napi_set_element(env, jsValue, index++, jsItem);
        }
    } else {
        napi_create_object(env, &jsValue);
    }

    return jsValue;
}
}
bool UnwrapStringMap(napi_env env, napi_value obj,
    std::map<std::string, std::string> &values)
{
    if (obj == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Input object is null");
        return false;
    }

    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, obj, &valueType);
    if (status != napi_ok || valueType != napi_object) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Input is not an object");
        return false;
    }

    napi_value propertyNames = nullptr;
    if (napi_get_property_names(env, obj, &propertyNames) != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to get property names");
        return false;
    }
    uint32_t propertyCount = 0;
    if (napi_get_array_length(env, propertyNames, &propertyCount) != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to get array length");
        return false;
    }

    values.clear();
    for (uint32_t i = 0; i < propertyCount; i++) {
        napi_value key = nullptr;
        if (napi_get_element(env, propertyNames, i, &key) != napi_ok) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to get element");
            return false;
        }

        std::string keyStr;
        if (!AppExecFwk::UnwrapStringFromJS2(env, key, keyStr)) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to unwrap key");
            return false;
        }

        napi_value value = nullptr;
        if (napi_get_named_property(env, obj, keyStr.c_str(), &value) != napi_ok) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to get value");
            return false;
        }

        std::string valueStr;
        if (!AppExecFwk::UnwrapStringFromJS2(env, value, valueStr)) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to unwrap value");
            return false;
        }

        values.emplace(std::make_pair(keyStr, valueStr));
    }

    return true;
}

bool UnwrapExecOptions(napi_env env, napi_value obj, ExecOptions &options)
{
    if (obj == nullptr) {
        return true;
    }

    napi_valuetype valueType = napi_undefined;
    napi_status status = napi_typeof(env, obj, &valueType);
    if (status != napi_ok || valueType != napi_object) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Input is not an object");
        return false;
    }

    // Extract background (optional)
    napi_value backgroundProp = nullptr;
    if (napi_get_named_property(env, obj, "background", &backgroundProp) != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "invalid background property");
        return false;
    }
    if (!AppExecFwk::UnwrapBoolFromJS2(env, backgroundProp, options.background)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "unwrap background failed");
        return false;
    }

    // Extract yieldMs (optional)
    napi_value yieldMsProp = nullptr;
    if (napi_get_named_property(env, obj, "yieldMs", &yieldMsProp) != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "invalid yieldMs property");
        return false;
    }
    if (!AppExecFwk::UnwrapInt32FromJS2(env, yieldMsProp, options.yieldMs)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "unwrap yieldMs failed");
        return false;
    }

    // Extract timeout (optional)
    napi_value timeoutProp = nullptr;
    if (napi_get_named_property(env, obj, "timeout", &timeoutProp) != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "invalid timeout property");
        return false;
    }
    if (!AppExecFwk::UnwrapInt32FromJS2(env, timeoutProp, options.timeout)) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "unwrap timeout failed");
        return false;
    }
    return true;
}

napi_value CreateJsCliSessionInfo(napi_env env, const CliSessionInfo &session)
{
    AbilityRuntime::HandleEscape handleEscape(env);
    napi_value jsObj = nullptr;
    napi_status status = napi_create_object(env, &jsObj);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to create JS CliSessionInfo");
        return nullptr;
    }

    napi_set_named_property(env, jsObj, "sessionId", AppExecFwk::WrapStringToJS(env, session.sessionId));
    napi_set_named_property(env, jsObj, "toolName", AppExecFwk::WrapStringToJS(env, session.toolName));
    napi_set_named_property(env, jsObj, "status", AppExecFwk::WrapStringToJS(env, session.status));

    // Set result if present
    if (session.result != nullptr) {
        napi_value jsResult = nullptr;
        status = napi_create_object(env, &jsResult);
        if (status != napi_ok) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to create JS ExecResult");
            return nullptr;
        }
        napi_set_named_property(env, jsResult, "exitCode", AppExecFwk::WrapInt32ToJS(env, session.result->exitCode));
        // Set outputText
        napi_value jsOutputText = AppExecFwk::WrapStringToJS(env, session.result->outputText);
        napi_set_named_property(env, jsResult, "outputText", jsOutputText);
        // Set errorText
        napi_set_named_property(env, jsResult, "errorText", AppExecFwk::WrapStringToJS(env, session.result->errorText));
        // Set signalNumber
        napi_value jsSignalNumber = AppExecFwk::WrapInt32ToJS(env, session.result->signalNumber);
        napi_set_named_property(env, jsResult, "signalNumber", jsSignalNumber);
        // Set timedOut
        napi_set_named_property(env, jsResult, "timedOut", AppExecFwk::WrapBoolToJS(env, session.result->timedOut));
        // Set executionTime
        napi_value jsExecutionTime = AppExecFwk::WrapInt64ToJS(env, session.result->executionTime);
        napi_set_named_property(env, jsResult, "executionTime", jsExecutionTime);
        napi_set_named_property(env, jsObj, "result", jsResult);
    }

    return handleEscape.Escape(jsObj);
}

napi_value CreateJsArgMapping(napi_env env, const ArgMapping &argMapping)
{
    napi_value jsObj = nullptr;
    napi_status status = napi_create_object(env, &jsObj);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to create JS object");
        return nullptr;
    }

    // Set type (string: 'flag', 'positional', 'flattened', 'jsonString', 'mixed')
    napi_value jsType = AppExecFwk::WrapStringToJS(env, ArgMappingTypeToString(argMapping.type));
    napi_set_named_property(env, jsObj, "type", jsType);

    // Set separator
    napi_value jsSeparator = AppExecFwk::WrapStringToJS(env, argMapping.separator);
    napi_set_named_property(env, jsObj, "separator", jsSeparator);

    // Set order
    napi_value jsOrder = AppExecFwk::WrapStringToJS(env, argMapping.order);
    napi_set_named_property(env, jsObj, "order", jsOrder);

    // Set templates (parse JSON string to object)
    napi_value jsTemplates = ParseJsonStringToJsObject(env, argMapping.templates);
    napi_set_named_property(env, jsObj, "templates", jsTemplates);

    return jsObj;
}

napi_value CreateJsSubCommandInfo(napi_env env, const SubCommandInfo &subcmd)
{
    napi_value jsObj = nullptr;
    napi_status status = napi_create_object(env, &jsObj);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to create JS object");
        return nullptr;
    }

    // Set description
    napi_value jsDescription = AppExecFwk::WrapStringToJS(env, subcmd.description);
    napi_set_named_property(env, jsObj, "description", jsDescription);

    // Set requirePermissions (array)
    napi_value jsPermissions = nullptr;
    napi_create_array(env, &jsPermissions);
    for (size_t i = 0; i < subcmd.requirePermissions.size(); i++) {
        napi_value jsPerm = AppExecFwk::WrapStringToJS(env, subcmd.requirePermissions[i]);
        napi_set_element(env, jsPermissions, i, jsPerm);
    }
    napi_set_named_property(env, jsObj, "requirePermissions", jsPermissions);

    // Set inputSchema (parse JSON string to object)
    napi_value jsInputSchema = ParseJsonStringToJsObject(env, subcmd.inputSchema);
    napi_set_named_property(env, jsObj, "inputSchema", jsInputSchema);

    // Set outputSchema (parse JSON string to object)
    napi_value jsOutputSchema = ParseJsonStringToJsObject(env, subcmd.outputSchema);
    napi_set_named_property(env, jsObj, "outputSchema", jsOutputSchema);

    // Set argMapping
    if (subcmd.argMapping != nullptr) {
        napi_value jsArgMapping = CreateJsArgMapping(env, *subcmd.argMapping);
        if (jsArgMapping != nullptr) {
            napi_set_named_property(env, jsObj, "argMapping", jsArgMapping);
        }
    }

    // Set eventTypes (array)
    napi_value jsEventTypes = nullptr;
    napi_create_array(env, &jsEventTypes);
    for (size_t i = 0; i < subcmd.eventTypes.size(); i++) {
        napi_value jsEventType = AppExecFwk::WrapStringToJS(env, subcmd.eventTypes[i]);
        napi_set_element(env, jsEventTypes, i, jsEventType);
    }
    napi_set_named_property(env, jsObj, "eventTypes", jsEventTypes);

    // Set eventSchemas (parse JSON string to object)
    napi_value jsEventSchemas = ParseJsonStringToJsObject(env, subcmd.eventSchemas);
    napi_set_named_property(env, jsObj, "eventSchemas", jsEventSchemas);

    return jsObj;
}

napi_value CreateJsToolInfo(napi_env env, const ToolInfo &tool)
{
    napi_value jsObj = nullptr;
    napi_status status = napi_create_object(env, &jsObj);
    if (status != napi_ok) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to create JS object");
        return nullptr;
    }

    // Set name
    napi_value jsName = AppExecFwk::WrapStringToJS(env, tool.name);
    napi_set_named_property(env, jsObj, "name", jsName);

    // Set version
    napi_value jsVersion = AppExecFwk::WrapStringToJS(env, tool.version);
    napi_set_named_property(env, jsObj, "version", jsVersion);

    // Set description
    napi_value jsDescription = AppExecFwk::WrapStringToJS(env, tool.description);
    napi_set_named_property(env, jsObj, "description", jsDescription);

    // Set executablePath
    napi_value jsExecutablePath = AppExecFwk::WrapStringToJS(env, tool.executablePath);
    napi_set_named_property(env, jsObj, "executablePath", jsExecutablePath);

    // Set requirePermissions (array)
    napi_value jsPermissions = nullptr;
    napi_create_array(env, &jsPermissions);
    for (size_t i = 0; i < tool.requirePermissions.size(); i++) {
        napi_value jsPerm = AppExecFwk::WrapStringToJS(env, tool.requirePermissions[i]);
        napi_set_element(env, jsPermissions, i, jsPerm);
    }
    napi_set_named_property(env, jsObj, "requirePermissions", jsPermissions);

    // Set inputSchema (parse JSON string to object)
    napi_value jsInputSchema = ParseJsonStringToJsObject(env, tool.inputSchema);
    napi_set_named_property(env, jsObj, "inputSchema", jsInputSchema);

    // Set outputSchema (parse JSON string to object)
    napi_value jsOutputSchema = ParseJsonStringToJsObject(env, tool.outputSchema);
    napi_set_named_property(env, jsObj, "outputSchema", jsOutputSchema);

    // Set argMapping
    if (tool.argMapping != nullptr) {
        napi_value jsArgMapping = CreateJsArgMapping(env, *tool.argMapping);
        if (jsArgMapping != nullptr) {
            napi_set_named_property(env, jsObj, "argMapping", jsArgMapping);
        }
    }

    // Set eventTypes (array)
    napi_value jsEventTypes = nullptr;
    napi_create_array(env, &jsEventTypes);
    for (size_t i = 0; i < tool.eventTypes.size(); i++) {
        napi_value jsEventType = AppExecFwk::WrapStringToJS(env, tool.eventTypes[i]);
        napi_set_element(env, jsEventTypes, i, jsEventType);
    }
    napi_set_named_property(env, jsObj, "eventTypes", jsEventTypes);

    // Set eventSchemas (parse JSON string to object)
    napi_value jsEventSchemas = ParseJsonStringToJsObject(env, tool.eventSchemas);
    napi_set_named_property(env, jsObj, "eventSchemas", jsEventSchemas);

    // Set timeout
    napi_value jsTimeout = AppExecFwk::WrapInt32ToJS(env, tool.timeout);
    napi_set_named_property(env, jsObj, "timeout", jsTimeout);

    // Set hasSubCommand
    napi_value jsHasSubCommand = AppExecFwk::WrapBoolToJS(env, tool.hasSubCommand);
    napi_set_named_property(env, jsObj, "hasSubCommand", jsHasSubCommand);

    // Set subcommands (map)
    napi_value jsSubcommands = nullptr;
    napi_create_object(env, &jsSubcommands);
    for (const auto &pair : tool.subcommands) {
        napi_value jsSubcmd = CreateJsSubCommandInfo(env, pair.second);
        if (jsSubcmd != nullptr) {
            napi_set_named_property(env, jsSubcommands, pair.first.c_str(), jsSubcmd);
        }
    }
    napi_set_named_property(env, jsObj, "subcommands", jsSubcommands);

    return jsObj;
}

} // namespace CliTool
} // namespace OHOS
