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

#include "tool_util.h"

#include <algorithm>
#include <climits>
#include <nlohmann/json.hpp>
#include <random>
#include <sstream>
#include <utility>
#include <vector>

#include "accesstoken_kit.h"
#include "bundle_info.h"
#include "bundle_mgr_helper.h"
#include "cli_error_code.h"
#include "exec_tool_param.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"
#include "permission_util.h"
#include "session_record.h"
#include "tool_info.h"
#include "want_params.h"
#include "want_params_wrapper.h"

namespace OHOS {
namespace CliTool {
namespace {
constexpr int32_t MILLISECOND_COEFFICIENT = 1000;
}
int32_t ToolUtil::ValidateProperties(const ToolInfo &toolInfo, ExecToolParam &param,
    AccessToken::AccessTokenID tokenId)
{
    if (!param.subcommand.empty()) {
        if (!toolInfo.hasSubCommand) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "not have subcommand");
            return ERR_INVALID_PARAM;
        }

        auto search = toolInfo.subcommands.find(param.subcommand);
        if (search == toolInfo.subcommands.end()) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "not have subcommand");
            return ERR_INVALID_PARAM;
        }
        if (!PermissionUtil::VerifyAccessToken(tokenId, search->second.requirePermissions)) {
            return ERR_PERMISSION_DENIED;
        }
    } else {
        if (!PermissionUtil::VerifyAccessToken(tokenId, toolInfo.requirePermissions)) {
            return ERR_PERMISSION_DENIED;
        }
    }

    if (param.options.timeout < 0 || param.options.yieldMs < 0) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "yieldMs or timeout < 0");
        return ERR_INVALID_PARAM;
    }

    if (param.options.timeout == 0) {
        param.options.timeout = toolInfo.timeout;
        TAG_LOGI(AAFwkTag::CLI_TOOL, "use toolInfo timeout");
    } else if (param.options.timeout > toolInfo.timeout) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Excessively large timeout");
        return ERR_INVALID_PARAM;
    }

    if (!param.options.background) {
        if (param.options.yieldMs == 0) {
            param.options.yieldMs = param.options.timeout * MILLISECOND_COEFFICIENT;
        } else if (param.options.yieldMs > param.options.timeout * MILLISECOND_COEFFICIENT) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "yieldTime exceeds timeout.");
            return ERR_INVALID_PARAM;
        }
    }

    return ValidateInputSchemaProperties(toolInfo.inputSchema, param.args);
}

int32_t ToolUtil::ValidateInputSchemaProperties(const std::string &inputSchema,
    const AAFwk::WantParams &args)
{
    if (args.IsEmpty()) {
        TAG_LOGI(AAFwkTag::CLI_TOOL, "args is empty");
        return ERR_OK;
    }

    if (inputSchema.empty()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "inputSchema is empty");
        return ERR_INVALID_PARAM;
    }

    nlohmann::json schema = nlohmann::json::parse(inputSchema, nullptr, false);
    if (schema.is_discarded()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "discarded error");
        return ERR_NO_INIT;
    }
    if (!schema.contains("properties") || !schema["properties"].is_object()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "properties not found or invalid");
        return ERR_INVALID_PARAM;
    }
    auto properties = schema["properties"];
    for (auto &[key, value] : args.GetParams()) {
        if (!properties.contains(key)) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "args key '%{public}s' not found in properties", key.c_str());
            return ERR_INVALID_PARAM;
        }

        // Validate type if specified in schema
        auto &propertySchema = properties[key];
        if (propertySchema.contains("type")) {
            std::string expectedType = propertySchema["type"].get<std::string>();
            if (!ValidateParamType(value, expectedType, propertySchema, key)) {
                TAG_LOGE(AAFwkTag::CLI_TOOL, "args key '%{public}s' type mismatch, expected: %{public}s",
                    key.c_str(), expectedType.c_str());
                return ERR_INVALID_PARAM;
            }
        }
    }
    return ERR_OK;
}

std::string ToolUtil::GenerateCliSessionId(const std::string &name, std::shared_ptr<SessionRecord> record)
{
    std::random_device seed;
    std::mt19937 rng(seed());
    std::uniform_int_distribution<int> uni(0, INT_MAX);
    int randomDigit = uni(rng);
    auto timestamp = std::chrono::system_clock::now().time_since_epoch();
    auto time = std::chrono::duration_cast<std::chrono::milliseconds>(timestamp).count();
    if (record != nullptr) {
        record->startTime = time;
    }
    return name + "_" + std::to_string(time) + "_" + std::to_string(randomDigit);
}

bool ToolUtil::GenerateSandboxConfig(const std::string &challenge, AccessToken::AccessTokenID tokenId,
    std::string &sandboxConfig)
{
    AppExecFwk::BundleInfo bundleInfo;
    if (!ToolUtil::GetBundleInfoByTokenId(tokenId, bundleInfo)) {
        return false;
    }

    nlohmann::json config;
    config["callerTokenId"] = IPCSkeleton::GetCallingFullTokenID();
    config["challenge"] = challenge;
    config["uid"] = IPCSkeleton::GetCallingUid();
    config["callerPid"] = IPCSkeleton::GetCallingPid();
    config["gid"] = bundleInfo.gid;
    config["appId"] = bundleInfo.appId;
    sandboxConfig = config.dump();
    TAG_LOGE(AAFwkTag::CLI_TOOL, "sandboxConfig: %{public}s", sandboxConfig.c_str());
    return true;
}

bool ToolUtil::GetBundleInfoByTokenId(AccessToken::AccessTokenID tokenId, AppExecFwk::BundleInfo &bundleInfo)
{
    auto tokenType = AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType != AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "caller is not hap");
        return false;
    }
    AccessToken::HapTokenInfo hapInfo;
    auto ret = AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapInfo);
    if (ret != AccessToken::AccessTokenKitRet::RET_SUCCESS) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "GetHapTokenInfo failed, ret:%{public}d", ret);
        return false;
    }

    auto bundleMgrHelper = DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance();
    if (bundleMgrHelper == nullptr) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "bundlerMgrHelper is invalid");
        return false;
    }
    auto flag = static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    if (hapInfo.instIndex == 0) {
        if (bundleMgrHelper->GetBundleInfoV9(hapInfo.bundleName, flag, bundleInfo, hapInfo.userID) != ERR_OK) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Fail to get bundle info");
            return false;
        }
        return true;
    }
    if (bundleMgrHelper->GetCloneBundleInfo(hapInfo.bundleName, flag, hapInfo.instIndex, bundleInfo, hapInfo.userID) !=
        ERR_OK) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Fail to get bundle info");
        return false;
    }
    return true;
}

void ToolUtil::TransferToCmdParam(const ToolInfo &toolInfo, const AAFwk::WantParams &args, std::string &cmdLine)
{
    if (args.IsEmpty()) {
        TAG_LOGI(AAFwkTag::CLI_TOOL, "Not has arg");
        return;
    }
    if (toolInfo.argMapping == nullptr) {
        TAG_LOGW(AAFwkTag::CLI_TOOL, "argMapping is nullptr");
        return;
    }

    // Apply mapping based on type
    switch (toolInfo.argMapping->type) {
        case ArgMappingType::FLAG:
            ApplyFlagMapping(toolInfo.argMapping->templates, args, cmdLine);
            break;
        case ArgMappingType::POSITIONAL:
            ApplyPositionalMapping(toolInfo.argMapping->order, args, cmdLine);
            break;
        case ArgMappingType::FLATTENED:
            ApplyFlattenedMapping(toolInfo.argMapping->separator, toolInfo.argMapping->templates, args, cmdLine);
            break;
        case ArgMappingType::JSONSTRING:
            ApplyJsonStringMapping(toolInfo.argMapping->templates, args, cmdLine);
            break;
        case ArgMappingType::MIXED:
            ApplyMixedMapping(toolInfo.argMapping->templates, args, cmdLine);
            break;
        default:
            TAG_LOGW(AAFwkTag::CLI_TOOL, "Unknown argMapping type");
            break;
    }
}

void ToolUtil::ApplyFlagMapping(const std::string &templates, const AAFwk::WantParams &args, std::string &cmdLine)
{
    if (templates.empty()) {
        TAG_LOGW(AAFwkTag::CLI_TOOL, "Flag templates is empty");
        return;
    }

    nlohmann::json templatesJson = nlohmann::json::parse(templates, nullptr, false);
    if (templatesJson.is_discarded() || !templatesJson.is_object()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to parse templates JSON");
        return;
    }

    for (const auto &[key, value] : args.GetParams()) {
        if (!templatesJson.contains(key)) {
            continue;
        }

        auto &templateValue = templatesJson[key];
        // Apply FLAG mode logic for this parameter
        ApplyFlagModeLogic(value, templateValue, cmdLine);
    }
}

void ToolUtil::ApplyPositionalMapping(const std::string &order, const AAFwk::WantParams &args, std::string &cmdLine)
{
    if (order.empty()) {
        TAG_LOGW(AAFwkTag::CLI_TOOL, "Positional order is empty");
        return;
    }

    nlohmann::json orderJson = nlohmann::json::parse(order, nullptr, false);
    if (orderJson.is_discarded() || !orderJson.is_array()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to parse order JSON");
        return;
    }

    for (const auto &key : orderJson) {
        if (!key.is_string()) {
            continue;
        }
        std::string keyStr = key.get<std::string>();
        auto it = args.GetParams().find(keyStr);
        if (it != args.GetParams().end()) {
            std::string strValue = GetParamStringValue(it->second);
            if (!strValue.empty()) {
                cmdLine += " " + strValue;
            }
        }
    }
}

void ToolUtil::ApplyFlattenedMapping(const std::string &separator, const std::string &templates,
    const AAFwk::WantParams &args, std::string &cmdLine)
{
    std::string sep = separator.empty() ? "." : separator;

    nlohmann::json templatesJson = nlohmann::json::parse(templates, nullptr, false);
    if (templatesJson.is_discarded() || !templatesJson.is_object()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to parse templates JSON");
        return;
    }

    // Process each template key (which contains the flattened path)
    for (const auto &templateIt : templatesJson.items()) {
        const std::string &flattenedKey = templateIt.key();
        const auto &templateValue = templateIt.value();

        // Query nested value and process in one step to reduce depth
        ProcessFlattenedTemplate(flattenedKey, templateValue, sep, args, cmdLine);
    }
}

void ToolUtil::ApplyJsonStringMapping(const std::string &templates, const AAFwk::WantParams &args, std::string &cmdLine)
{
    nlohmann::json templatesJson = nlohmann::json::parse(templates, nullptr, false);
    if (templatesJson.is_discarded() || !templatesJson.is_object()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to parse templates JSON");
        return;
    }

    for (const auto &[key, value] : args.GetParams()) {
        if (!templatesJson.contains(key)) {
            continue;
        }

        auto &templateValue = templatesJson[key];

        if (templateValue.is_string()) {
            ProcessJsonStringTemplate(key, value, templateValue, cmdLine);
        } else if (templateValue.is_object()) {
            ProcessBooleanTemplate(key, value, templateValue, cmdLine);
        }
    }
}

void ToolUtil::ApplyMixedMapping(const std::string &templates, const AAFwk::WantParams &args, std::string &cmdLine)
{
    nlohmann::json templatesJson = nlohmann::json::parse(templates, nullptr, false);
    if (templatesJson.is_discarded() || !templatesJson.is_object()) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "Failed to parse templates JSON");
        return;
    }

    // First pass: collect positional parameters to ensure correct order
    std::vector<std::pair<int, std::string>> positionalParams; // (order, value)

    for (const auto &[key, value] : args.GetParams()) {
        // Skip if key not in templates
        if (!templatesJson.contains(key)) {
            continue;
        }

        auto paramConfig = templatesJson[key];
        // Skip if invalid config
        if (!paramConfig.is_object() || !paramConfig.contains("mode")) {
            continue;
        }

        std::string mode = paramConfig["mode"].get<std::string>();
        // FLAG mode: process immediately
        if (mode == "flag" && paramConfig.contains("template")) {
            ApplyFlagModeLogic(value, paramConfig["template"], cmdLine);
            continue;
        }

        // POSITIONAL mode: collect for later processing
        if (mode == "positional") {
            ProcessPositionalMode(value, paramConfig, positionalParams);
            continue;
        }

        // FLATTENED mode: process immediately
        if (mode == "flattened") {
            ProcessFlattenedMode(key, value, paramConfig, args, cmdLine);
            continue;
        }

        // JSON-STRING mode: process immediately
        if (mode == "json-string" && paramConfig.contains("template")) {
            ProcessJsonStringTemplate(key, value, paramConfig["template"], cmdLine);
            continue;
        }
    }

    // Second pass: append positional parameters in correct order
    if (!positionalParams.empty()) {
        // Sort by order value
        std::sort(positionalParams.begin(), positionalParams.end(),
            [](const auto &a, const auto &b) { return a.first < b.first; });

        // Append in sorted order
        for (const auto &param : positionalParams) {
            cmdLine += " " + param.second;
        }
    }
}

std::string ToolUtil::FormatTemplate(const std::string &tmpl, const std::string &value)
{
    std::string result = tmpl;
    size_t pos = result.find("{value}");
    constexpr int32_t valueSize = 7;
    if (pos != std::string::npos) {
        result.replace(pos, valueSize, value);
    }
    pos = result.find("{json}");
    constexpr int32_t jsonSize = 6;
    if (pos != std::string::npos) {
        result.replace(pos, jsonSize, value);
    }
    return result;
}

sptr<AAFwk::IInterface> ToolUtil::QueryNestedValue(const AAFwk::WantParams &args,
    const std::string &path, const std::string &separator)
{
    if (path.empty()) {
        return nullptr;
    }

    // Try direct lookup first
    sptr<AAFwk::IInterface> result = TryDirectLookup(args, path);
    if (result != nullptr) {
        return result;
    }

    // Try nested path traversal
    std::string sep = separator.empty() ? "." : separator;
    return TryNestedPathTraversal(args, path, sep);
}

sptr<AAFwk::IInterface> ToolUtil::TryDirectLookup(const AAFwk::WantParams &args,
    const std::string &path)
{
    auto &params = args.GetParams();
    auto it = params.find(path);
    if (it != params.end()) {
        TAG_LOGI(AAFwkTag::CLI_TOOL, "Found param with direct lookup: %{public}s", path.c_str());
        return it->second;
    }
    return nullptr;
}

sptr<AAFwk::IInterface> ToolUtil::TryNestedPathTraversal(const AAFwk::WantParams &args,
    const std::string &path, const std::string &separator)
{
    std::vector<std::string> pathSegments = SplitPathBySeparator(path, separator);
    constexpr int32_t segmentSize = 2;
    if (pathSegments.size() < segmentSize) {
        return nullptr;
    }

    return QueryNestedPath(args, pathSegments, separator);
}

std::string ToolUtil::WantParamsToJson(const AAFwk::WantParams &wantParams)
{
    nlohmann::json result = nlohmann::json::object();

    for (const auto &[key, value] : wantParams.GetParams()) {
        // Check if value is another WantParams (nested object)
        AAFwk::WantParams nestedWantParams;
        if (ExtractWantParams(value, nestedWantParams)) {
            // Recursively convert nested WantParams to JSON
            result[key] = nlohmann::json::parse(WantParamsToJson(nestedWantParams), nullptr, false);
        } else if (value != nullptr) {
            // Convert IInterface to JSON value using GetParamJsonValue
            std::string valueJsonStr = GetParamJsonValue(value);
            nlohmann::json valueJson = nlohmann::json::parse(valueJsonStr, nullptr, false);
            if (!valueJson.is_discarded()) {
                result[key] = valueJson;
            }
        }
    }

    return result.dump();
}

std::string ToolUtil::GetParamStringValue(const sptr<AAFwk::IInterface> &value)
{
    if (value == nullptr) {
        return "";
    }

    // Try String
    if (auto strObj = AAFwk::IString::Query(value)) {
        std::string strValue;
        if (strObj->GetString(strValue) == ERR_OK) {
            return strValue;
        }
        return "";
    }

    // Try Boolean
    if (auto boolObj = AAFwk::IBoolean::Query(value)) {
        bool boolValue = false;
        if (boolObj->GetValue(boolValue) == ERR_OK) {
            return boolValue ? "true" : "false";
        }
        return "";
    }

    // Try Integer/Int
    if (auto intObj = AAFwk::IInteger::Query(value)) {
        int intValue = 0;
        if (intObj->GetValue(intValue) == ERR_OK) {
            return std::to_string(intValue);
        }
        return "";
    }

    // Try Long
    if (auto longObj = AAFwk::ILong::Query(value)) {
        long longValue = 0;
        if (longObj->GetValue(longValue) == ERR_OK) {
            return std::to_string(longValue);
        }
        return "";
    }

    // Try Float
    if (auto floatObj = AAFwk::IFloat::Query(value)) {
        float floatValue = 0.0f;
        if (floatObj->GetValue(floatValue) == ERR_OK) {
            return std::to_string(floatValue);
        }
        return "";
    }

    // Try Double
    if (auto doubleObj = AAFwk::IDouble::Query(value)) {
        double doubleValue = 0.0;
        if (doubleObj->GetValue(doubleValue) == ERR_OK) {
            return std::to_string(doubleValue);
        }
        return "";
    }

    // If no type matches, return empty string
    return "";
}

std::string ToolUtil::GetParamJsonValue(const sptr<AAFwk::IInterface> &value)
{
    if (value == nullptr) {
        return "null";
    }

    // Try WantParams (nested object) - should check before other types
    std::string jsonStr = ConvertWantParamsToJson(value);
    if (!jsonStr.empty()) {
        return jsonStr;
    }

    // Try Array - only single-level array support (no nested arrays)
    jsonStr = ConvertArrayToJson(value);
    if (!jsonStr.empty()) {
        return jsonStr;
    }

    // Try String - JSON strings are quoted
    jsonStr = ConvertStringToJson(value);
    if (!jsonStr.empty()) {
        return jsonStr;
    }

    // Try Boolean - JSON booleans are unquoted
    jsonStr = ConvertBooleanToJson(value);
    if (!jsonStr.empty()) {
        return jsonStr;
    }

    // Try Numeric types (int, long, float, double)
    jsonStr = ConvertNumericToJson(value);
    if (!jsonStr.empty()) {
        return jsonStr;
    }

    // If no type matches, return null
    return "null";
}

std::string ToolUtil::ConvertWantParamsToJson(const sptr<AAFwk::IInterface> &value)
{
    AAFwk::WantParams wantParams;
    if (ExtractWantParams(value, wantParams)) {
        return WantParamsToJson(wantParams);
    }
    return "";
}

std::string ToolUtil::ConvertArrayToJson(const sptr<AAFwk::IInterface> &value)
{
    if (auto arrayObj = AAFwk::IArray::Query(value)) {
        return BuildJsonArrayFromIArray(arrayObj, [](const sptr<AAFwk::IInterface>& element) {
            return GetParamJsonValue(element);
        });
    }
    return "";
}

std::string ToolUtil::ConvertStringToJson(const sptr<AAFwk::IInterface> &value)
{
    if (auto strObj = AAFwk::IString::Query(value)) {
        std::string strValue;
        if (strObj->GetString(strValue) != ERR_OK) {
            return "\"\"";
        }
        return "\"" + EscapeJsonString(strValue) + "\"";
    }
    return "";
}

std::string ToolUtil::ConvertBooleanToJson(const sptr<AAFwk::IInterface> &value)
{
    if (auto boolObj = AAFwk::IBoolean::Query(value)) {
        bool boolValue = false;
        if (boolObj->GetValue(boolValue) == ERR_OK) {
            return boolValue ? "true" : "false";
        }
        return "false";
    }
    return "";
}

std::string ToolUtil::ConvertNumericToJson(const sptr<AAFwk::IInterface> &value)
{
    // Try Integer/Int
    if (auto intObj = AAFwk::IInteger::Query(value)) {
        int intValue = 0;
        if (intObj->GetValue(intValue) == ERR_OK) {
            return std::to_string(intValue);
        }
        return "0";
    }

    // Try Long
    if (auto longObj = AAFwk::ILong::Query(value)) {
        long longValue = 0;
        if (longObj->GetValue(longValue) == ERR_OK) {
            return std::to_string(longValue);
        }
        return "0";
    }

    // Try Float
    if (auto floatObj = AAFwk::IFloat::Query(value)) {
        float floatValue = 0.0f;
        if (floatObj->GetValue(floatValue) == ERR_OK) {
            return std::to_string(floatValue);
        }
        return "0.0";
    }

    // Try Double
    if (auto doubleObj = AAFwk::IDouble::Query(value)) {
        double doubleValue = 0.0;
        if (doubleObj->GetValue(doubleValue) == ERR_OK) {
            return std::to_string(doubleValue);
        }
        return "0.0";
    }

    return "";
}

bool ToolUtil::GetParamBoolValue(const sptr<AAFwk::IInterface> &value, bool &result)
{
    if (value == nullptr) {
        return false;
    }

    // Try Boolean type directly
    if (auto boolObj = AAFwk::IBoolean::Query(value)) {
        if (boolObj->GetValue(result) == ERR_OK) {
            return true;
        }
        return false;
    }

    return false;
}

bool ToolUtil::GetParamArrayValue(const sptr<AAFwk::IInterface> &value, std::vector<std::string> &result)
{
    if (value == nullptr) {
        return false;
    }

    // Try to query as IArray
    auto arrayValue = AAFwk::IArray::Query(value);
    if (arrayValue == nullptr) {
        return false;
    }

    bool foundAny = false;
    IterateIArray(arrayValue, [&result, &foundAny](const sptr<AAFwk::IInterface>& element) {
        std::string elementStr = GetParamStringValue(element);
        if (!elementStr.empty()) {
            result.push_back(elementStr);
            foundAny = true;
        }
    });

    return foundAny;
}

void ToolUtil::ApplyFlattenedModeToSingleParam(const std::string &key, const sptr<AAFwk::IInterface> &value,
    const std::string &separator, const nlohmann::json &templateValue,
    const AAFwk::WantParams &args, std::string &cmdLine)
{
    // This method applies FLATTENED mode logic for a single parameter
    // It uses nested path query to get the value from the nested structure

    // In flattened mode, templateValue should be a string template
    if (!templateValue.is_string()) {
        TAG_LOGW(AAFwkTag::CLI_TOOL, "Flattened mode requires string template for key '%{public}s'", key.c_str());
        return;
    }

    // Inline logic to reduce call depth
    std::string tmpl = templateValue.get<std::string>();
    std::string sep = separator.empty() ? "." : separator;
    sptr<AAFwk::IInterface> nestedValue = QueryNestedValue(args, key, sep);

    if (nestedValue == nullptr) {
        TAG_LOGW(AAFwkTag::CLI_TOOL, "Could not find nested param for key '%{public}s'", key.c_str());
        return;
    }

    // Convert the found value to string
    std::string strValue = GetParamStringValue(nestedValue);

    // Handle boolean conditions
    bool boolValue = false;
    if (GetParamBoolValue(nestedValue, boolValue)) {
        if (boolValue && tmpl.find("{value}") != std::string::npos) {
            // Boolean value with {value} placeholder
            std::string formatted = FormatTemplate(tmpl, (boolValue ? "true" : "false"));
            cmdLine += " " + formatted;
        } else {
            // Boolean without placeholder, skip
            TAG_LOGW(AAFwkTag::CLI_TOOL, "Boolean value for key '%{public}s' but no boolean template",
                key.c_str());
        }
    } else if (!strValue.empty()) {
        // Regular string value
        std::string formatted = FormatTemplate(tmpl, strValue);
        cmdLine += " " + formatted;
    }
}

// ============================================================================
// Helper methods for code reuse
// ============================================================================

bool ToolUtil::ExtractWantParams(const sptr<AAFwk::IInterface> &value, AAFwk::WantParams &wantParams)
{
    if (value == nullptr) {
        return false;
    }

    auto wantParamsWrapper = AAFwk::IWantParams::Query(value);
    if (wantParamsWrapper == nullptr) {
        return false;
    }

    return wantParamsWrapper->GetValue(wantParams) == ERR_OK;
}

std::string ToolUtil::EscapeJsonString(const std::string &str)
{
    std::string escaped = "";
    for (char c : str) {
        if (c == '"') {
            escaped += "\\\"";
        } else if (c == '\\') {
            escaped += "\\\\";
        } else if (c == '\n') {
            escaped += "\\n";
        } else if (c == '\r') {
            escaped += "\\r";
        } else if (c == '\t') {
            escaped += "\\t";
        } else {
            escaped += c;
        }
    }
    return escaped;
}

void ToolUtil::IterateIArray(sptr<AAFwk::IArray> arrayObj,
    std::function<void(const sptr<AAFwk::IInterface>&)> elementHandler)
{
    if (arrayObj == nullptr) {
        return;
    }

    long arrayLength = 0;
    if (arrayObj->GetLength(arrayLength) != ERR_OK || arrayLength <= 0) {
        return;
    }

    for (long i = 0; i < arrayLength; ++i) {
        sptr<AAFwk::IInterface> elementValue;
        if (arrayObj->Get(i, elementValue) != ERR_OK || elementValue == nullptr) {
            continue;
        }

        // Skip nested arrays
        if (AAFwk::IArray::Query(elementValue) != nullptr) {
            continue;
        }

        elementHandler(elementValue);
    }
}

std::string ToolUtil::BuildJsonArrayFromIArray(sptr<AAFwk::IArray> arrayObj,
    std::function<std::string(const sptr<AAFwk::IInterface>&)> elementConverter)
{
    if (arrayObj == nullptr) {
        return "[]";
    }

    long arrayLength = 0;
    if (arrayObj->GetLength(arrayLength) != ERR_OK || arrayLength <= 0) {
        return "[]";
    }

    std::string result = "[";
    bool firstElement = true;

    IterateIArray(arrayObj, [&result, &firstElement, &elementConverter](const sptr<AAFwk::IInterface>& element) {
        if (!firstElement) {
            result += ",";
        }
        result += elementConverter(element);
        firstElement = false;
    });

    result += "]";
    return result;
}

// ============================================================================
// Core FLAG mode logic (extracted for reuse)
// ============================================================================

void ToolUtil::ApplyFlagModeLogic(const sptr<AAFwk::IInterface> &value,
    const nlohmann::json &templateValue, std::string &cmdLine)
{
    if (value == nullptr) {
        return;
    }

    // Handle string template
    if (templateValue.is_string()) {
        std::string strValue = GetParamStringValue(value);
        if (!strValue.empty()) {
            std::string tmpl = templateValue.get<std::string>();
            std::string formatted = FormatTemplate(tmpl, strValue);
            cmdLine += " " + formatted;
        }
        return;
    }

    // Handle boolean template with if_true/if_false
    if (templateValue.is_object()) {
        bool boolValue = false;
        if (GetParamBoolValue(value, boolValue)) {
            std::string flag = "";
            if (boolValue && templateValue.contains("if_true")) {
                flag = templateValue["if_true"].get<std::string>();
            } else if (!boolValue && templateValue.contains("if_false")) {
                flag = templateValue["if_false"].get<std::string>();
            }

            if (!flag.empty()) {
                cmdLine += " " + flag;
            }
        }
        return;
    }

    // Handle array type - expand to multiple arguments
    if (!templateValue.is_string()) {
        return;
    }

    std::string tmpl = templateValue.get<std::string>();
    ProcessArrayExpansion(value, tmpl, cmdLine);
}

// ============================================================================
// Helper methods for mode processing (extracted to reduce nesting depth)
// ============================================================================

void ToolUtil::ProcessPositionalMode(const sptr<AAFwk::IInterface> &value, const nlohmann::json &paramConfig,
    std::vector<std::pair<int, std::string>> &positionalParams)
{
    // POSITIONAL mode: handle order and order arrays
    if (!paramConfig.contains("order")) {
        return;
    }

    auto orderValue = paramConfig["order"];
    if (!orderValue.is_number_integer()) {
        return;
    }

    // Single order value
    std::string strValue = GetParamStringValue(value);
    if (!strValue.empty()) {
        positionalParams.push_back({orderValue.get<int32_t>(), strValue});
    }
}

void ToolUtil::ProcessFlattenedMode(const std::string &key, const sptr<AAFwk::IInterface> &value,
    const nlohmann::json &paramConfig, const AAFwk::WantParams &args, std::string &cmdLine)
{
    // FLATTENED mode: handle both single template and multiple templates
    std::string separator = ".";
    if (paramConfig.contains("separator")) {
        separator = paramConfig["separator"].get<std::string>();
    }

    if (!paramConfig.contains("template")) {
        return;
    }

    // Single template
    ApplyFlattenedModeToSingleParam(key, value, separator, paramConfig["template"], args, cmdLine);
}

void ToolUtil::ProcessJsonStringTemplate(const std::string &key, const sptr<AAFwk::IInterface> &value,
    const nlohmann::json &templateValue, std::string &cmdLine)
{
    if (value == nullptr) {
        TAG_LOGW(AAFwkTag::CLI_TOOL, "Param '%{public}s' value is null", key.c_str());
        return;
    }

    std::string tmpl = templateValue.get<std::string>();
    std::string jsonStr = ConvertValueToJson(key, value);

    // Apply template with JSON string
    std::string formatted = FormatTemplate(tmpl, jsonStr);
    cmdLine += " " + formatted;
}

void ToolUtil::ProcessBooleanTemplate(const std::string &key, const sptr<AAFwk::IInterface> &value,
    const nlohmann::json &templateValue, std::string &cmdLine)
{
    bool boolValue = false;
    if (!GetParamBoolValue(value, boolValue)) {
        return;
    }

    std::string flag = "";
    if (boolValue && templateValue.contains("if_true")) {
        flag = templateValue["if_true"].get<std::string>();
    } else if (!boolValue && templateValue.contains("if_false")) {
        flag = templateValue["if_false"].get<std::string>();
    }

    if (!flag.empty()) {
        cmdLine += " " + flag;
    }
}

std::string ToolUtil::ConvertValueToJson(const std::string &key, const sptr<AAFwk::IInterface> &value)
{
    // Check if value is a WantParams (nested object)
    AAFwk::WantParams nestedWantParams;
    if (ExtractWantParams(value, nestedWantParams)) {
        // Recursively convert nested WantParams to JSON
        std::string jsonStr = WantParamsToJson(nestedWantParams);
        TAG_LOGI(AAFwkTag::CLI_TOOL, "Param '%{public}s' is nested WantParams, converted to: %{public}s",
            key.c_str(), jsonStr.c_str());
        return jsonStr;
    }

    // Convert IInterface to JSON string
    std::string jsonStr = GetParamJsonValue(value);
    TAG_LOGI(AAFwkTag::CLI_TOOL, "Param '%{public}s' converted to JSON: %{public}s",
        key.c_str(), jsonStr.c_str());
    return jsonStr;
}

void ToolUtil::ProcessFlattenedTemplate(const std::string &flattenedKey, const nlohmann::json &templateValue,
    const std::string &separator, const AAFwk::WantParams &args, std::string &cmdLine)
{
    // Query nested value - simplifed version
    sptr<AAFwk::IInterface> value = QueryNestedValue(args, flattenedKey, separator);
    if (value == nullptr) {
        return;
    }

    // Process template based on type
    if (templateValue.is_string()) {
        std::string strValue = GetParamStringValue(value);
        if (!strValue.empty()) {
            std::string formatted = FormatTemplate(templateValue.get<std::string>(), strValue);
            cmdLine += " " + formatted;
        }
    } else if (templateValue.is_object()) {
        ProcessBooleanTemplate(flattenedKey, value, templateValue, cmdLine);
    }
}

void ToolUtil::ProcessArrayExpansion(const sptr<AAFwk::IInterface> &value, const std::string &tmpl,
    std::string &cmdLine)
{
    auto arrayValue = AAFwk::IArray::Query(value);
    if (arrayValue == nullptr) {
        return;
    }

    long arrayLength = 0;
    if (arrayValue->GetLength(arrayLength) != ERR_OK || arrayLength <= 0) {
        return;
    }

    // Iterate through array elements and expand to command line
    for (long i = 0; i < arrayLength; ++i) {
        sptr<AAFwk::IInterface> elementValue;
        if (arrayValue->Get(i, elementValue) != ERR_OK || elementValue == nullptr) {
            continue;
        }

        // Skip nested arrays
        if (AAFwk::IArray::Query(elementValue) != nullptr) {
            continue;
        }

        std::string elementStr = GetParamStringValue(elementValue);
        if (!elementStr.empty()) {
            std::string formatted = FormatTemplate(tmpl, elementStr);
            cmdLine += " " + formatted;
        }
    }
}

std::vector<std::string> ToolUtil::SplitPathBySeparator(const std::string &path, const std::string &separator)
{
    std::vector<std::string> pathSegments;
    if (path.empty()) {
        return pathSegments;
    }

    std::string sep = separator.empty() ? "." : separator;
    size_t start = 0;
    size_t end = path.find(sep);

    while (end != std::string::npos) {
        std::string segment = path.substr(start, end - start);
        if (!segment.empty()) {
            pathSegments.push_back(segment);
        }
        start = end + sep.length();
        end = path.find(sep, start);
    }
    std::string lastSegment = path.substr(start);
    if (!lastSegment.empty()) {
        pathSegments.push_back(lastSegment);
    }

    return pathSegments;
}

sptr<AAFwk::IInterface> ToolUtil::QueryNestedPath(const AAFwk::WantParams &args,
    const std::vector<std::string> &pathSegments, const std::string &separator)
{
    auto &params = args.GetParams();

    // First level: query from args
    auto firstIt = params.find(pathSegments[0]);
    if (firstIt == params.end()) {
        TAG_LOGI(AAFwkTag::CLI_TOOL, "First level key not found: %{public}s", pathSegments[0].c_str());
        return nullptr;
    }

    sptr<AAFwk::IInterface> currentValue = firstIt->second;

    // Nested levels: traverse through WantParams
    for (size_t i = 1; i < pathSegments.size(); ++i) {
        currentValue = QueryNextLevel(currentValue, pathSegments[i], separator);
        if (currentValue == nullptr) {
            TAG_LOGI(AAFwkTag::CLI_TOOL, "Nested key not found: %{public}s", pathSegments[i].c_str());
            return nullptr;
        }
    }

    TAG_LOGI(AAFwkTag::CLI_TOOL, "Found param with nested traversal: %{public}s",
        pathSegments.size() > 1 ? pathSegments[0].c_str() : "N/A");
    return currentValue;
}

sptr<AAFwk::IInterface> ToolUtil::QueryNextLevel(const sptr<AAFwk::IInterface> &currentValue,
    const std::string &nextSegment, const std::string &separator)
{
    if (currentValue == nullptr) {
        return nullptr;
    }

    AAFwk::WantParams nestedParams;
    if (!ExtractWantParams(currentValue, nestedParams)) {
        return nullptr;
    }

    auto &nestedMap = nestedParams.GetParams();
    auto nestedIt = nestedMap.find(nextSegment);
    if (nestedIt == nestedMap.end()) {
        return nullptr;
    }

    return nestedIt->second;
}

// ============================================================================
// Type validation helpers for ValidateInputSchemaProperties
// ============================================================================

bool ToolUtil::ValidateParamType(const sptr<AAFwk::IInterface> &value, const std::string &expectedType,
    const nlohmann::json &propertySchema, const std::string &key)
{
    if (value == nullptr) {
        TAG_LOGW(AAFwkTag::CLI_TOOL, "value is null for key '%{public}s'", key.c_str());
        return false;
    }
    if (expectedType == "array") {
        return ValidateArrayType(value, propertySchema, key);
    }
    if (expectedType == "object") {
        return ValidateObjectType(value, propertySchema, key);
    }
    return ValidateBasicType(value, expectedType);
}

bool ToolUtil::ValidateBasicType(const sptr<AAFwk::IInterface> &value, const std::string &expectedType)
{
    if (expectedType == "string") {
        return IsStringType(value);
    }
    if (expectedType == "boolean") {
        return IsBooleanType(value);
    }
    if (expectedType == "integer") {
        return IsIntegerType(value);
    }
    if (expectedType == "number") {
        return IsNumberType(value);
    }
    TAG_LOGW(AAFwkTag::CLI_TOOL, "Unknown type '%{public}s', allowing for compatibility", expectedType.c_str());
    return true;
}

bool ToolUtil::ValidateArrayType(const sptr<AAFwk::IInterface> &value,
    const nlohmann::json &propertySchema, const std::string &key)
{
    if (!IsArrayType(value)) {
        return false;
    }
    if (!propertySchema.contains("items") || !propertySchema["items"].is_object()) {
        return true;
    }
    auto arrayObj = AAFwk::IArray::Query(value);
    if (arrayObj == nullptr) {
        return false;
    }
    return ValidateArrayItems(arrayObj, propertySchema["items"], key);
}

bool ToolUtil::ValidateObjectType(const sptr<AAFwk::IInterface> &value,
    const nlohmann::json &propertySchema, const std::string &key)
{
    if (!IsObjectType(value)) {
        return false;
    }
    AAFwk::WantParams nestedParams;
    if (!ExtractWantParams(value, nestedParams)) {
        return false;
    }
    return ValidateNestedObject(nestedParams, propertySchema, key);
}

bool ToolUtil::ValidateArrayItems(sptr<AAFwk::IArray> arrayObj,
    const nlohmann::json &itemsSchema, const std::string &key)
{
    long arrayLength = 0;
    if (arrayObj->GetLength(arrayLength) != ERR_OK || arrayLength == 0) {
        return true;
    }
    std::string itemType = itemsSchema.value("type", "");
    if (itemType.empty()) {
        return true;
    }
    for (long i = 0; i < arrayLength; ++i) {
        sptr<AAFwk::IInterface> elementValue;
        if (arrayObj->Get(i, elementValue) != ERR_OK || elementValue == nullptr) {
            continue;
        }
        std::string elementKey = key + "[" + std::to_string(i) + "]";
        if (!ValidateParamType(elementValue, itemType, itemsSchema, elementKey)) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Array '%{public}s' element %{public}ld type mismatch, expected: %{public}s",
                key.c_str(), i, itemType.c_str());
            return false;
        }
    }
    return true;
}

bool ToolUtil::ValidateNestedObject(const AAFwk::WantParams &nestedParams,
    const nlohmann::json &objectSchema, const std::string &parentKey)
{
    if (!objectSchema.contains("properties") || !objectSchema["properties"].is_object()) {
        TAG_LOGI(AAFwkTag::CLI_TOOL, "No nested properties defined for '%{public}s', skipping validation",
            parentKey.c_str());
        return true;
    }
    auto nestedProperties = objectSchema["properties"];
    if (objectSchema.contains("required") && objectSchema["required"].is_array()) {
        for (const auto &requiredProp : objectSchema["required"]) {
            if (!requiredProp.is_string()) {
                continue;
            }
            std::string requiredKey = requiredProp.get<std::string>();
            std::string fullKey = parentKey + "." + requiredKey;
            if (nestedParams.GetParams().find(requiredKey) == nestedParams.GetParams().end()) {
                TAG_LOGE(AAFwkTag::CLI_TOOL, "Required nested property '%{public}s' not found", fullKey.c_str());
                return false;
            }
        }
    }
    for (const auto &[nestedKey, nestedValue] : nestedParams.GetParams()) {
        std::string fullKey = parentKey + "." + nestedKey;
        if (!nestedProperties.contains(nestedKey)) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "Nested property '%{public}s' not found in schema", fullKey.c_str());
            return false;
        }
        auto &nestedPropertySchema = nestedProperties[nestedKey];
        if (nestedPropertySchema.contains("type")) {
            std::string expectedType = nestedPropertySchema["type"].get<std::string>();
            if (!ValidateParamType(nestedValue, expectedType, nestedPropertySchema, fullKey)) {
                TAG_LOGE(AAFwkTag::CLI_TOOL, "Nested property '%{public}s' type mismatch, expected: %{public}s",
                    fullKey.c_str(), expectedType.c_str());
                return false;
            }
        }
    }
    return true;
}

bool ToolUtil::IsStringType(const sptr<AAFwk::IInterface> &value)
{
    return AAFwk::IString::Query(value) != nullptr;
}

bool ToolUtil::IsBooleanType(const sptr<AAFwk::IInterface> &value)
{
    return AAFwk::IBoolean::Query(value) != nullptr;
}

bool ToolUtil::IsIntegerType(const sptr<AAFwk::IInterface> &value)
{
    return AAFwk::IInteger::Query(value) != nullptr || AAFwk::ILong::Query(value) != nullptr;
}

bool ToolUtil::IsNumberType(const sptr<AAFwk::IInterface> &value)
{
    return AAFwk::IInteger::Query(value) != nullptr ||
           AAFwk::ILong::Query(value) != nullptr ||
           AAFwk::IFloat::Query(value) != nullptr ||
           AAFwk::IDouble::Query(value) != nullptr;
}

bool ToolUtil::IsArrayType(const sptr<AAFwk::IInterface> &value)
{
    return AAFwk::IArray::Query(value) != nullptr;
}

bool ToolUtil::IsObjectType(const sptr<AAFwk::IInterface> &value)
{
    AAFwk::WantParams wantParams;
    return ExtractWantParams(value, wantParams);
}

} // namespace CliTool
} // namespace OHOS
