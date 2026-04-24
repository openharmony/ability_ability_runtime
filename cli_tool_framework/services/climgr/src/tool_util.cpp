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

#include <nlohmann/json.hpp>
#include <random>

#include "accesstoken_kit.h"
#include "bundle_info.h"
#include "bundle_mgr_helper.h"
#include "cli_error_code.h"
#include "hilog_tag_wrapper.h"
#include "ipc_skeleton.h"
#include "string_wrapper.h"
#include "tool_info.h"
#include "want_params.h"

namespace OHOS {
namespace CliTool {
int32_t ToolUtil::ValidateProperties(const ToolInfo &toolInfo, const std::string &subcommand,
    const AAFwk::WantParams &args)
{
    if (!subcommand.empty()) {
        if (!toolInfo.hasSubCommand) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "not have subcommand");
            return ERR_INVALID_PARAM;
        }

        if (toolInfo.subcommands.find(subcommand) == toolInfo.subcommands.end()) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "not have subcommand");
            return ERR_INVALID_PARAM;
        }
    }

    return ValidateInputSchemaProperties(toolInfo.inputSchema, args);
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
    for (auto &[key, vlue] : args.GetParams()) {
        if (!properties.contains(key)) {
            TAG_LOGE(AAFwkTag::CLI_TOOL, "args key not found in properties");
            return ERR_INVALID_PARAM;
        }
    }
    return ERR_OK;
}

std::string ToolUtil::GenerateCliSessionId(const std::string &name)
{
    std::random_device seed;
    std::mt19937 rng(seed());
    std::uniform_int_distribution<int> uni(0, INT_MAX);
    int randomDigit = uni(rng);
    auto timestamp = std::chrono::system_clock::now().time_since_epoch();
    auto time = std::chrono::duration_cast<std::chrono::seconds>(timestamp).count();
    return name + "_" + std::to_string(time) + "_" + std::to_string(randomDigit);
}

bool ToolUtil::GenerateSandboxConfig(const std::string &challenge, std::string &sandboxConfig)
{
    AppExecFwk::BundleInfo bundleInfo;
    if (!ToolUtil::GetBundleInfoByTokenId(bundleInfo)) {
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
    return true;
}

bool ToolUtil::GetBundleInfoByTokenId(AppExecFwk::BundleInfo &bundleInfo)
{
    OHOS::Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType != Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        TAG_LOGE(AAFwkTag::CLI_TOOL, "caller is not hap");
        return false;
    }
    Security::AccessToken::HapTokenInfo hapInfo;
    auto ret = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(tokenId, hapInfo);
    if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
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
        if (bundleMgrHelper->GetBundleInfo(hapInfo.bundleName, flag, bundleInfo, hapInfo.userID) != ERR_OK) {
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

void ToolUtil::TransferToCmdParam(const AAFwk::WantParams &args, std::string &cmdLine)
{
    for (const auto &[key, value] : args.GetParams()) {
        if (AAFwk::IString::Query(value) != nullptr) {
            AAFwk::IString *ao = AAFwk::IString::Query(value);
            if (ao != nullptr) {
                cmdLine += " " + key + " " + AAFwk::String::Unbox(ao);
            }
        }
    }
}

} // namespace CliTool
} // namespace OHOS
