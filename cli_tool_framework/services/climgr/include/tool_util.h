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

#ifndef OHOS_ABILITY_RUNTIME_TOOL_UTIL_H
#define OHOS_ABILITY_RUNTIME_TOOL_UTIL_H

#include <string>

#include <access_token.h>

namespace OHOS {
namespace AAFwk {
class WantParams;
}
namespace AppExecFwk {
struct BundleInfo;
}
namespace CliTool {
class ExecToolParam;
class SessionRecord;
class ToolInfo;

using namespace OHOS::Security;

class ToolUtil {
public:
    static int32_t ValidateProperties(const ToolInfo &toolInfo, ExecToolParam &param,
        AccessToken::AccessTokenID tokenId);

    static std::string GenerateCliSessionId(const std::string &name, std::shared_ptr<SessionRecord> record);

    static bool GenerateSandboxConfig(const std::string &challenge, AccessToken::AccessTokenID tokenId,
        std::string &sandboxConfig);

    static void TransferToCmdParam(const AAFwk::WantParams &args, std::string &cmdLine);

private:
    static bool GetBundleInfoByTokenId(AccessToken::AccessTokenID tokenId,
        AppExecFwk::BundleInfo &bundleInfo);
    static int32_t ValidateInputSchemaProperties(const std::string &inputSchema, const AAFwk::WantParams &args);
};

} // namespace CliTool
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_TOOL_UTIL_H
