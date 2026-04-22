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

#include <map>
#include <string>
#include <vector>

#include "bundle_info.h"
#include "cli_session_info.h"
#include "tool_info.h"

namespace OHOS {
namespace CliTool {

class ToolUtil {
public:
    static ToolUtil &GetInstance();

    // 禁止拷贝和移动
    ToolUtil(const ToolUtil &) = delete;
    ToolUtil &operator=(const ToolUtil &) = delete;
    ToolUtil(ToolUtil &&) = delete;
    ToolUtil &operator=(ToolUtil &&) = delete;

    /**
     * @brief 验证inputSchema中的properties
     * @param inputSchema JSON格式的schema字符串
     * @param toolName 工具名称（string类型）
     * @param subcommand 子命令（string类型）
     * @param args 参数map（map<string, string>类型）
     * @return 验证成功返回true，否则返回false
     */
    bool ValidateInputSchemaProperties(const std::string &inputSchema,
        const std::string &toolName, const std::string &subcommand,
        const std::map<std::string, std::string> &args);

    /**
     * @brief 创建管道并设置非阻塞
     * @param pipeFd 管道文件描述符数组 [0]=读端, [1]=写端
     * @return 创建成功返回true，否则返回false
     */
    bool CreatePipe(int pipeFd[2]);

    /**
     * @brief 在子进程中执行工具
     * @param toolInfo 工具信息
     * @param subcommand 子命令
     * @param args 参数map
     * @param stdoutPipe 标准输出管道
     * @param stderrPipe 标准错误管道
     */
    void ExecuteChildProcess(std::string &cmdLine, const std::string &sandboxConfig,
        const std::map<std::string, std::string> &args, int stdoutPipe[], int stderrPipe[]);

    std::string GenerateCliSessionId(const std::string &name, int64_t startTime, int32_t counter) const;

    void ConstructSessionInfo(CliSessionInfo &session, const std::string &toolName, int32_t counter);

    bool GenerateSandboxConfig(const std::string &challenge, std::string &sandboxConfig) const;

    bool GetBundleInfoByTokenId(AppExecFwk::BundleInfo &bundleInfo) const;

private:
    ToolUtil() = default;
    ~ToolUtil() = default;
};

} // namespace CliTool
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_TOOL_UTIL_H
