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

#ifndef OHOS_ABILITY_RUNTIME_EXEC_TOOL_CALLBACK_IMPL_H
#define OHOS_ABILITY_RUNTIME_EXEC_TOOL_CALLBACK_IMPL_H

#include <functional>

#include "cli_session_info.h"
#include "exec_tool_callback_stub.h"

namespace OHOS {
namespace CliTool {
namespace {
using ExecToolResultTask = std::function<void(const CliSessionInfo &session)>;
}

class ExecToolCallbackImpl : public ExecToolCallbackStub {
public:
    explicit ExecToolCallbackImpl(ExecToolResultTask &&task) : task_(task) {}
    virtual ~ExecToolCallbackImpl() = default;

    int32_t SendResult(const CliSessionInfo &session) override;

private:
    ExecToolResultTask task_;
};
}  // namespace CliTool
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_EXEC_TOOL_CALLBACK_IMPL_H
