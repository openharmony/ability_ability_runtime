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

#include "exec_tool_callback_impl.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace CliTool {
int32_t ExecToolCallbackImpl::SendResult(const CliSessionInfo &session)
{
    TAG_LOGI(AAFwkTag::CLI_TOOL, "ExecToolCallbackImpl send result, sessionId=%{public}s, status=%{public}s",
        session.sessionId.c_str(), session.status.c_str());
    if (task_) {
        TAG_LOGD(AAFwkTag::CLI_TOOL, "ExecToolCallbackImpl invoke callback");
        task_(session);
    }
    return ERR_OK;
}
}  // namespace CliTool
}  // namespace OHOS
