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

#include "app_mgr_client.h"

#include "mock_my_flag.h"

namespace OHOS {
int32_t AgentRuntime::MyFlag::retGetBundleNameByPid = 0;
namespace AppExecFwk {
const std::string BUNDLE_NAME = "mockBundleName";
AppMgrClient::AppMgrClient()
{}

AppMgrClient::~AppMgrClient()
{}

int32_t AppMgrClient::GetRunningProcessInfoByPid(const pid_t pid, OHOS::AppExecFwk::RunningProcessInfo &info) const
{
    info.state_ = AgentRuntime::MyFlag::processState;
    return AgentRuntime::MyFlag::retGetProcessRunningInfoByPid;
}

int32_t AppMgrClient::GetBundleNameByPid(const int pid, std::string &bundleName, int32_t &uid)
{
    bundleName = BUNDLE_NAME;
    return AgentRuntime::MyFlag::retGetBundleNameByPid;
}
}  // namespace AppExecFwk
}  // namespace OHOS
