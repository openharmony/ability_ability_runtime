/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "ability_keep_alive_service.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AAFwk;
int32_t AbilityKeepAliveService::callSetResult = ERR_OK;
int32_t AbilityKeepAliveService::callQueryResult = ERR_OK;
bool AbilityKeepAliveService::callIsKeepAliveResult = false;
int32_t AbilityKeepAliveService::callGetResult = ERR_OK;
int32_t AbilityKeepAliveService::callSetAppServiceExtensionResult = ERR_OK;
int32_t AbilityKeepAliveService::callQueryAppServiceExtensionResult = ERR_OK;
int32_t AbilityKeepAliveService::callClearKeepAliveAppServiceExtensionResult = ERR_OK;
bool AbilityKeepAliveService::getInfoList = true;
int32_t AbilityKeepAliveService::callIsKeepAliveTimes = 0;

AbilityKeepAliveService &AbilityKeepAliveService::GetInstance()
{
    static AbilityKeepAliveService instance;
    return instance;
}

AbilityKeepAliveService::AbilityKeepAliveService() {}

AbilityKeepAliveService::~AbilityKeepAliveService() {}

int32_t AbilityKeepAliveService::SetApplicationKeepAlive(KeepAliveInfo &info, bool flag)
{
    return callSetResult;
}

int32_t AbilityKeepAliveService::QueryKeepAliveApplications(int32_t userId,
    int32_t appType, std::vector<KeepAliveInfo> &infoList)
{
    return callQueryResult;
}

bool AbilityKeepAliveService::IsKeepAliveApp(const std::string &bundleName, int32_t userId)
{
    callIsKeepAliveTimes++;
    return callIsKeepAliveResult;
}

int32_t AbilityKeepAliveService::GetKeepAliveApplications(int32_t userId, std::vector<KeepAliveInfo> &infoList)
{
    if (getInfoList) {
        KeepAliveInfo info;
        info.bundleName = "mockTestBundle";
        infoList.push_back(info);
    }
    return callGetResult;
}

int32_t AbilityKeepAliveService::SetAppServiceExtensionKeepAlive(KeepAliveInfo &info, bool flag)
{
    return callSetAppServiceExtensionResult;
}

int32_t AbilityKeepAliveService::QueryKeepAliveAppServiceExtensions(std::vector<KeepAliveInfo> &infoList)
{
    return callQueryAppServiceExtensionResult;
}

int32_t AbilityKeepAliveService::ClearKeepAliveAppServiceExtension(const KeepAliveInfo &info)
{
    return callClearKeepAliveAppServiceExtensionResult;
}
} // namespace AbilityRuntime
} // namespace OHOS
