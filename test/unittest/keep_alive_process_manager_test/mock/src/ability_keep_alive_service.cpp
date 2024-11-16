/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
    return callIsKeepAliveResult;
}

int32_t AbilityKeepAliveService::GetKeepAliveApplications(int32_t userId, std::vector<KeepAliveInfo> &infoList)
{
    return callGetResult;
}
} // namespace AbilityRuntime
} // namespace OHOS
