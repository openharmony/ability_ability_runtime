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

#include "ability_keep_alive_data_manager.h"

#include "ability_manager_errors.h"

namespace OHOS {
namespace AbilityRuntime {
int32_t AbilityKeepAliveDataManager::callSetResult = ERR_OK;
int32_t AbilityKeepAliveDataManager::callInsertResult = ERR_OK;
int32_t AbilityKeepAliveDataManager::callDeleteResult = ERR_OK;
int32_t AbilityKeepAliveDataManager::callQueryDataResult = ERR_OK;
int32_t AbilityKeepAliveDataManager::callQueryApplicationResult = ERR_OK;
KeepAliveSetter AbilityKeepAliveDataManager::queryDataSetter = KeepAliveSetter::UNSPECIFIED;
std::vector<KeepAliveInfo> AbilityKeepAliveDataManager::returnInfoList;

AbilityKeepAliveDataManager &AbilityKeepAliveDataManager::GetInstance()
{
    static AbilityKeepAliveDataManager instance;
    return instance;
}

AbilityKeepAliveDataManager::AbilityKeepAliveDataManager() {}

AbilityKeepAliveDataManager::~AbilityKeepAliveDataManager() {}

int32_t AbilityKeepAliveDataManager::InsertKeepAliveData(const KeepAliveInfo &info)
{
    return callInsertResult;
}

int32_t AbilityKeepAliveDataManager::DeleteKeepAliveData(const KeepAliveInfo &info)
{
    return callDeleteResult;
}

KeepAliveStatus AbilityKeepAliveDataManager::QueryKeepAliveData(const KeepAliveInfo &info)
{
    KeepAliveStatus kaStatus;
    kaStatus.code = callQueryDataResult;
    kaStatus.setter = queryDataSetter;
    return kaStatus;
}

int32_t AbilityKeepAliveDataManager::QueryKeepAliveApplications(
    const KeepAliveInfo &queryParam, std::vector<KeepAliveInfo> &infoList)
{
    infoList = returnInfoList;
    return callQueryApplicationResult;
}
} // namespace AbilityRuntime
} // namespace OHOS
