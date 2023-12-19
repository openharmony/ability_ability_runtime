/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "mock_ability_auto_startup_data_manager.h"

#include "hilog_wrapper.h"

namespace {
const std::string THE_FIRST_RETURN_VALUE = "1";
const std::string THE_SECOND_RETURN_VALUE = "2";
const std::string THE_THIRD_RETURN_VALUE = "3";
const std::string THE_FOURTH_RETURN_VALUE = "4";
const std::string THE_FIFTH_RETURN_VALUE = "5";
std::string g_mockQueryAutoStartupData = "";
std::string g_mockCheckAutoStartupData = "";
} // namespace

void MockQueryAutoStartupData(std::string mockQue)
{
    g_mockQueryAutoStartupData = mockQue;
}

void MockCheckAutoStartupData(std::string mockChe)
{
    g_mockCheckAutoStartupData = mockChe;
}

namespace OHOS {
namespace AbilityRuntime {
AbilityAutoStartupDataManager::AbilityAutoStartupDataManager() {}

AbilityAutoStartupDataManager::~AbilityAutoStartupDataManager() {}
int32_t AbilityAutoStartupDataManager::InsertAutoStartupData(
    const AutoStartupInfo &info, bool isAutoStartup, bool isEdmForce)
{
    return ERR_OK;
}

int32_t AbilityAutoStartupDataManager::UpdateAutoStartupData(
    const AutoStartupInfo &info, bool isAutoStartup, bool isEdmForce)
{
    return ERR_OK;
}

int32_t AbilityAutoStartupDataManager::DeleteAutoStartupData(const AutoStartupInfo &info)
{
    return ERR_OK;
}

int32_t AbilityAutoStartupDataManager::DeleteAutoStartupData(const std::string &bundleName)
{
    return ERR_OK;
}

AutoStartupStatus AbilityAutoStartupDataManager::QueryAutoStartupData(const AutoStartupInfo &info)
{
    AutoStartupStatus asustatus;
    if (g_mockQueryAutoStartupData == THE_FIRST_RETURN_VALUE) {
        asustatus.code = ERR_INVALID_VALUE;
    }
    if (g_mockQueryAutoStartupData == THE_SECOND_RETURN_VALUE) {
        asustatus.code = ERR_NAME_NOT_FOUND;
    }
    if (g_mockQueryAutoStartupData == THE_THIRD_RETURN_VALUE) {
        asustatus.code = ERR_OK;
        asustatus.isEdmForce = true;
    }
    if (g_mockQueryAutoStartupData == THE_FOURTH_RETURN_VALUE) {
        asustatus.code = ERR_OK;
        asustatus.isEdmForce = false;
        asustatus.isAutoStartup = false;
    }
    if (g_mockQueryAutoStartupData == THE_FIFTH_RETURN_VALUE) {
        asustatus.code = ERR_OK;
        asustatus.isEdmForce = false;
        asustatus.isAutoStartup = true;
    }
    return asustatus;
}

int32_t AbilityAutoStartupDataManager::QueryAllAutoStartupApplications(std::vector<AutoStartupInfo> &infoList)
{
    return ERR_OK;
}

int32_t AbilityAutoStartupDataManager::GetCurrentAppAutoStartupData(
    const std::string &bundleName, std::vector<AutoStartupInfo> &infoList)
{
    if (g_mockCheckAutoStartupData == THE_FIRST_RETURN_VALUE) {
        return ERR_NO_INIT;
    }
    if (g_mockCheckAutoStartupData == THE_THIRD_RETURN_VALUE) {
        AutoStartupInfo info;
        info.abilityName = "abilityName";
        infoList.push_back(info);
        return ERR_OK;
    }
    return ERR_OK;
}
} // namespace AbilityRuntime
} // namespace OHOS
