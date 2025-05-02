/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "mock_data_ability_manager.h"

namespace OHOS {
namespace AAFwk {
using namespace std::chrono;
using namespace std::placeholders;

namespace {
constexpr bool DEBUG_ENABLED = false;
constexpr system_clock::duration DATA_ABILITY_LOAD_TIMEOUT = 11000ms;
}  // namespace

DataAbilityManager::DataAbilityManager()
{
}

DataAbilityManager::~DataAbilityManager()
{
}

sptr<IAbilityScheduler> DataAbilityManager::Acquire(
    const AbilityRequest &abilityRequest, bool tryBind, const sptr<IRemoteObject> &client, bool isNotHap)
{
    return nullptr;
}

int DataAbilityManager::Release(
    const sptr<IAbilityScheduler> &scheduler, const sptr<IRemoteObject> &client, bool isNotHap)
{
    return ERR_OK;
}

bool DataAbilityManager::ContainsDataAbility(const sptr<IAbilityScheduler> &scheduler)
{
    return false;
}

int DataAbilityManager::AttachAbilityThread(const sptr<IAbilityScheduler> &scheduler, const sptr<IRemoteObject> &token)
{
    return ERR_OK;
}

int DataAbilityManager::AbilityTransitionDone(const sptr<IRemoteObject> &token, int state)
{
    return ERR_OK;
}

void DataAbilityManager::OnAbilityRequestDone(const sptr<IRemoteObject> &token, const int32_t state)
{
    /* Do nothing now. */
}

void DataAbilityManager::OnAbilityDied(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
}

void DataAbilityManager::OnAppStateChanged(const AppInfo &info)
{
}

std::shared_ptr<AbilityRecord> DataAbilityManager::GetAbilityRecordById(int64_t id)
{
    return nullptr;
}

std::shared_ptr<AbilityRecord> DataAbilityManager::GetAbilityRecordByToken(const sptr<IRemoteObject> &token)
{
    return nullptr;
}

std::shared_ptr<AbilityRecord> DataAbilityManager::GetAbilityRecordByScheduler(const sptr<IAbilityScheduler> &scheduler)
{
    return nullptr;
}

void DataAbilityManager::Dump(const char *func, int line)
{
}

DataAbilityManager::DataAbilityRecordPtr DataAbilityManager::LoadLocked(
    const std::string &name, const AbilityRequest &req)
{
    return nullptr;
}

void DataAbilityManager::DumpLocked(const char *func, int line)
{
}

void DataAbilityManager::DumpState(std::vector<std::string> &info, const std::string &args) const
{
}

void DataAbilityManager::DumpClientInfo(std::vector<std::string> &info, bool isClient,
    std::shared_ptr<DataAbilityRecord> record) const
{
}

void DataAbilityManager::DumpSysState(std::vector<std::string> &info, bool isClient, const std::string &args) const
{
}

void DataAbilityManager::GetAbilityRunningInfos(std::vector<AbilityRunningInfo> &info, bool isPerm)
{
}

void DataAbilityManager::RestartDataAbility(const std::shared_ptr<AbilityRecord> &abilityRecord)
{
}

void DataAbilityManager::ReportDataAbilityAcquired(const sptr<IRemoteObject> &client, bool isNotHap,
    std::shared_ptr<DataAbilityRecord> &record)
{
}

void DataAbilityManager::ReportDataAbilityReleased(const sptr<IRemoteObject> &client, bool isNotHap,
    std::shared_ptr<DataAbilityRecord> &record)
{
}
}  // namespace AAFwk
}  // namespace OHOS
