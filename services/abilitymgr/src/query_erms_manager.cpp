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

#include "query_erms_manager.h"

#include "ability_record.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"

namespace OHOS {
namespace AAFwk {
QueryERMSManager::QueryERMSManager() {}

QueryERMSManager::~QueryERMSManager() {}

QueryERMSManager &QueryERMSManager::GetInstance()
{
    static QueryERMSManager manager;
    return manager;
}

void QueryERMSManager::HandleOnQueryERMSSuccess(int32_t recordId, const std::string &appId,
    const std::string &startTime, const AtomicServiceStartupRule &rule)
{
    TAG_LOGI(AAFwkTag::QUERY_ERMS, "query ERMS succeeded");
    QueryERMSObserverManager::GetInstance().OnQueryFinished(
        recordId, appId, startTime, rule, ERR_OK);
}

void QueryERMSManager::HandleOnQueryERMSFail(int32_t recordId, const std::string &appId, const std::string &startTime,
    const AtomicServiceStartupRule &rule, int resultCode)
{
    TAG_LOGI(AAFwkTag::QUERY_ERMS, "query ERMS failed,resultCode=%{public}d", resultCode);
    QueryERMSObserverManager::GetInstance().OnQueryFinished(
        recordId, appId, startTime, rule, resultCode);
}

void QueryERMSManager::HandleQueryERMSResult(int32_t recordId, const std::string &appId, const std::string &startTime,
    const AtomicServiceStartupRule &rule, int32_t resultCode)
{
    if (resultCode == ERR_OK) {
        HandleOnQueryERMSSuccess(recordId, appId, startTime, rule);
        return;
    }
    HandleOnQueryERMSFail(recordId, appId, startTime, rule, resultCode);
}

void QueryERMSManager::OnQueryFinished(int32_t recordId, const std::string &appId, const std::string &startTime,
    const AtomicServiceStartupRule &rule, int32_t resultCode)
{
    HITRACE_METER_NAME(HITRACE_TAG_ABILITY_MANAGER, __PRETTY_FUNCTION__);
    TAG_LOGI(AAFwkTag::QUERY_ERMS, "resultCode: %{public}d", resultCode);

    HandleQueryERMSResult(recordId, appId, startTime, rule, resultCode);
}

int QueryERMSManager::AddQueryERMSObserver(sptr<IRemoteObject> callerToken,
    sptr<AbilityRuntime::IQueryERMSObserver> observer)
{
    TAG_LOGI(AAFwkTag::QUERY_ERMS, "called");
    if (callerToken == nullptr) {
        TAG_LOGE(AAFwkTag::QUERY_ERMS, "callerToken is null");
        return ERR_INVALID_VALUE;
    }
    auto abilityRecord = Token::GetAbilityRecordByToken(callerToken);
    if (abilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::QUERY_ERMS, "ability record is null");
        return ERR_INVALID_VALUE;
    }
    return QueryERMSObserverManager::GetInstance().AddObserver(abilityRecord->GetRecordId(),
        observer);
}
}  // namespace AAFwk
}  // namespace OHOS
