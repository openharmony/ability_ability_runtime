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

#include "ability_record_mgr.h"
#include "hilog_tag_wrapper.h"
namespace OHOS {
namespace AppExecFwk {
/**
 * @brief Get the token witch is set to the AbilityRecordMgr.
 *
 * @return Returns the token which is set to the AbilityRecordMgr.
 */
sptr<IRemoteObject> AbilityRecordMgr::GetToken() const
{
    return tokens_;
}

/**
 * @brief Set the token witch the app launched.
 *
 * @param token The token which the is launched by app.
 */
void AbilityRecordMgr::SetToken(const sptr<IRemoteObject> &token)
{
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null token");
        return;
    }
    tokens_ = token;
}

/**
 * @brief Save the token and abilityRecord to the AbilityRecordMgr.
 *
 * @param token The token which the abilityRecord belongs to.
 * @param abilityRecord the abilityRecord witch contains the context info belong the the ability.
 *
 */
void AbilityRecordMgr::AddAbilityRecord(
    const sptr<IRemoteObject> &token, const std::shared_ptr<AbilityLocalRecord> &abilityRecord)
{
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null token");
        return;
    }

    if (abilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null abilityRecord");
        return;
    }
    abilityRecords_[token] = abilityRecord;
}

/**
 * @brief Remove the abilityRecord by token.
 *
 * @param token The token which the abilityRecord belongs to.
 *
 */
void AbilityRecordMgr::RemoveAbilityRecord(const sptr<IRemoteObject> &token)
{
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null token");
        return;
    }
    abilityRecords_.erase(token);
}

/**
 * @brief Get the number of abilityRecords which the AbilityRecordMgr saved.
 *
 * @return Return the number of abilityRecords which the AbilityRecordMgr saved.
 *
 */
int AbilityRecordMgr::GetRecordCount() const
{
    return abilityRecords_.size();
}

/**
 * @brief Get the abilityRecord by token.
 *
 * @param token The token which the abilityRecord belongs to.
 *
 */
std::shared_ptr<AbilityLocalRecord> AbilityRecordMgr::GetAbilityItem(const sptr<IRemoteObject> &token) const
{
    if (token == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null token");
        return nullptr;
    }

    const auto &iter = abilityRecords_.find(token);
    if (iter != abilityRecords_.end()) {
        return iter->second;
    }
    TAG_LOGW(AAFwkTag::APPKIT, "not found ability");
    return nullptr;
}

/**
 * @brief Get the all tokens in the abilityRecordMgr.
 *
 * @return all tokens in the abilityRecordMgr.
 *
 */
std::vector<sptr<IRemoteObject>> AbilityRecordMgr::GetAllTokens()
{
    std::vector<sptr<IRemoteObject>> tokens;
    for (auto it = abilityRecords_.begin(); it != abilityRecords_.end(); ++it) {
        sptr<IRemoteObject> token = it->first;
        tokens.emplace_back(token);
    }
    return tokens;
}
} // namespace AppExecFwk
} // namespace OHOS
