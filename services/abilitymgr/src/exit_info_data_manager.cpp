/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "exit_info_data_manager.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {

bool ExitInfoDataManager::AddExitInfo(uint32_t accessTokenId, ExitCacheInfo &cacheInfo)
{
    if (IsExitInfoExist(accessTokenId)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ExitInfo exist!");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    exitCacheInfos_.insert(std::make_pair(accessTokenId, cacheInfo));
    return true;
}

bool ExitInfoDataManager::DeleteExitInfo(uint32_t accessTokenId)
{
    if (!IsExitInfoExist(accessTokenId)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "ExitInfo not exist!");
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    exitCacheInfos_.erase(accessTokenId);
    return true;
}

bool ExitInfoDataManager::GetExitInfo(uint32_t accessTokenId, ExitCacheInfo &cacheInfo)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto exitInfoIter = exitCacheInfos_.find(accessTokenId);
    if (exitInfoIter == exitCacheInfos_.end()) {
        TAG_LOGW(AAFwkTag::ABILITYMGR, "ExitInfo not exist!");
        return false;
    }
    cacheInfo = exitInfoIter->second;
    exitCacheInfos_.erase(exitInfoIter);
    return true;
}

bool ExitInfoDataManager::GetExitInfo(int32_t pid, int32_t uid, uint32_t &accessTokenId, ExitCacheInfo &cacheInfo)
{
    std::map<uint32_t, ExitCacheInfo>::iterator it;
    std::lock_guard<std::mutex> lock(mutex_);
    for (it = exitCacheInfos_.begin(); it != exitCacheInfos_.end(); ++it) {
        if (it->second.exitInfo.pid == pid && it->second.exitInfo.uid == uid) {
            accessTokenId = it->first;
            cacheInfo = it->second;
            exitCacheInfos_.erase(it);
            return true;
        }
    }
    return false;
}

bool ExitInfoDataManager::IsExitInfoExist(uint32_t accessTokenId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto exitInfoIter = exitCacheInfos_.find(accessTokenId);
    return exitInfoIter != exitCacheInfos_.end();
}
}  // namespace AbilityRuntime
}  // namespace OHOS
