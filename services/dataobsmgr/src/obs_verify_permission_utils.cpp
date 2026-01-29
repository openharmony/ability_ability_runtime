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

#include "obs_verify_permission_utils.h"

#include "bundle_mgr_helper.h"
#include "dataobs_mgr_errors.h"
#include "data_share_permission.h"
#include "ipc_skeleton.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {
using namespace Security::AccessToken;
using namespace AppExecFwk;
OBSVerifyPermissionUtils& OBSVerifyPermissionUtils::GetInstance()
{
    static OBSVerifyPermissionUtils instance_;
    return instance_;
}

bool OBSVerifyPermissionUtils::VerifyPermission(uint32_t listenerTokenId, int32_t userId,
    const Uri &uri, uint32_t tokenId)
{
    if (listenerTokenId == tokenId) {
        return true;
    }
    auto [isSA, listenerCallingName] = GetCallingInfo(listenerTokenId);
    if (isSA) {
        return true;
    }
    Uri uriTemp = uri;
    std::vector<std::string> listenerGroupIds = GetGroupInfosFromCache(listenerCallingName, userId, uri.ToString());
    for (auto &groupId : listenerGroupIds) {
        if (uriTemp.GetAuthority() == groupId) {
            return true;
        }
    }
    std::string scheme = uriTemp.GetScheme();
    std::string errMsg = scheme + " checkfailed:" + std::string(listenerGroupIds.empty() ? "empty" : "notEmpty");
    TAG_LOGE(AAFwkTag::DBOBSMGR, "verify failed listenerCallingName:%{public}s, scheme:%{public}s",
        listenerCallingName.c_str(), scheme.c_str());
    auto invalidUri = (scheme == RELATIONAL_STORE) ? DATAOBS_RDB_INVALID_URI : DATAOBS_PREFERENCE_INVALID_URI;
    DataShare::DataSharePermission::ReportExtensionFault(invalidUri, listenerTokenId, listenerCallingName, errMsg);
    return false;
}

std::pair<bool, std::string> OBSVerifyPermissionUtils::GetCallingInfo(uint32_t callingTokenid)
{
    std::string callingName;
    bool isSA = false;
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callingTokenid);

    int result = -1;
    if (tokenType == Security::AccessToken::TOKEN_HAP) {
        Security::AccessToken::HapTokenInfo tokenInfo;
        result = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(callingTokenid, tokenInfo);
        if (result == Security::AccessToken::RET_SUCCESS) {
            callingName = std::move(tokenInfo.bundleName);
        }
    } else if (tokenType == Security::AccessToken::TOKEN_NATIVE || tokenType == Security::AccessToken::TOKEN_SHELL) {
        Security::AccessToken::NativeTokenInfo tokenInfo;
        result = Security::AccessToken::AccessTokenKit::GetNativeTokenInfo(callingTokenid, tokenInfo);
        isSA = true;
    } else {
        TAG_LOGE(AAFwkTag::DBOBSMGR, "tokenType is invalid, tokenType:%{public}d", tokenType);
    }
    return {isSA, callingName};
}

std::vector<std::string> OBSVerifyPermissionUtils::GetGroupInfosFromCache(const std::string &bundleName,
    int32_t userId, const std::string &uri)
{
    std::string key = uri;
    {
        std::shared_lock<std::shared_mutex> readLock(groupsIdMutex_);
        auto it = std::find_if(groupsIdCache_.begin(), groupsIdCache_.end(),
            [&key](const auto& pair) { return pair.first == key; });
        if (it != groupsIdCache_.end()) {
            return it->second;
        }
    }

    std::vector<DataGroupInfo> infos;
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    auto bmsHelper = DelayedSingleton<BundleMgrHelper>::GetInstance();
    if (bmsHelper == nullptr) {
        TAG_LOGE(AAFwkTag::DBOBSMGR, "bmsHelper is nullptr");
        return {};
    }
    bool res = bmsHelper->QueryDataGroupInfos(bundleName, userId, infos);
    IPCSkeleton::SetCallingIdentity(identity);

    if (!res) {
        TAG_LOGE(AAFwkTag::DBOBSMGR, "query group failed:%{public}s, user:%{public}d", bundleName.c_str(), userId);
        return {};
    }
    std::vector<std::string> groupIds;
    for (auto &it : infos) {
        groupIds.push_back(std::move(it.dataGroupId));
    }
    std::unique_lock<std::shared_mutex> writeLock(groupsIdMutex_);
    auto it = std::find_if(groupsIdCache_.begin(), groupsIdCache_.end(),
        [&key](const auto& pair) { return pair.first == key; });
    if (it != groupsIdCache_.end()) {
        return it->second;
    }
    if (groupsIdCache_.size() >= CACHE_SIZE_THRESHOLD) {
        groupsIdCache_.pop_front();
    }
    groupsIdCache_.emplace_back(key, groupIds);
    return groupIds;
}
}  // namespace AAFwk
}  // namespace OHOS