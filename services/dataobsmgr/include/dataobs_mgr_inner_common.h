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

#ifndef OHOS_ABILITY_RUNTIME_DATAOBS_MGR_INNER_COMMON_H
#define OHOS_ABILITY_RUNTIME_DATAOBS_MGR_INNER_COMMON_H

#include "data_ability_observer_interface.h"
#include <string>

namespace OHOS {
namespace AAFwk {
static const int32_t MAX_OBSERVER_NODE_CNT = 100000;
struct ObserverInfo {
    ObserverInfo() {}
    ObserverInfo(uint32_t tokenId, uint64_t fullTokenId, uint32_t firstCallerTokenId, int32_t userId, bool isExtension)
        : tokenId(tokenId), fullTokenId(fullTokenId), firstCallerTokenId(firstCallerTokenId), userId(userId),
          isFromExtension(isExtension) {}
    uint32_t tokenId = 0;
    uint64_t fullTokenId = 0;
    uint32_t firstCallerTokenId = 0;
    int32_t userId = -1;
    int32_t callingUserId = -1;
    int32_t pid = 0;
    bool isFromExtension = false;
    bool isSilentUri = false;
    std::string permission;
    std::string errMsg;
};

struct ObserverNode {
    sptr<IDataAbilityObserver> observer_ = nullptr;
    int32_t userId_ = -1;
    uint32_t tokenId_ = 0;
    bool isFromExtension_ = false;
    std::string permission_;
    int32_t pid_ = 0;
    int32_t nodeId_ = -1;
    static inline int32_t nextNodeId_ = 1;

    ObserverNode(sptr<IDataAbilityObserver> observer, int32_t userId, uint32_t tokenId, int32_t pid)
        : observer_(observer), userId_(userId), tokenId_(tokenId), pid_(pid)
    {
        nodeId_ = nextNodeId_++;
        if (nextNodeId_ > MAX_OBSERVER_NODE_CNT) {
            // reset nextNodeId_
            nextNodeId_ = 1;
        }
    }

    bool operator==(struct ObserverNode other) const
    {
        return (observer_ == other.observer_) && (userId_ == other.userId_) && (tokenId_ == other.tokenId_);
    }
};

struct NotifyInfo {
    Uri uri = Uri("");
    std::string readPermission;
    bool isSilentUri;
    NotifyInfo(std::string readPermission, bool isSilentUri) : readPermission(readPermission),
        isSilentUri(isSilentUri) {}
    NotifyInfo(Uri uri, std::string readPermission, bool isSilentUri) : uri(uri),
        readPermission(readPermission), isSilentUri(isSilentUri) {}
};

}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_DATAOBS_MGR_INNER_COMMON_H