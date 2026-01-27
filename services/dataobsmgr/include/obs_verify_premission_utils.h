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

#ifndef OHOS_ABILITY_RUNTIME_OBS_VERIFY_PERMISSION_UTILS_H
#define OHOS_ABILITY_RUNTIME_OBS_VERIFY_PERMISSION_UTILS_H

#include <string>
#include <vector>
#include <list>
#include <shared_mutex>

#include "uri.h"

namespace OHOS {
namespace AAFwk {
class OBSVerifyPermissionUtils {
public:
    static OBSVerifyPermissionUtils &GetInstance();
    bool VerifyPermission(uint32_t listenerTokenId, int32_t userId, const Uri &uri, uint32_t tokenId);
private:
    std::pair<bool, std::string> GetCallingName(uint32_t callingTokenid);
    std::vector<std::string> GetGroupInfosFromCache(const std::string &bundleName, int32_t userId, const std::string &uri);
    static constexpr int32_t CACHE_SIZE_THRESHOLD = 20;
    std::shared_mutex groupsIdMutex_;
    std::list<std::pair<std::string, std::vector<std::string>>> groupsIdCache_;
};
}
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_OBS_VERIFY_PERMISSION_UTILS_H
