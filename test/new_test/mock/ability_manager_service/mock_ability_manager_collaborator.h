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

#ifndef OHOS_ABILITY_RUNTIME_IABILITY_MANAGER_COLLABORATOR_H
#define OHOS_ABILITY_RUNTIME_IABILITY_MANAGER_COLLABORATOR_H

#include <string>
#include <vector>

namespace OHOS {
namespace AAFwk {
class MockAbilityManagerCollaborator {
public:
    /**
     * @brief Notify collaborator grant uri permission started.
     * @param uris The uri list to grant permission.
     * @param flag Want::FLAG_AUTH_READ_URI_PERMISSION or Want::FLAG_AUTH_WRITE_URI_PERMISSION.
     * @param userId The user id of target application.
     * @return 0 when on success or else failed.
     */
    int32_t NotifyGrantUriPermissionStart(const std::vector<std::string> &uris, uint32_t flag, int32_t userId)
    {
        return 0;
    }

    /**
     * @brief Notify collaborator grant uri Permission finished.
     * @param uris The uri list to grant permission.
     * @param flag Want::FLAG_AUTH_READ_URI_PERMISSION or Want::FLAG_AUTH_WRITE_URI_PERMISSION.
     * @param userId The user id of target application.
     * @param checkResults The result of check uri permission.
     * @return 0 when on success or else failed.
     */
    int32_t NotifyGrantUriPermissionEnd(const std::vector<std::string> &uris, uint32_t flag, int32_t userId,
        const std::vector<bool> &checkResults)
    {
        return 0;
    }
};
}  // namespace AAFwk
}  // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_IABILITY_MANAGER_COLLABORATOR_H