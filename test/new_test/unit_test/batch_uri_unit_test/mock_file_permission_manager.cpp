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

#include "file_permission_manager.h"

namespace OHOS {
namespace AAFwk {

std::vector<bool> FilePermissionManager::CheckUriPersistentPermission(std::vector<Uri> &uriVec, uint32_t callerTokenId,
    uint32_t flag, const std::string &bundleName, std::vector<PolicyInfo> &pathPolicies)
{
    return std::vector<bool>(uriVec.size(), true);
}

PolicyInfo FilePermissionManager::GetPathPolicyInfoFromUri(Uri &uri, uint32_t flag, const std::string &bundleName)
{
    PolicyInfo policyInfo;
    policyInfo.path = uri.ToString();
    policyInfo.mode = flag;
    return policyInfo;
}

}  // namespace AAFwk
}  // namespace OHOS
