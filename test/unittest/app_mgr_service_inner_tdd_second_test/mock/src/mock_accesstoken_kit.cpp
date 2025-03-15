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

#include "accesstoken_kit.h"
#include "mock_my_flag.h"

namespace OHOS {
namespace Security {
namespace AccessToken {
int AccessTokenKit::GetKernelPermissions(AccessTokenID tokenID, std::vector<PermissionWithValue> &kernelPermList)
{
    if (tokenID == AppExecFwk::MOCKTOKENID::TOKENID_TWO) {
        PermissionWithValue kernelPermOne = { .permissionName = "ohos.permission.kernel.ALLOW_WRITABLE_CODE_MEMORY",
            .value = "kernelPermOneValue" };
        kernelPermList.emplace_back(kernelPermOne);
    } else if (tokenID == AppExecFwk::MOCKTOKENID::TOKENID_THREE) {
        PermissionWithValue kernelPermOne = { .permissionName = "kernelPermOne", .value = "kernelPermOneValue" };
        kernelPermList.emplace_back(kernelPermOne);
    }
    return 0;
}

int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::vector<std::string> &permissionList,
    std::vector<int32_t> &permStateList, bool crossIpc)
{
    if (tokenID == AppExecFwk::MOCKTOKENID::TOKENID_ONE) {
        return 0;
    } else {
        permStateList.emplace_back(Security::AccessToken::PERMISSION_GRANTED);
        permStateList.emplace_back(Security::AccessToken::PERMISSION_GRANTED);
        permStateList.emplace_back(Security::AccessToken::PERMISSION_GRANTED);
        permStateList.emplace_back(Security::AccessToken::PERMISSION_GRANTED);
        return 0;
    }
}
} // namespace AccessToken
} // namespace Security
} // namespace OHOS