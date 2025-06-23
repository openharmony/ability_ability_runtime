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

#include "../../mock/include/mock_permission_verification.h"
#include "../../mock/include/mock_my_flag.h"

namespace OHOS {
namespace AAFwk {
bool PermissionVerification::VerifyCallingPermission(const std::string &permissionName) const
{
    return MyFlag::verifyCallingPermissionFlag_;
}

bool PermissionVerification::IsSACall() const
{
    return (MyFlag::flag_);
}

bool PermissionVerification::CheckSpecificSystemAbilityAccessPermission(const std::string &processName) const
{
    MyFlag::usedCheckSpecificTimes_++;
    return MyFlag::checkSpecificFlag_;
}

bool PermissionVerification::JudgeCallerIsAllowedToUseSystemAPI() const
{
    return MyFlag::isAllowedToUseSystemAPIFlag_;
}

bool PermissionVerification::VerifyInstallBundlePermission() const
{
    return MyFlag::isVerifyInstallBundlePermission_;
}

bool PermissionVerification::VerifyGetBundleInfoPrivilegedPermission() const
{
    return MyFlag::isVerifyPrivilegedPermission_;
}
} // namespace AAFwk
} // namespace OHOS
