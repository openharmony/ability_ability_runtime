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

#include "mock_permission_verification.h"

namespace OHOS {
namespace AAFwk {

bool PermissionVerification::VerifyCallingPermission(const std::string &permissionName) const
{
    return !!(MyFlag::mockFlag_);
}
bool PermissionVerification::IsSACall() const
{
    MyFlag::callCount_++;
    return false;
}
bool PermissionVerification::IsShellCall() const
{
    MyFlag::callCount_++;
    return false;
}
bool PermissionVerification::CheckSpecificSystemAbilityAccessPermission() const
{
    return !!(MyFlag::mockFlag_);
}
bool PermissionVerification::VerifyRunningInfoPerm() const
{
    return !!(MyFlag::mockFlag_);
}
bool PermissionVerification::VerifyControllerPerm() const
{
    return !!(MyFlag::mockFlag_);
}
#ifdef WITH_DLP
bool PermissionVerification::VerifyDlpPermission(Want &want) const
{
    return !!(MyFlag::mockFlag_);
}
#endif // WITH_DLP
int PermissionVerification::VerifyAccountPermission() const
{
    return MyFlag::mockFlag_;
}
bool PermissionVerification::VerifyMissionPermission() const
{
    return !!(MyFlag::mockFlag_);
}
int PermissionVerification::VerifyAppStateObserverPermission() const
{
    return MyFlag::mockFlag_;
}
int32_t PermissionVerification::VerifyUpdateConfigurationPerm() const
{
    return static_cast<int32_t>(MyFlag::mockFlag_);
}
bool PermissionVerification::VerifyInstallBundlePermission() const
{
    return !!(MyFlag::mockFlag_);
}
bool PermissionVerification::VerifyGetBundleInfoPrivilegedPermission() const
{
    return !!(MyFlag::mockFlag_);
}
int PermissionVerification::CheckCallDataAbilityPermission(const VerificationInfo &verificationInfo, bool isShell) const
{
    return MyFlag::mockFlag_;
}
int PermissionVerification::CheckCallServiceAbilityPermission(const VerificationInfo &verificationInfo) const
{
    return MyFlag::mockFlag_;
}
int PermissionVerification::CheckCallAbilityPermission(const VerificationInfo &verificationInfo) const
{
    return MyFlag::mockFlag_;
}
int PermissionVerification::CheckCallServiceExtensionPermission(const VerificationInfo &verificationInfo) const
{
    return MyFlag::mockFlag_;
}
int PermissionVerification::CheckStartByCallPermission(const VerificationInfo &verificationInfo) const
{
    return MyFlag::mockFlag_;
}
unsigned int PermissionVerification::GetCallingTokenID() const
{
    return static_cast<unsigned int>(MyFlag::mockFlag_);
}
bool PermissionVerification::JudgeStartInvisibleAbility(const uint32_t accessTokenId, const bool visible) const
{
    return !!(MyFlag::mockFlag_);
}
bool PermissionVerification::JudgeStartAbilityFromBackground(const bool isBackgroundCall) const
{
    return !!(MyFlag::mockFlag_);
}
bool PermissionVerification::JudgeAssociatedWakeUp(const uint32_t accessTokenId, const bool associatedWakeUp) const
{
    return !!(MyFlag::mockFlag_);
}
int PermissionVerification::JudgeInvisibleAndBackground(const VerificationInfo &verificationInfo) const
{
    return MyFlag::mockFlag_;
}
bool PermissionVerification::JudgeCallerIsAllowedToUseSystemAPI() const
{
    return true;
}
bool PermissionVerification::VerifyPrepareTerminatePermission() const
{
    return true;
}
bool PermissionVerification::IsSystemAppCall() const
{
    return true;
}

bool PermissionVerification::VerifySetProcessCachePermission() const
{
    return true;
}
}  // namespace AAFwk
}  // namespace OHOS