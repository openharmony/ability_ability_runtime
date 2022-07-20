/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_PERMISSION_VERIFICATION_UTILS_H
#define OHOS_ABILITY_RUNTIME_PERMISSION_VERIFICATION_UTILS_H

#include <string>

#include "hilog_wrapper.h"
#include "permission_constants.h"
#include "permission_verification.h"

namespace OHOS {
namespace AAFwk {
namespace PermissionVerificationUtils {
const std::string DLP_PARAMS_INDEX = "ohos.dlp.params.index";
const std::string DLP_PARAMS_SECURITY_FLAG = "ohos.dlp.params.securityFlag";

[[maybe_unused]] static bool VerifyDlpPermission(Want &want)
{
    if (want.GetIntParam(DLP_PARAMS_INDEX, 0) == 0) {
        want.RemoveParam(DLP_PARAMS_SECURITY_FLAG);
        return true;
    }
    auto isSaCall = AAFwk::PermissionVerification::GetInstance()->IsSACall();
    if (isSaCall) {
        return true;
    }
    auto isCallingPerm = AAFwk::PermissionVerification::GetInstance()->VerifyCallingPermission(
        PermissionConstants::PERMISSION_ACCESS_DLP);
    if (isCallingPerm) {
        return true;
    }
    HILOG_ERROR("%{public}s: Permission verification failed", __func__);
    return false;
}
}  // namespace PermissionVerificationUtils
}  // namespace AAFwk
}  // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_PERMISSION_VERIFICATION_UTILS_H
