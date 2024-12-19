/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "child_process_manager_error_utils.h"

#include <map>

namespace OHOS {
namespace AbilityRuntime {
AbilityErrorCode ChildProcessManagerErrorUtil::GetAbilityErrorCode(const ChildProcessManagerErrorCode &internalErrCode)
{
    auto it = INTERNAL_ERR_CODE_MAP.find(internalErrCode);
    if (it != INTERNAL_ERR_CODE_MAP.end()) {
        return it->second;
    }

    return AbilityErrorCode::ERROR_CODE_INNER;
}

ChildProcessManagerErrorCode ChildProcessManagerErrorUtil::GetChildProcessManagerErrorCode(
    int32_t abilityManagerErrorCode)
{
    auto it = ABILITY_MANAGER_ERR_CODE_MAP.find(abilityManagerErrorCode);
    if (it != ABILITY_MANAGER_ERR_CODE_MAP.end()) {
        return it->second;
    }

    return ChildProcessManagerErrorCode::ERR_APP_MGR_FAILED_INNER;
}

Ability_NativeChildProcess_ErrCode ChildProcessManagerErrorUtil::CvtChildProcessManagerErrCode(
    ChildProcessManagerErrorCode cpmErr)
{
    auto it = CPM_ERRCODE_MAP.find(cpmErr);
    if (it == CPM_ERRCODE_MAP.end()) {
        return NCP_ERR_INTERNAL;
    }

    return it->second;
}
} // namespace AbilityRuntime
} // namespace OHOS