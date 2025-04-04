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

#ifndef OHOS_ABILITY_RUNTIME_CHILD_PROCESS_MANAGER_ERROR_UTILS_H
#define OHOS_ABILITY_RUNTIME_CHILD_PROCESS_MANAGER_ERROR_UTILS_H

#include <map>

#include "ability_business_error.h"
#include "ability_manager_errors.h"
#include "native_child_process.h"

namespace OHOS {
namespace AbilityRuntime {
enum class ChildProcessManagerErrorCode {
    ERR_OK = 0,
    ERR_MULTI_PROCESS_MODEL_DISABLED = 1,
    ERR_ALREADY_IN_CHILD_PROCESS = 2,
    ERR_GET_HAP_INFO_FAILED = 3,
    ERR_FORK_FAILED = 4,
    ERR_GET_BUNDLE_INFO_FAILED = 5,
    ERR_GET_APP_MGR_FAILED = 6,
    ERR_APP_MGR_FAILED_INNER = 7,
    ERR_UNSUPPORT_NATIVE_CHILD_PROCESS = 8,
    ERR_MAX_CHILD_PROCESSES = 9,
    ERR_LIB_LOADING_FAILED = 10,
    ERR_CONNECTION_FAILED = 11,
    ERR_UNSUPPORTED_START_MODE = 12,
    ERR_MULTI_PROCESS_MODEL_DISABLED_NEW = 13,
};

const std::map<ChildProcessManagerErrorCode, AbilityErrorCode> INTERNAL_ERR_CODE_MAP = {
    { ChildProcessManagerErrorCode::ERR_OK, AbilityErrorCode::ERROR_OK },
    { ChildProcessManagerErrorCode::ERR_MULTI_PROCESS_MODEL_DISABLED,
        AbilityErrorCode::ERROR_CODE_OPERATION_NOT_SUPPORTED },
    { ChildProcessManagerErrorCode::ERR_ALREADY_IN_CHILD_PROCESS,
        AbilityErrorCode::ERROR_CODE_OPERATION_NOT_SUPPORTED },
    { ChildProcessManagerErrorCode::ERR_GET_HAP_INFO_FAILED, AbilityErrorCode::ERROR_CODE_INNER },
    { ChildProcessManagerErrorCode::ERR_FORK_FAILED, AbilityErrorCode::ERROR_CODE_INNER },
    { ChildProcessManagerErrorCode::ERR_GET_BUNDLE_INFO_FAILED, AbilityErrorCode::ERROR_CODE_INNER },
    { ChildProcessManagerErrorCode::ERR_GET_APP_MGR_FAILED, AbilityErrorCode::ERROR_CODE_INNER },
    { ChildProcessManagerErrorCode::ERR_APP_MGR_FAILED_INNER, AbilityErrorCode::ERROR_CODE_INNER },
    { ChildProcessManagerErrorCode::ERR_UNSUPPORTED_START_MODE, AbilityErrorCode::ERROR_CODE_INVALID_PARAM },
    { ChildProcessManagerErrorCode::ERR_MULTI_PROCESS_MODEL_DISABLED_NEW,
        AbilityErrorCode::ERROR_CODE_CAPABILITY_NOT_SUPPORT },
    { ChildProcessManagerErrorCode::ERR_MAX_CHILD_PROCESSES,
        AbilityErrorCode::ERROR_CODE_CHILD_PROCESS_NUMBER_EXCEEDS_UPPER_BOUND },
};

const std::map<int32_t, ChildProcessManagerErrorCode> ABILITY_MANAGER_ERR_CODE_MAP = {
    { AAFwk::ERR_NOT_SUPPORT_CHILD_PROCESS, ChildProcessManagerErrorCode::ERR_MULTI_PROCESS_MODEL_DISABLED_NEW },
    { AAFwk::ERR_NOT_SUPPORT_NATIVE_CHILD_PROCESS, ChildProcessManagerErrorCode::ERR_UNSUPPORT_NATIVE_CHILD_PROCESS },
    { AAFwk::ERR_ALREADY_IN_CHILD_PROCESS, ChildProcessManagerErrorCode::ERR_ALREADY_IN_CHILD_PROCESS },
    { AAFwk::ERR_CHILD_PROCESS_REACH_LIMIT, ChildProcessManagerErrorCode::ERR_MAX_CHILD_PROCESSES },
    { ERR_OVERFLOW, ChildProcessManagerErrorCode::ERR_MAX_CHILD_PROCESSES },
};

class ChildProcessManagerErrorUtil {
public:
    static AbilityErrorCode GetAbilityErrorCode(const ChildProcessManagerErrorCode &internalErrCode);
    static ChildProcessManagerErrorCode GetChildProcessManagerErrorCode(int32_t abilityManagerErrorCode);

    static Ability_NativeChildProcess_ErrCode CvtChildProcessManagerErrCode(ChildProcessManagerErrorCode cpmErr);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_CHILD_PROCESS_MANAGER_ERROR_UTILS_H