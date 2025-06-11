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

#ifndef OHOS_ABILITY_RUNTIME_ETS_ERROR_UTILS_H
#define OHOS_ABILITY_RUNTIME_ETS_ERROR_UTILS_H

#include "ability_business_error.h"
#include "ani.h"

namespace OHOS {
namespace AbilityRuntime {
void ThrowEtsError(ani_env *env, ani_object err);
void ThrowEtsError(ani_env *env, int32_t errCode, const std::string &errorMsg = "");
void ThrowEtsError(ani_env *env, const AbilityErrorCode &err);
void ThrowEtsInvalidCallerError(ani_env *env);
void ThrowEtsTooFewParametersError(ani_env *env);
void ThrowEtsInvalidNumParametersError(ani_env *env);
void ThrowEtsNoPermissionError(ani_env *env, const std::string &permission);
void ThrowEtsInvalidParamError(ani_env *env, const std::string &message);
void ThrowEtsErrorByNativeErr(ani_env *env, int32_t err);
void ThrowEtsNotSystemAppError(ani_env *env);

ani_object CreateEtsError(ani_env *env, const AbilityErrorCode &err);
ani_object CreateEtsError(ani_env *env, ani_int code, const std::string &msg);
ani_object CreateEtsInvalidParamError(ani_env *env, const std::string &message);
ani_object CreateEtsNoPermissionError(ani_env *env, const std::string &permission);
ani_object CreateEtsErrorByNativeErr(ani_env *env, int32_t err, const std::string &permission = "");
ani_object WrapEtsError(ani_env *env, const std::string &msg);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_ERROR_UTILS_H
