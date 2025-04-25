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

#ifndef OHOS_ABILITY_RUNTIME_SIMULATOR_STS_ABILITY_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_SIMULATOR_STS_ABILITY_CONTEXT_H

#include "sts_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
static ani_int grantUriPermissionPromiseSync([[maybe_unused]]ani_env *env,
    ani_string uri, ani_enum_item flagEnum, ani_string targetName);
static void grantUriPermissionPromiseWithAppCloneIndexSync([[maybe_unused]]ani_env *env,
    ani_string uri, ani_enum_item flagEnum, ani_string targetName, ani_int appCloneIndex);
static void grantUriPermissionCallbackSync([[maybe_unused]]ani_env *env,
    ani_string uri, ani_enum_item flagEnum, ani_string targetName, ani_object callback);
static ani_int revokeUriPermissionPromiseSync([[maybe_unused]]ani_env *env,
    ani_string uri, ani_string targetName);
static void revokeUriPermissionPromiseWithAppCloneIndexSync([[maybe_unused]]ani_env *env,
    ani_string uri, ani_string targetName, ani_int appCloneIndex);
static void revokeUriPermissionCallbackSync([[maybe_unused]]ani_env *env,
    ani_string uri, ani_string targetName, ani_object callback);
void CreateJsUriPermMgr(ani_env *env);
bool AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result);
ani_object WrapBusinessError(ani_env *env, ani_int code);
ani_object WrapError(ani_env *env, const std::string &msg);
ani_string GetAniString(ani_env *env, const std::string &str);
ani_object createDouble(ani_env *env, int32_t res);
std::string GetErrMsg(int32_t err, const std::string &permission = "");
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ABILITY_STAGE_H