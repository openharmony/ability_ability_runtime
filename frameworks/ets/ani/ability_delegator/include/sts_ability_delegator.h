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

#ifndef OHOS_ABILITY_RUNTIME_STS_ABILITY_DELEGATOR_H
#define OHOS_ABILITY_RUNTIME_STS_ABILITY_DELEGATOR_H

#include <string>
#include "context.h"
#include "sts_runtime.h"
#include "want.h"
namespace OHOS {
namespace AbilityDelegatorSts {
void ExecuteShellCommand(ani_env* env, [[maybe_unused]]ani_object object,
    ani_string cmd, ani_double timeoutSecs, ani_object callback);
void FinishTestSync(ani_env* env, [[maybe_unused]]ani_object object,
    ani_string msg, ani_double code, ani_object callback);
ani_object CreateStsBaseContext(ani_env* aniEnv, ani_class contextClass,
    std::shared_ptr<AbilityRuntime::Context> context);
ani_object GetAppContext(ani_env* env, [[maybe_unused]]ani_object object, ani_class clss);
void PrintSync(ani_env *env, [[maybe_unused]]ani_class aniClass, ani_string msg);
void AddAbilityMonitorASync(ani_env *env, [[maybe_unused]]ani_class aniClass, ani_object monitor, ani_object callback);
void StartAbility(ani_env* env, [[maybe_unused]]ani_object object, ani_object wantObj, ani_object callback);
[[maybe_unused]]static void RetrieveStringFromAni(ani_env *env, ani_string string, std::string &resString);
ani_ref GetCurrentTopAbilitySync(ani_env* env);
void SetEtsVm(ani_vm *aniVM);
} // namespace AbilityDelegatorSts
} // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_STS_ABILITY_DELEGATOR_H
