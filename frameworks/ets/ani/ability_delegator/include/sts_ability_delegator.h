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
namespace OHOS {
namespace AbilityDelegatorSts {
ani_object ExecuteShellCommand(ani_env* env, std::string &cmd, int timeoutSecs = 0);
ani_int FinishTestSync(std::string &msg, int64_t &code);
ani_object CreateStsBaseContext(ani_env* aniEnv, ani_class contextClass,
    std::shared_ptr<AbilityRuntime::Context> context);
ani_object GetAppContext(ani_env* env, ani_class clss);
void PrintSync(ani_env *env, [[maybe_unused]]ani_class aniClass, ani_string msg);
void AddAbilityMonitorASync(ani_env *env, [[maybe_unused]]ani_class aniClass, ani_object monitor);
} // namespace AbilityDelegatorSts
} // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_STS_ABILITY_DELEGATOR_H
