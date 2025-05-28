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

#ifndef OHOS_ABILITY_RUNTIME_ETS_ABILITY_DELEGATOR_H
#define OHOS_ABILITY_RUNTIME_ETS_ABILITY_DELEGATOR_H

#include <string>
#include "ability_delegator.h"
#include "context.h"
#include "ets_ability_stage_monitor.h"
#include "ets_ability_delegator_registry.h"
#include "ets_ability_monitor.h"
#include "iability_monitor.h"
#include "sts_runtime.h"
#include "want.h"
namespace OHOS {
namespace AbilityDelegatorEts {
using namespace OHOS::AbilityRuntime;
class EtsAbilityDelegator {
public:
    EtsAbilityDelegator();
    ~EtsAbilityDelegator();
    static void ExecuteShellCommand(ani_env* env, [[maybe_unused]]ani_object object,
        ani_string cmd, ani_double timeoutSecs, ani_object callback);

    static void FinishTest(ani_env* env, [[maybe_unused]]ani_object object,
        ani_string msg, ani_double code, ani_object callback);

    static ani_object CreateEtsBaseContext(ani_env* aniEnv, ani_class contextClass,
        std::shared_ptr<AbilityRuntime::Context> context);

    static ani_object GetAppContext(ani_env* env, [[maybe_unused]]ani_object object, ani_class clss);

    static void PrintSync(ani_env *env, [[maybe_unused]]ani_class aniClass, ani_string msg);

    static void AddAbilityMonitor(ani_env *env, [[maybe_unused]]ani_class aniClass,
        ani_object monitorObj, ani_object callback);

    static void StartAbility(ani_env* env, [[maybe_unused]]ani_object object, ani_object wantObj, ani_object callback);

    static ani_ref GetCurrentTopAbility(ani_env* env);

private:
    [[maybe_unused]]static void RetrieveStringFromAni(ani_env *env, ani_string string, std::string &resString);

    static ani_object WrapShellCmdResult(ani_env* env, std::unique_ptr<AppExecFwk::ShellCmdResult> result);

    static bool ParseMonitorPara(ani_env *env, ani_object monitorObj,
        std::shared_ptr<EtsAbilityMonitor> &monitorImpl);

    static bool ParseMonitorParaInner(ani_env *env, ani_object monitorObj,
        std::shared_ptr<EtsAbilityMonitor> &monitorImpl);
};
} // namespace AbilityDelegatorEts
} // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_ETS_ABILITY_DELEGATOR_H
