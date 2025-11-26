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

#ifndef OHOS_ABILITY_RUNTIME_ETS_ABILITY_AUTO_STARTUP_MANAGER_H
#define OHOS_ABILITY_RUNTIME_ETS_ABILITY_AUTO_STARTUP_MANAGER_H

#include "ani.h"
#include "ets_ability_auto_startup_callback.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsAbilityAutoStartupManager {
public:
    EtsAbilityAutoStartupManager() = default;
    ~EtsAbilityAutoStartupManager() = default;
    static void RegisterAutoStartupCallback(ani_env *env, ani_string aniType, ani_object callback);
    static void UnregisterAutoStartupCallback(ani_env *env, ani_string aniType, ani_object callback);
    static void SetApplicationAutoStartup(ani_env *env, ani_object info, ani_object callback);
    static void CancelApplicationAutoStartup(ani_env *env, ani_object info, ani_object callback);
    static void QueryAllAutoStartupApplications(ani_env *env, ani_object callback);
    static void AutoStartupInfoCheck(ani_env *env, ani_object info);
    static void NativeCheckCallerIsSystemApp(ani_env *env);

private:
    void OnRegisterAutoStartupCallback(ani_env *env, ani_string aniType, ani_object callback);
    void OnUnregisterAutoStartupCallback(ani_env *env, ani_string aniType, ani_object callback);
    void OnSetApplicationAutoStartup(ani_env *env, ani_object info, ani_object callback);
    void OnCancelApplicationAutoStartup(ani_env *env, ani_object info, ani_object callback);
    void OnQueryAllAutoStartupApplications(ani_env *env, ani_object callback);
    void OnAutoStartupInfoCheck(ani_env *env, ani_object info);
    void OnNativeCheckCallerIsSystemApp(ani_env *env);

    sptr<EtsAbilityAutoStartupCallback> etsAutoStartupCallback_;
    static EtsAbilityAutoStartupManager& GetInstance();
};
void EtsAbilityAutoStartupManagerInit(ani_env *env);
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_ETS_ABILITY_AUTO_STARTUP_MANAGER_H