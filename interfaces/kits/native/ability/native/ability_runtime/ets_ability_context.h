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

#ifndef OHOS_ABILITY_RUNTIME_SIMULATOR_ETS_ABILITY_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_SIMULATOR_ETS_ABILITY_CONTEXT_H

#include "ability_context.h"
#include "ani.h"
#include "configuration.h"
#include "ets_free_install_observer.h"
#include "ets_runtime.h"
#include "ohos_application.h"

namespace OHOS {
namespace AbilityRuntime {
using OHOSApplication = AppExecFwk::OHOSApplication;
class EtsAbilityContext final {
public:
    static EtsAbilityContext &GetInstance()
    {
        static EtsAbilityContext instance;
        return instance;
    }
    static void StartAbility(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object call);
    static void StartAbilityWithOptions(
        ani_env *env, ani_object aniObj, ani_object wantObj, ani_object opt, ani_object call);
    static void StartAbilityForResult(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object callback);
    static void StartAbilityForResultWithOptions(
        ani_env *env, ani_object aniObj, ani_object wantObj, ani_object startOptionsObj, ani_object callback);
    static void TerminateSelf(ani_env *env, ani_object aniObj, ani_object callback);
    static void TerminateSelfWithResult(ani_env *env, ani_object aniObj, ani_object abilityResult, ani_object callback);
    static void ReportDrawnCompleted(ani_env *env, ani_object aniObj, ani_object call);

    static ani_object SetAbilityContext(ani_env *env, const std::shared_ptr<AbilityContext> &context);
    static std::shared_ptr<AbilityContext> GetAbilityContext(ani_env *env, ani_object aniObj);

private:
    static bool AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result);
    void InheritWindowMode(ani_env *env, ani_object aniObj, AAFwk::Want &want);
    void OnStartAbility(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object opt, ani_object call);
    void OnStartAbilityForResult(
        ani_env *env, ani_object aniObj, ani_object wantObj, ani_object startOptionsObj, ani_object callback);
    void OnTerminateSelf(ani_env *env, ani_object aniObj, ani_object callback);
    void OnTerminateSelfWithResult(ani_env *env, ani_object aniObj, ani_object abilityResult, ani_object callback);
    void OnReportDrawnCompleted(ani_env *env, ani_object aniObj, ani_object call);
    void AddFreeInstallObserver(ani_env *env, const AAFwk::Want &want, ani_object callback,
        const std::shared_ptr<AbilityContext> &context, bool isAbilityResult = false, bool isOpenLink = false);
    void StartAbilityForResultInner(ani_env *env, const AAFwk::StartOptions &startOptions, AAFwk::Want &want,
        std::shared_ptr<AbilityContext> context, ani_object startOptionsObj, ani_object callback);
    int32_t GenerateRequestCode();

    static std::mutex requestCodeMutex_;
    sptr<EtsFreeInstallObserver> freeInstallObserver_ = nullptr;
};

ani_object CreateEtsAbilityContext(
    ani_env *env, const std::shared_ptr<AbilityContext> &context, const std::shared_ptr<OHOSApplication> &application);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_SIMULATOR_ETS_ABILITY_CONTEXT_H
