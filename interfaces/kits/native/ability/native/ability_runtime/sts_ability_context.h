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

#include <algorithm>
#include <memory>
#include <native_engine/native_value.h>

#include "ability_context.h"
#include "configuration.h"
#include "sts_runtime.h"
#include "ohos_application.h"
#include "sts_free_install_observer.h"

class STSNativeReference;

namespace OHOS {
namespace AbilityRuntime {
using OHOSApplication = AppExecFwk::OHOSApplication;
class StsAbilityContext final {
public:
    static StsAbilityContext &GetInstance()
    {
        static StsAbilityContext instance;
        return instance;
    }
    static void StartAbility1(
        [[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj, ani_object wantObj, ani_object call);
    static void StartAbility2([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj, ani_object wantObj,
        ani_object opt, ani_object call);
    static void StartAbilityForResult1(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object callback);
    static void StartAbilityForResult2(
        ani_env *env, ani_object aniObj, ani_object wantObj, ani_object startOptionsObj, ani_object callback);
    static void TerminateSelf(ani_env *env, ani_object aniObj, ani_object callback);
    static void TerminateSelfWithResult(ani_env *env, ani_object aniObj, ani_object abilityResult, ani_object callback);
    static void reportDrawnCompletedSync(
        [[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj, ani_object call);
    static ani_object StartAbilityByTypeSync([[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object aniObj,
        ani_string aniType, ani_ref aniWantParam, ani_object startCallback);

    static ani_object SetAbilityContext(ani_env *env, const std::shared_ptr<AbilityContext> &context);
    static std::shared_ptr<AbilityContext> GetAbilityContext(ani_env *env, ani_object aniObj);

private:
    static void InheritWindowMode(ani_env *env, ani_object aniObj, AAFwk::Want &want);
    void StartAbilityInner([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
        ani_object wantObj, ani_object opt, ani_object call);
    static void StartAbilityForResultInner(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object startOptionsObj, ani_object callback);
    static int32_t GenerateRequestCode();
    void AddFreeInstallObserver(
        ani_env *env, const AAFwk::Want &want, ani_object callback, const std::shared_ptr<AbilityContext> &context);

    sptr<StsFreeInstallObserver> freeInstallObserver_ = nullptr;
    static std::mutex requestCodeMutex_;
};

bool BindNativeMethods(ani_env *env, ani_class &cls);
bool SetAbilityInfo(ani_env *env, ani_class cls, ani_object contextObj, const std::shared_ptr<AbilityContext> &context);
bool SetConfiguration(
    ani_env *env, ani_class cls, ani_object contextObj, const std::shared_ptr<AbilityContext> &context);
bool SetHapModuleInfo(
    ani_env *env, ani_class cls, ani_object contextObj, const std::shared_ptr<AbilityContext> &context);
ani_ref CreateStsAbilityContext(
    ani_env *env, const std::shared_ptr<AbilityContext> &context, const std::shared_ptr<OHOSApplication> &application);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_SIMULATOR_STS_ABILITY_CONTEXT_H
