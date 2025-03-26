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

class STSNativeReference;

namespace OHOS {
namespace AbilityRuntime {
class StsAbilityContext final {
public:
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

    static ani_object SetAbilityContext(ani_env *env, const std::shared_ptr<AbilityContext> &context);
    static std::shared_ptr<AbilityContext> GetAbilityContext(ani_env *env, ani_object aniObj);

private:
    static bool AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result);
    static ani_object WrapBusinessError(ani_env *env, int32_t code);
    static ani_object WrapError(ani_env *env, const std::string &msg);
    static void InheritWindowMode(ani_env *env, ani_object aniObj, AAFwk::Want &want);
    static void StartAbilityInner([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
        ani_object wantObj, ani_object opt, ani_object call);
    static void StartAbilityForResultInner(ani_env *env, ani_object aniObj, ani_object wantObj,
        ani_object startOptionsObj, ani_object callback);
    static int32_t GenerateRequestCode();
    static std::string GetErrMsg(int32_t err, const std::string &permission = "");

    static std::mutex requestCodeMutex_;
};
ani_ref CreateStsAbilityContext(ani_env *env, const std::shared_ptr<AbilityContext> &context);
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_SIMULATOR_STS_ABILITY_CONTEXT_H
