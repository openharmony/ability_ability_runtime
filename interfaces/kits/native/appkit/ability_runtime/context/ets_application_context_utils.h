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

#ifndef OHOS_ABILITY_RUNTIME_ETS_APPLICATION_CONTEXT_UTILS_H
#define OHOS_ABILITY_RUNTIME_ETS_APPLICATION_CONTEXT_UTILS_H

#include "ability_manager_client.h"
#include "ability_runtime_error_util.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "application_context.h"
#include "sts_context_utils.h"
#include "sts_error_utils.h"
#include "sts_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsApplicationContextUtils {
public:
    explicit EtsApplicationContextUtils() {}
    virtual ~EtsApplicationContextUtils() = default;
    static void RestartApp([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
        ani_object wantObj);
    static void SetFont([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
        ani_string font);
    static void SetColorMode([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
        ani_enum_item colorMode);
    static void ClearUpApplicationData([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
        ani_object callback);
    static void GetRunningProcessInformation([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
        ani_object callback);
    static ani_double NativeOnSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
        ani_string type, ani_object envCallback);
    static void NativeOffSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
        ani_string type, ani_double callbackId, ani_object call);
    static void killAllProcesses([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
        ani_boolean clearPageStack, ani_object call);
    static void PreloadUIExtensionAbility([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
        ani_object wantObj, ani_object call);
    static void SetSupportedProcessCacheSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
        ani_boolean value);
    static void SetApplicationContextToEts(const std::shared_ptr<ApplicationContext> &abilityRuntimeContext);
    static void CreateEtsApplicationContext(ani_env* aniEnv, void* applicationContextObjRef);
    static void BindApplicationContextFunc(ani_env* aniEnv, ani_class& contextClass);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_APPLICATION_CONTEXT_UTILS_H