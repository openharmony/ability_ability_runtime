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

#ifndef OHOS_ABILITY_RUNTIME_STS_CONTEXT_UTILS_H
#define OHOS_ABILITY_RUNTIME_STS_CONTEXT_UTILS_H

#include "sts_runtime.h"
#include "context.h"
#include "ets_enviroment_callback.h"

namespace OHOS {
namespace AbilityRuntime {
namespace ContextUtil {
void BindApplicationCtx(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    void* applicationCtxRef);

void SetArea([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj, ani_int value);

void BindMethods(ani_env* aniEnv, ani_class contextClass);

void BindApplicationInfo(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context);

void BindResourceManager(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context);

void BindParentProperty(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context);

void BindContextDir(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context);

void StsCreatContext(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    void* applicationCtxRef, std::shared_ptr<Context> context);

ani_object CreateModuleResourceManagerSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_string bundleName, ani_string moduleName);

ani_object GetApplicationContextSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj);

}
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_STS_CONTEXT_UTILS_H
