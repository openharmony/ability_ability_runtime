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

#ifndef OHOS_ABILITY_RUNTIME_STS_APPLICATION_H
#define OHOS_ABILITY_RUNTIME_STS_APPLICATION_H

#include "ani.h"

namespace OHOS {
namespace AbilityRuntime {
static void CreateModuleContext([[maybe_unused]] ani_env *env,
    ani_object contextObj, ani_string bundleName, ani_string moduleName, ani_object callback);
static void CreateBundleContext([[maybe_unused]] ani_env *env,
    ani_object contextObj, ani_string bundleName, ani_object callback);
void ApplicationInit(ani_env *env);
} // namespace AbilityRuntime
} // namespace OHOS
#endif //OHOS_ABILITY_RUNTIME_STS_APPLICATION_H