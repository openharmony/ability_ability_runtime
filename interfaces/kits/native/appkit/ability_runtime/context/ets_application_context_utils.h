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
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "application_context.h"
#include "ets_context_utils.h"
#include "ets_error_utils.h"
#include "ets_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsApplicationContextUtils {
public:
    explicit EtsApplicationContextUtils() {}
    virtual ~EtsApplicationContextUtils() = default;
    static void SetSupportedProcessCacheSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
        ani_boolean value);
    static std::shared_ptr<ApplicationContext> GeApplicationContext(ani_env *env, ani_object aniObj);
    static ani_object SetApplicationContext(ani_env* aniEnv,
        const std::shared_ptr<ApplicationContext> &applicationContext);
    static ani_object CreateEtsApplicationContext(ani_env* aniEnv,
        const std::shared_ptr<ApplicationContext> &applicationContext);
    static void BindApplicationContextFunc(ani_env* aniEnv);
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_APPLICATION_CONTEXT_UTILS_H