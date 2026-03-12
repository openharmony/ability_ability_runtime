/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "error_manager_ani_util.h"
#include "hilog_tag_wrapper.h"
#include "ierror_observer.h"

namespace OHOS {
namespace AbilityRuntime {
bool IsRefUndefined(ani_env *env, ani_ref ref)
{
    ani_boolean isUndefined = ANI_FALSE;
    env->Reference_IsUndefined(ref, &isUndefined);
    return isUndefined;
}

bool IsNull(ani_env *env, ani_ref ref)
{
    ani_boolean isNull = ANI_FALSE;
    env->Reference_IsNull(ref, &isNull);
    return isNull;
}

ani_vm* GetAniVm(ani_env *env)
{
    ani_vm* vm = nullptr;
    if (env->GetVM(&vm) != ANI_OK) {
        TAG_LOGE(AAFwkTag::RECOVERY, "GetVM failed");
        return nullptr;
    }
    return vm;
}

ani_env* GetAniEnv(ani_vm *vm)
{
    ani_env* env = nullptr;
    if (vm->GetEnv(ANI_VERSION_1, &env) != ANI_OK) {
        TAG_LOGE(AAFwkTag::RECOVERY, "GetEnv failed");
        return nullptr;
    }
    return env;
}
}  // namespace AbilityRuntime
}  // namespace OHOS

