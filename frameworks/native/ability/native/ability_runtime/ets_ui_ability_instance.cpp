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

#include "ets_ui_ability_instance.h"

#include <cstddef>
#include <dlfcn.h>

#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "string_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
const char *ETS_ANI_LIBNAME = "libui_ability_ani.z.so";
const char *ETS_ANI_CREATE_FUNC = "OHOS_ETS_Ability_Create";
using CreateETSUIAbilityFunc = UIAbility*(*)(const std::unique_ptr<Runtime>&);
CreateETSUIAbilityFunc g_etsCreateFunc = nullptr;
const char *CREATE_AND_BIND_ETS_UI_ABILITY_CONTEXT_FUNC = "OHOS_CreateAndBindETSUIAbilityContext";
using CreateAndBindETSUIAbilityContextFunc = void(*)(const std::shared_ptr<AbilityContext> &abilityContext,
    const std::unique_ptr<Runtime> &runtime);
CreateAndBindETSUIAbilityContextFunc g_createAndBindETSUIAbilityContextFunc = nullptr;
}

UIAbility *CreateETSUIAbility(const std::unique_ptr<Runtime> &runtime)
{
    if (g_etsCreateFunc != nullptr) {
        return g_etsCreateFunc(runtime);
    }
    auto handle = dlopen(ETS_ANI_LIBNAME, RTLD_LAZY);
    if (handle == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "dlopen failed %{public}s, %{public}s", ETS_ANI_LIBNAME, dlerror());
        return nullptr;
    }
    auto symbol = dlsym(handle, ETS_ANI_CREATE_FUNC);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "dlsym failed %{public}s, %{public}s", ETS_ANI_CREATE_FUNC, dlerror());
        dlclose(handle);
        return nullptr;
    }
    g_etsCreateFunc = reinterpret_cast<CreateETSUIAbilityFunc>(symbol);
    return g_etsCreateFunc(runtime);
}

void CreateAndBindETSUIAbilityContext(const std::shared_ptr<AbilityContext> &abilityContext,
    const std::unique_ptr<Runtime> &runtime)
{
    if (g_createAndBindETSUIAbilityContextFunc != nullptr) {
        return g_createAndBindETSUIAbilityContextFunc(abilityContext, runtime);
    }
    auto handle = dlopen(ETS_ANI_LIBNAME, RTLD_LAZY);
    if (handle == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "dlopen failed %{public}s, %{public}s", ETS_ANI_LIBNAME, dlerror());
        return;
    }
    auto symbol = dlsym(handle, CREATE_AND_BIND_ETS_UI_ABILITY_CONTEXT_FUNC);
    if (symbol == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "dlsym failed %{public}s, %{public}s", ETS_ANI_CREATE_FUNC, dlerror());
        dlclose(handle);
        return;
    }
    g_createAndBindETSUIAbilityContextFunc = reinterpret_cast<CreateAndBindETSUIAbilityContextFunc>(symbol);
    return g_createAndBindETSUIAbilityContextFunc(abilityContext, runtime);
}
} // namespace AbilityRuntime
} // namespace OHOS