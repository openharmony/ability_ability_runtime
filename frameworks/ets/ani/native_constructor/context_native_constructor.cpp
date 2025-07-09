/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <ani.h>
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
void ContextConstructor() {}

void AbilityStageContextConstructor() {}

void ExtensionContextConstructor() {}

void UIAbilityContextConstructor() {}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env = nullptr;
    if (vm == nullptr || result == nullptr) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Illegal VM or result");
        return ANI_ERROR;
    }
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Unsupported ANI_VERSION_1");
        return ANI_ERROR;
    }
    ani_class contextClass = nullptr;
    static const char *contextClassName = "Lapplication/Context/Context;";
    if (ANI_OK != env->FindClass(contextClassName, &contextClass)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Not found class %{public}s.", contextClassName);
        return ANI_NOT_FOUND;
    }
    std::array classMethodsContext = {
        ani_native_function {"<ctor>", ":V", reinterpret_cast<void *>(ContextConstructor)},
    };
    if (ANI_OK != env->Class_BindNativeMethods(contextClass, classMethodsContext.data(),
        classMethodsContext.size())) {
            TAG_LOGE(AAFwkTag::ETSRUNTIME, "Cannot bind native ctor to class %{public}s.", contextClassName);
        return ANI_ERROR;
    };

    ani_class extensionContextClass = nullptr;
    static const char *extensionContextClassName = "Lapplication/ExtensionContext/ExtensionContext;";
    if (ANI_OK != env->FindClass(extensionContextClassName, &extensionContextClass)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Not found class %{public}s.", extensionContextClassName);
        return ANI_NOT_FOUND;
    }
    std::array classMethodsExtensionContext = {
        ani_native_function {"<ctor>", ":V", reinterpret_cast<void *>(ExtensionContextConstructor)},
    };
    if (ANI_OK != env->Class_BindNativeMethods(extensionContextClass, classMethodsExtensionContext.data(),
        classMethodsExtensionContext.size())) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Cannot bind native ctor to class %{public}s.", extensionContextClassName);
        return ANI_ERROR;
    };

    ani_class uiAbilityClass = nullptr;
    static const char *uiAbilityClassName = "Lapplication/UIAbilityContext/UIAbilityContext;";
    if (ANI_OK != env->FindClass(uiAbilityClassName, &uiAbilityClass)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Not found class %{public}s.", uiAbilityClassName);
        return ANI_NOT_FOUND;
    }
    std::array classMethodsUiAbility = {
        ani_native_function {"<ctor>", ":V", reinterpret_cast<void *>(UIAbilityContextConstructor)},
    };
    if (ANI_OK != env->Class_BindNativeMethods(uiAbilityClass, classMethodsUiAbility.data(),
        classMethodsUiAbility.size())) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Cannot bind native ctor to class %{public}s.", uiAbilityClassName);
        return ANI_ERROR;
    };
    
    ani_class abilityStageContextClass = nullptr;
    static const char *abilityStageContextClassName = "Lapplication/AbilityStageContext/AbilityStageContext;";
    if (ANI_OK != env->FindClass(abilityStageContextClassName, &abilityStageContextClass)) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Not found class %{public}s.", abilityStageContextClassName);
        return ANI_NOT_FOUND;
    }
    std::array classMethodsAbilityStage = {
        ani_native_function {"<ctor>", ":V", reinterpret_cast<void *>(AbilityStageContextConstructor)},
    };
    if (ANI_OK != env->Class_BindNativeMethods(abilityStageContextClass, classMethodsAbilityStage.data(),
        classMethodsAbilityStage.size())) {
        TAG_LOGE(AAFwkTag::ETSRUNTIME, "Cannot bind native ctor to class %{public}s.", abilityStageContextClassName);
        return ANI_ERROR;
    };
    *result = ANI_VERSION_1;
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS