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
#include <iostream>
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
void ContextConstructor()
{
}

void ExtensionContextConstructor()
{
}
 
void UIAbilityContextConstructor()
{
}
 
extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    ani_env *env;
    if (vm == nullptr || result == nullptr) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Illegal VM or result");
        return ANI_ERROR;
    }
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Unsupported ANI_VERSION_1");
        return ANI_ERROR;
    }
    // class Context
    ani_class contextClass;
    static const char *contextClassName = "Lapplication/Context/Context;";
    if (ANI_OK != env->FindClass(contextClassName, &contextClass)) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Not found class %{public}s.", contextClassName);
        return ANI_NOT_FOUND;
    }
    std::array classMethods_context = {
        ani_native_function {"<ctor>", ":V", reinterpret_cast<void *>(ContextConstructor)},
    };
    if (ANI_OK != env->Class_BindNativeMethods(contextClass, classMethods_context.data(),
        classMethods_context.size())) {
            TAG_LOGE(AAFwkTag::STSRUNTIME, "Cannot bind native ctor to class %{public}s.", contextClassName);
        return ANI_ERROR;
    };
    // class ExtensionContext
    ani_class extensionContextClass;
    static const char *extensionContextClassName = "Lapplication/ExtensionContext/ExtensionContext;";
    if (ANI_OK != env->FindClass(extensionContextClassName, &extensionContextClass)) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Not found class %{public}s.", extensionContextClassName);
        return ANI_NOT_FOUND;
    }
    std::array classMethods_extensionContext = {
        ani_native_function {"<ctor>", ":V", reinterpret_cast<void *>(ExtensionContextConstructor)},
    };
    if (ANI_OK != env->Class_BindNativeMethods(extensionContextClass, classMethods_extensionContext.data(),
        classMethods_extensionContext.size())) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Cannot bind native ctor to class %{public}s.", extensionContextClassName);
        return ANI_ERROR;
    };
    // class UIAbilityContext
    ani_class uiAbilityClass;
    static const char *uiAbilityClassName = "Lapplication/UIAbilityContext/UIAbilityContext;";
    if (ANI_OK != env->FindClass(uiAbilityClassName, &uiAbilityClass)) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Not found class %{public}s.", uiAbilityClassName);
        return ANI_NOT_FOUND;
    }
    std::array classMethods_uiAbility = {
        ani_native_function {"<ctor>", ":V", reinterpret_cast<void *>(UIAbilityContextConstructor)},
    };
    if (ANI_OK != env->Class_BindNativeMethods(uiAbilityClass, classMethods_uiAbility.data(),
        classMethods_uiAbility.size())) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "Cannot bind native ctor to class %{public}s.", uiAbilityClassName);
        return ANI_ERROR;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS