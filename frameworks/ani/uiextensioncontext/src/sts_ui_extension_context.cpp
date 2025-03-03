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

#include "sts_ui_extension_context.h"
static void TerminateSelfSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class aniClass)
{
    TAG_LOGE(AAFwkTag::UI_EXT, "terminateSelfSync start");
    ani_class cls = nullptr;
    ani_long nativeContextLong;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("LUIExtensionContext/UIExtensionContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "terminateSelfSync find class status : %{public}d", status);
    }
    if ((status = env->Class_FindField(cls, "nativeUIExtensionContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "terminateSelfSync find field status : %{public}d", status);
    }
    if ((status = env->Object_GetField_Long(aniClass, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "terminateSelfSync get field status : %{public}d", status);
    }
    TAG_LOGE(AAFwkTag::UI_EXT, "nativeUIExtensionContext %{public}lld", nativeContextLong);
    ((OHOS::AbilityRuntime::UIExtensionContext*)nativeContextLong)->TerminateSelf();
    TAG_LOGE(AAFwkTag::UI_EXT, "terminateSelfSync end");
}
static void TerminateSelfSyncPromise([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_class aniClass)
{
    TAG_LOGE(AAFwkTag::UI_EXT, "terminateSelfSyncPromise start");
    ani_class cls = nullptr;
    ani_long nativeContextLong;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass("LUIExtensionContext/UIExtensionContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "terminateSelfSyncPromise find class status : %{public}d", status);
    }
    if ((status = env->Class_FindField(cls, "nativeUIExtensionContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "terminateSelfSyncPromise find field status : %{public}d", status);
    }
    if ((status = env->Object_GetField_Long(aniClass, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "terminateSelfSyncPromise get filed status : %{public}d", status);
    }
    TAG_LOGE(AAFwkTag::UI_EXT, "nativeUIExtensionContext %{public}lld", nativeContextLong);
    ((OHOS::AbilityRuntime::UIExtensionContext*)nativeContextLong)->TerminateSelf();
    TAG_LOGE(AAFwkTag::UI_EXT, "terminateSelfSyncPromise end");
}
ani_ref CreateStsUiExtensionContext(ani_env *env, std::shared_ptr<OHOS::AbilityRuntime::UIExtensionContext> context)
{
    TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext start");
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_field field = nullptr;
    ani_object contextObj = nullptr;
    if ((env->FindClass("LUIExtensionContext/UIExtensionContext;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext find class status : %{public}d", status);
    }
    std::array functions = {
        ani_native_function { "terminateSelfSync", ":V", reinterpret_cast<ani_int*>(TerminateSelfSync) },
        ani_native_function { "terminateSelfSyncPromise", ":V", reinterpret_cast<ani_int*>(TerminateSelfSyncPromise) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext bind method status : %{public}d", status);
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext find method status : %{public}d", status);
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext new object status : %{public}d", status);
    }
    if ((status = env->Class_FindField(cls, "nativeUIExtensionContext", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext find field status : %{public}d", status);
    }
    ani_long nativeContextLong = (ani_long)context.get();
    if ((status = env->Object_SetField_Long(contextObj, field, nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext set filed status : %{public}d", status);
    }
    TAG_LOGE(AAFwkTag::UI_EXT, "CreateStsUiExtensionContext end");
    return contextObj;
}
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    std::cerr << "ANI_Constructor call" <<std::endl;
    ani_env *env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        std::cerr << "Unsupported ANI_VERSION_1" << std::endl;
        return ANI_ERROR;
    }
    auto context = std::make_shared<OHOS::AbilityRuntime::UIExtensionContext>();
    (void)CreateStsUiExtensionContext(env, context);
    *result = ANI_VERSION_1;
    return ANI_OK;
}