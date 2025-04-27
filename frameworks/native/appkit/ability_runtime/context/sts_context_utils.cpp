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

#include "sts_context_utils.h"

#include "ani_common_util.h"
#include "ani_enum_convert.h"
#include "application_context.h"
#include "application_context_manager.h"
#include "common_fun_ani.h"
#include "hilog_tag_wrapper.h"
#include "resourceManager.h"
#include "sts_error_utils.h"
#include "ani_common_util.h"
#include "ability_runtime_error_util.h"

namespace OHOS {
namespace AbilityRuntime {
namespace ContextUtil {
namespace {
    std::shared_ptr<EtsEnviromentCallback> etsEnviromentCallback_ = nullptr;
}

static std::weak_ptr<Context> context_;
void BindApplicationCtx(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    void* applicationCtxRef)
{
    // bind parent context field:applicationContext
    ani_field applicationContextField;
    if (aniEnv->Class_FindField(contextClass, "applicationContext", &applicationContextField) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindField failed");
        return;
    }
    ani_ref applicationContextRef = reinterpret_cast<ani_ref>(applicationCtxRef);
    if (aniEnv->Object_SetField_Ref(contextObj, applicationContextField, applicationContextRef) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed");
        return;
    }
}

void BindApplicationInfo(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context)
{
    ani_field applicationInfoField;
    if (ANI_OK != aniEnv->Class_FindField(contextClass, "applicationInfo", &applicationInfoField)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find applicationInfo failed");
        return;
    }
    auto appInfo = context->GetApplicationInfo();
    ani_object appInfoObj = AppExecFwk::CommonFunAni::ConvertApplicationInfo(aniEnv, *appInfo);
    if (aniEnv->Object_SetField_Ref(contextObj, applicationInfoField,
        reinterpret_cast<ani_ref>(appInfoObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed");
        return;
    }
}

void BindResourceManager(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context)
{
    ani_field resourceManagerField;
    if (ANI_OK != aniEnv->Class_FindField(contextClass, "resourceManager", &resourceManagerField)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find resourceManager failed");
        return;
    }
    auto resourceManager = context->GetResourceManager();
    ani_object resourceMgrObj = Global::Resource::ResMgrAddon::CreateResMgr(aniEnv, "", resourceManager, context);
    if (aniEnv->Object_SetField_Ref(contextObj, resourceManagerField,
        reinterpret_cast<ani_ref>(resourceMgrObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed");
        return;
    }
}

void BindParentProperty(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context)
{
    BindApplicationInfo(aniEnv, contextClass, contextObj, context);
    BindResourceManager(aniEnv, contextClass, contextObj, context);

    // bind parent context property
    ani_field areaField;
    if (ANI_OK != aniEnv->Class_FindField(contextClass, "area", &areaField)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find area failed");
        return;
    }
    auto area = context->GetArea();
    ani_enum_item areaModeItem {};
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToSts(
        aniEnv, "L@ohos/app/ability/contextConstant/contextConstant/AreaMode;", area, areaModeItem);

    if (aniEnv->Object_SetField_Ref(contextObj, areaField, (ani_ref)areaModeItem) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Int failed");
        return;
    }

    ani_field filesDirField;
    if (ANI_OK != aniEnv->Class_FindField(contextClass, "filesDir", &filesDirField)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find filesDir failed");
        return;
    }
    auto filesDir = context->GetFilesDir();
    ani_string filesDir_string{};
    aniEnv->String_NewUTF8(filesDir.c_str(), filesDir.size(), &filesDir_string);
    if (aniEnv->Object_SetField_Ref(contextObj, filesDirField, reinterpret_cast<ani_ref>(filesDir_string)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed");
        return;
    }

    ani_field tempDirField;
    if (ANI_OK != aniEnv->Class_FindField(contextClass, "tempDir", &tempDirField)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find find tempDir failed");
        return;
    }
    auto tempDir = context->GetTempDir();
    ani_string tempDir_string{};
    aniEnv->String_NewUTF8(tempDir.c_str(), tempDir.size(), &tempDir_string);
    if (aniEnv->Object_SetField_Ref(contextObj, tempDirField, reinterpret_cast<ani_ref>(tempDir_string)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed");
        return;
    }
}

void BindContextDir(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context)
{
    if (aniEnv == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "aniEnv or context is nullptr");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_field preferencesDirField;
    if ((status = aniEnv->Class_FindField(contextClass, "preferencesDir", &preferencesDirField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "find preferencesDir failed, status: %{public}d", status);
        return;
    }
    auto preferencesDir = context->GetPreferencesDir();
    TAG_LOGI(AAFwkTag::APPKIT, "ani preferencesDir:%{public}s", preferencesDir.c_str());
    ani_string preferencesDirString{};
    aniEnv->String_NewUTF8(preferencesDir.c_str(), preferencesDir.size(), &preferencesDirString);
    if ((status = aniEnv->Object_SetField_Ref(contextObj, preferencesDirField,
        reinterpret_cast<ani_ref>(preferencesDirString))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed status: %{public}d", status);
        return;
    }

    ani_field databaseDirField;
    if ((status = aniEnv->Class_FindField(contextClass, "databaseDir", &databaseDirField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "find databaseDir failed status: %{public}d", status);
        return;
    }
    auto databaseDir = context->GetDatabaseDir();
    TAG_LOGI(AAFwkTag::APPKIT, "ani databaseDir:%{public}s", databaseDir.c_str());
    ani_string databaseDirString{};
    aniEnv->String_NewUTF8(databaseDir.c_str(), databaseDir.size(), &databaseDirString);
    if ((status = aniEnv->Object_SetField_Ref(contextObj, databaseDirField,
        reinterpret_cast<ani_ref>(databaseDirString))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed status: %{public}d", status);
        return;
    }

    ani_field cacheDirField;
    if ((status = aniEnv->Class_FindField(contextClass, "cacheDir", &cacheDirField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "find cacheDir failed status: %{public}d", status);
        return;
    }
    auto cacheDir = context->GetCacheDir();
    TAG_LOGI(AAFwkTag::APPKIT, "ani cacheDir:%{public}s", cacheDir.c_str());
    ani_string cacheDirString{};
    aniEnv->String_NewUTF8(cacheDir.c_str(), cacheDir.size(), &cacheDirString);
    if ((status = aniEnv->Object_SetField_Ref(contextObj, cacheDirField,
        reinterpret_cast<ani_ref>(cacheDirString))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed, status: %{public}d", status);
        return;
    }
}

void StsCreatContext(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    void* applicationCtxRef, std::shared_ptr<Context> context)
{
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "aniEnv is nullptr");
        return;
    }
    BindApplicationCtx(aniEnv, contextClass, contextObj, applicationCtxRef);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "context is nullptr");
        return;
    }
    context_ = context;
    BindParentProperty(aniEnv, contextClass, contextObj, context);
    BindContextDir(aniEnv, contextClass, contextObj, context);
}

ani_object CreateModuleResourceManagerSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_string bundleName, ani_string moduleName)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env is nullptr");
        return OHOS::AbilityRuntime::CreateStsInvalidParamError(env, "env is null");
    }
    std::string bundleName_ = "";
    AppExecFwk::AniStringToStdString(env, bundleName, bundleName_);
    std::string moduleName_ = "";
    AppExecFwk::AniStringToStdString(env, moduleName, moduleName_);
    ani_status status = ANI_ERROR;

    auto context = context_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return {};
    }

    auto resourceManager = context->CreateModuleResourceManager(bundleName_, moduleName_);
    ani_class resourceManagerCls = nullptr;
    if ((status = env->FindClass("L@ohos/resourceManager/resourceManager/ResourceManagerInner;",
        &resourceManagerCls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass ApplicationContext failed status: %{public}d", status);
        return OHOS::AbilityRuntime::CreateStsInvalidParamError(env, "findClass fail");
    }

    ani_method CtorMethod = nullptr;
    if ((status = env->Class_FindMethod(resourceManagerCls, "<ctor>", ":V", &CtorMethod)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod ctor failed status: %{public}d", status);
        return OHOS::AbilityRuntime::CreateStsInvalidParamError(env, "Class_FindMethod ctor failed");
    }

    ani_object Object = nullptr;
    if ((status = env->Object_New(resourceManagerCls, CtorMethod, &Object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_New failed status: %{public}d", status);
        return OHOS::AbilityRuntime::CreateStsInvalidParamError(env, "Object_New failed");
    }

    ani_field Field;
    if ((status = env->Class_FindField(resourceManagerCls, "nativeResMgr", &Field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindField failed status: %{public}d", status);
        return OHOS::AbilityRuntime::CreateStsInvalidParamError(env, "Class_FindField failed");
    }

    if ((status = env->Object_SetField_Long(Object, Field, (ani_long)resourceManager.get())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Long failed status: %{public}d", status);
        return OHOS::AbilityRuntime::CreateStsInvalidParamError(env, "Object_SetField_Long failed");
    }

    return Object;
}

ani_object GetApplicationContextSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj)
{
    auto appContextObj = ApplicationContextManager::GetApplicationContextManager().GetStsGlobalObject(env);
    if (appContextObj != nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appContextObj is not nullptr");
        return appContextObj->aniObj;
    }
    ThrowStsInvalidParamError(env, "appContextObj null");
    return {};
}

ani_long GetNativeApplicationContextLong(ani_env *env, ani_object& aniObj)
{
    ani_status status = ANI_ERROR;
    ani_long nativeContextLong = 0;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env is nullptr");
        return nativeContextLong;
    }
    ani_class applicationContextCls = nullptr;
    if ((status = env->FindClass("Lapplication/ApplicationContext/ApplicationContext;",
        &applicationContextCls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass ApplicationContext failed status: %{public}d", status);
        AbilityRuntime::ThrowStsInvalidParamError(env, "FindClass failed");
        return nativeContextLong;
    }
    ani_field contextField;
    if ((status = env->Class_FindField(applicationContextCls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindField failed status: %{public}d", status);
        AbilityRuntime::ThrowStsInvalidParamError(env, "Class_FindField failed");
        return nativeContextLong;
    }
    if ((status = env->Object_GetField_Long(aniObj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_GetField_Long failed status: %{public}d", status);
        AbilityRuntime::ThrowStsInvalidParamError(env, "Object_GetField_Long failed");
        return nativeContextLong;
    }
    if (nativeContextLong == 0) {
        AbilityRuntime::ThrowStsInvalidParamError(env, "nativeContext is null");
    }

    return nativeContextLong;
}

ani_double NativeOnSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_string type, ani_object envCallback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "NativeOnSync Call");
    ani_long nativeContextLong = GetNativeApplicationContextLong(env, aniObj);
    if (nativeContextLong == 0) {
        TAG_LOGE(AAFwkTag::APPKIT, "nativeContext is null");
        AbilityRuntime::ThrowStsInvalidParamError(env, "nativeContext is null");
        return ANI_ERROR;
    }
    if (etsEnviromentCallback_ != nullptr) {
        return ani_double(etsEnviromentCallback_->Register(envCallback));
    }

    etsEnviromentCallback_ = std::make_shared<EtsEnviromentCallback>(env);
    int32_t callbackId = etsEnviromentCallback_->Register(envCallback);
    ((AbilityRuntime::ApplicationContext*)nativeContextLong)->RegisterEnvironmentCallback(etsEnviromentCallback_);

    return ani_double(callbackId);
}

void NativeOffSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_string type, ani_double callbackId, ani_object call)
{
    TAG_LOGD(AAFwkTag::APPKIT, "NativeOffSync Call");
    ani_long nativeContextLong = GetNativeApplicationContextLong(env, aniObj);
    if (nativeContextLong == 0) {
        TAG_LOGE(AAFwkTag::APPKIT, "nativeContext is null");
        AppExecFwk::AsyncCallback(env, call, CreateStsError(env, AbilityErrorCode::ERROR_CODE_INVALID_PARAM), nullptr);
        return;
    }

    if (etsEnviromentCallback_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "etsEnviromentCallback is null");
        AppExecFwk::AsyncCallback(env, call, CreateStsError(env,
            (ani_int)AbilityErrorCode::ERROR_CODE_INVALID_PARAM, "env_callback is nullptr"), nullptr);
        return;
    }

    if (!etsEnviromentCallback_->UnRegister(callbackId)) {
        TAG_LOGE(AAFwkTag::APPKIT, "call UnRegister failed");
        AppExecFwk::AsyncCallback(env, call, CreateStsError(env,
            (ani_int)AbilityErrorCode::ERROR_CODE_INVALID_PARAM, "call UnRegister failed!"), nullptr);
        return;
    }

    AppExecFwk::AsyncCallback(env, call, CreateStsError(env, AbilityErrorCode::ERROR_OK), nullptr);
}

}
} // namespace AbilityRuntime
} // namespace OHOS
