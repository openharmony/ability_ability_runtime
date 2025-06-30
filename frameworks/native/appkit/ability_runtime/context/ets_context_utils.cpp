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

#include "ets_context_utils.h"

#include "ani_common_util.h"
#include "ani_enum_convert.h"
#include "application_context.h"
#include "application_context_manager.h"
#include "common_fun_ani.h"
#include "ets_application_context_utils.h"
#include "ets_error_utils.h"
#include "ets_native_reference.h"
#include "hilog_tag_wrapper.h"
#include "resourceManager.h"

namespace OHOS {
namespace AbilityRuntime {
namespace ContextUtil {
namespace {
constexpr const char* CONTEXT_CLASS_NAME = "Lapplication/Context/Context;";
constexpr const char* AREA_MODE_ENUM_NAME = "L@ohos/app/ability/contextConstant/contextConstant/AreaMode;";

void BindContextDir(ani_env *aniEnv, ani_object contextObj, std::shared_ptr<Context> context)
{
    if (aniEnv == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "aniEnv or context is nullptr");
        return;
    }
    ani_status status = ANI_ERROR;
    auto preferencesDir = context->GetPreferencesDir();
    ani_string preferencesDirString = nullptr;
    aniEnv->String_NewUTF8(preferencesDir.c_str(), preferencesDir.size(), &preferencesDirString);
    if ((status = aniEnv->Object_SetFieldByName_Ref(contextObj, "preferencesDir", preferencesDirString)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "preferencesDir SetField status: %{public}d", status);
        return;
    }

    auto databaseDir = context->GetDatabaseDir();
    ani_string databaseDirString = nullptr;
    aniEnv->String_NewUTF8(databaseDir.c_str(), databaseDir.size(), &databaseDirString);
    if ((status = aniEnv->Object_SetFieldByName_Ref(contextObj, "databaseDir", databaseDirString)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "databaseDir SetField status: %{public}d", status);
        return;
    }

    auto cacheDir = context->GetCacheDir();
    ani_string cacheDirString = nullptr;
    aniEnv->String_NewUTF8(cacheDir.c_str(), cacheDir.size(), &cacheDirString);
    if ((status = aniEnv->Object_SetFieldByName_Ref(contextObj, "cacheDir", cacheDirString)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "cacheDir SetField status: %{public}d", status);
        return;
    }

    auto filesDir = context->GetFilesDir();
    ani_string filesDirString = nullptr;
    aniEnv->String_NewUTF8(filesDir.c_str(), filesDir.size(), &filesDirString);
    if ((status = aniEnv->Object_SetFieldByName_Ref(contextObj, "filesDir", filesDirString)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "filesDir SetField status: %{public}d", status);
        return;
    }

    auto tempDir = context->GetTempDir();
    ani_string tempDirString = nullptr;
    aniEnv->String_NewUTF8(tempDir.c_str(), tempDir.size(), &tempDirString);
    if ((status = aniEnv->Object_SetFieldByName_Ref(contextObj, "tempDir", tempDirString)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "tempDir SetField status: %{public}d", status);
        return;
    }
}
} // namespace

void BindApplicationInfo(ani_env *aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context)
{
    if (aniEnv == nullptr || context ==  nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv or null context");
    }
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

void BindResourceManager(ani_env *aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context)
{
    if (aniEnv == nullptr || context ==  nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv or null context");
    }
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

void BindParentProperty(ani_env *aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context)
{
    if (aniEnv == nullptr || context ==  nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv or null context");
    }
    BindApplicationInfo(aniEnv, contextClass, contextObj, context);
    BindResourceManager(aniEnv, contextClass, contextObj, context);
    BindContextDir(aniEnv, contextObj, context);

    ani_field areaField;
    if (ANI_OK != aniEnv->Class_FindField(contextClass, "area", &areaField)) {
        TAG_LOGE(AAFwkTag::APPKIT, "find area failed");
        return;
    }
    auto area = context->GetArea();
    ani_enum_item areaModeItem = nullptr;
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToEts(
        aniEnv, "L@ohos/app/ability/contextConstant/contextConstant/AreaMode;", area, areaModeItem);
    if (aniEnv->Object_SetField_Ref(contextObj, areaField, (ani_ref)areaModeItem) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Int failed");
        return;
    }
}

void BindNativeFunction(ani_env *aniEnv)
{
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env is null");
        return;
    }
    ani_class contextCls = nullptr;
    if (aniEnv->FindClass(CONTEXT_CLASS_NAME, &contextCls) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass Context failed");
        return;
    }
    std::array contextFunctions = {
        ani_native_function {"getApplicationContextSync", ":Lapplication/ApplicationContext/ApplicationContext;",
            reinterpret_cast<void *>(AbilityRuntime::ContextUtil::GetApplicationContextSync)},
        ani_native_function {"switchArea", nullptr,
            reinterpret_cast<void *>(AbilityRuntime::ContextUtil::SwitchArea)},
        ani_native_function {"getArea", nullptr,
            reinterpret_cast<void *>(AbilityRuntime::ContextUtil::GetArea)}
    };
    ani_status status = aniEnv->Class_BindNativeMethods(contextCls, contextFunctions.data(),
        contextFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_BindNativeMethods failed status: %{public}d", status);
    }
}

void CreateEtsBaseContext(ani_env *aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context)
{
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv");
    }
    BindParentProperty(aniEnv, contextClass, contextObj, context);
    BindNativeFunction(aniEnv);
}

std::shared_ptr<Context> GetBaseContext(ani_env *env, ani_object aniObj)
{
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    ani_class cls = nullptr;
    if ((status = env->FindClass(CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return nullptr;
    }
    ani_field contextField = nullptr;
    if ((status = env->Class_FindField(cls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return nullptr;
    }
    ani_long nativeContextLong;
    if ((status = env->Object_GetField_Long(aniObj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return nullptr;
    }
    auto weakContext = reinterpret_cast<std::weak_ptr<Context>*>(nativeContextLong);
    return weakContext != nullptr ? weakContext->lock() : nullptr;
}

ani_object GetApplicationContext(ani_env *env, const std::shared_ptr<ApplicationContext> applicationContext)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return {};
    }
    ani_object applicationContextObject =
        EtsApplicationContextUtils::CreateEtsApplicationContext(env, applicationContext);
    if (applicationContextObject == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null applicationContextObject");
        return {};
    }
    applicationContext->SetApplicationInfoUpdateFlag(false);
    return applicationContextObject;
}

ani_object GetApplicationContextSync(ani_env *env, ani_object aniObj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
    }
    auto context = GetBaseContext(env, aniObj);
    if (!context) {
        TAG_LOGW(AAFwkTag::APPKIT, "null context");
        EtsErrorUtil::ThrowError(env, (int32_t)AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return {};
    }
    auto applicationContext = context->GetApplicationContext();
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null applicationContext");
        EtsErrorUtil::ThrowError(env, (int32_t)AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return {};
    }
    if (!applicationContext->GetApplicationInfoUpdateFlag()) {
        auto appContextObj = ApplicationContextManager::GetApplicationContextManager().GetEtsGlobalObject();
        if (appContextObj != nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "appContextObj is not nullptr");
            return appContextObj->aniObj;
        }
    }
    return GetApplicationContext(env, applicationContext);
}

void SwitchArea(ani_env *env, ani_object obj, ani_enum_item areaModeItem)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
    }
    int32_t areaMode = 0;
    if (!AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(env, areaModeItem, areaMode)) {
        TAG_LOGE(AAFwkTag::APPKIT, "Parse area failed");
        return;
    }
    auto context = GetBaseContext(env, obj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        return;
    }
    context->SwitchArea(areaMode);
    BindContextDir(env, obj, context);
}

ani_enum_item GetArea(ani_env *env, ani_object obj)
{
    ani_enum_item areaModeItem = nullptr;
    auto context = GetBaseContext(env, obj);
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env or context is null");
        return areaModeItem;
    }
    int32_t areaMode = static_cast<int32_t>(context->GetArea());
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvert_NativeToEts(env, AREA_MODE_ENUM_NAME, areaMode, areaModeItem);
    return areaModeItem;
}
}
} // namespace AbilityRuntime
} // namespace OHOS
