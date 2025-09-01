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
#include "ipc_skeleton.h"
#include "resourceManager.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace AbilityRuntime {
namespace ContextUtil {
namespace {
static std::once_flag g_bindNativeMethodsFlag;
constexpr const char* CONTEXT_CLASS_NAME = "Lapplication/Context/Context;";
constexpr const char* AREA_MODE_ENUM_NAME = "L@ohos/app/ability/contextConstant/contextConstant/AreaMode;";
constexpr const char* CLEANER_CLASS = "Lapplication/Context/Cleaner;";

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

void Clean(ani_env *env, ani_object object)
{
    TAG_LOGD(AAFwkTag::APPKIT, "Clean called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    ani_long ptr = 0;
    ani_status status = env->Object_GetFieldByName_Long(object, "ptr", &ptr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "ptr GetField status: %{public}d", status);
        return;
    }
    if (ptr != 0) {
        delete reinterpret_cast<std::weak_ptr<Context> *>(ptr);
    }
}

bool SetNativeContextLong(ani_env *env, ani_object aniObj, ani_long nativeContextLong)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return false;
    }
    auto status = env->Object_SetFieldByName_Long(aniObj, "nativeContext", nativeContextLong);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "nativeContextLong SetField status: %{public}d", status);
        return false;
    }
    ani_class contextCls = nullptr;
    if (env->FindClass(CONTEXT_CLASS_NAME, &contextCls) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass Context failed");
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(contextCls, "<ctor>", ":V", &method)) != ANI_OK ||
        method == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "ctor FindMethod status: %{public}d, or null method", status);
        return false;
    }
    ani_object contextObj = nullptr;
    if ((status = env->Object_New(contextCls, method, &contextObj)) != ANI_OK || contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_New status: %{public}d, or null contextObj", status);
        return false;
    }
    if ((status = env->Class_FindMethod(contextCls, "setEtsContextPtr", "J:V", &method)) != ANI_OK ||
        method == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "setEtsContextPtr FindMethod status: %{public}d, or null method", status);
        return false;
    }
    if ((status = env->Object_CallMethod_Void(contextObj, method, nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "call contextObj method failed, status: %{public}d", status);
        return false;
    }
    return true;
}

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
    ani_status status = ANI_ERROR;
    std::call_once(g_bindNativeMethodsFlag, [&status, aniEnv, contextCls]() {
        std::array contextFunctions = {
            ani_native_function {"getApplicationContextSync", ":Lapplication/ApplicationContext/ApplicationContext;",
                reinterpret_cast<void *>(AbilityRuntime::ContextUtil::GetApplicationContextSync)},
            ani_native_function {"switchArea", nullptr,
                reinterpret_cast<void *>(AbilityRuntime::ContextUtil::SwitchArea)},
            ani_native_function {"getArea", nullptr,
                reinterpret_cast<void *>(AbilityRuntime::ContextUtil::GetArea)},
            ani_native_function {"createModuleResourceManagerSync", "Lstd/core/String;Lstd/core/String;"
                ":L@ohos/resourceManager/resourceManager/ResourceManager;",
                reinterpret_cast<void *>(AbilityRuntime::ContextUtil::CreateModuleResourceManagerSync)},
        };
        status = aniEnv->Class_BindNativeMethods(contextCls, contextFunctions.data(),
            contextFunctions.size());
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "Class_BindNativeMethods failed status: %{public}d", status);
            return;
        }
        ani_class cleanerCls = nullptr;
        if ((status = aniEnv->FindClass(CLEANER_CLASS, &cleanerCls)) != ANI_OK || cleanerCls == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "Cleaner FindClass failed status: %{public}d, or null cleanerCls", status);
            return;
        }
        std::array cleanerMethods = {
            ani_native_function {"clean", nullptr, reinterpret_cast<void *>(Clean) },
        };
        if ((status = aniEnv->Class_BindNativeMethods(cleanerCls,
            cleanerMethods.data(), cleanerMethods.size())) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "Class_BindNativeMethods failed status: %{public}d", status);
            return;
        }
    });
}

bool SetHapModuleInfo(
    ani_env *env, ani_class cls, ani_object contextObj, const std::shared_ptr<OHOS::AbilityRuntime::Context> &context)
{
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env or context");
        return false;
    }
    auto hapModuleInfo = context->GetHapModuleInfo();
    if (hapModuleInfo == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "hapModuleInfo is nullptr");
        return false;
    }
    ani_ref hapModuleInfoRef = AppExecFwk::CommonFunAni::ConvertHapModuleInfo(env, *hapModuleInfo);
    if (hapModuleInfoRef == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "hapModuleInfoRef is nullptr");
        return false;
    }
    ani_status status = ANI_OK;
    status = env->Object_SetPropertyByName_Ref(contextObj, "currentHapModuleInfo", hapModuleInfoRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetPropertyByName_Ref failed, status: %{public}d", status);
        return false;
    }
    return true;
}

void CreateEtsBaseContext(ani_env *aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<Context> context)
{
    if (aniEnv == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv or null context");
        return;
    }
    if (!SetHapModuleInfo(aniEnv, contextClass, contextObj, context)) {
        TAG_LOGE(AAFwkTag::APPKIT, "SetHapModuleInfo fail");
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

bool CheckCallerIsSystemApp()
{
    auto selfToken = IPCSkeleton::GetSelfTokenID();
    return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken);
}

ani_object CreateModuleResourceManagerSync(ani_env *env, ani_object aniObj,
    ani_string bundleName, ani_string moduleName)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    std::string stdBundleName = "";
    AppExecFwk::GetStdString(env, bundleName, stdBundleName);
    std::string stdModuleName = "";
    AppExecFwk::GetStdString(env, moduleName, stdModuleName);
    auto context = GetBaseContext(env, aniObj);
    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return nullptr;
    }
    if (!CheckCallerIsSystemApp()) {
        TAG_LOGE(AAFwkTag::APPKIT, "not system-app");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP);
        return nullptr;
    }
    auto resourceManager = context->CreateModuleResourceManager(stdBundleName, stdModuleName);
    if (resourceManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null resourceManager");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return nullptr;
    }
    return Global::Resource::ResMgrAddon::CreateResMgr(env, "", resourceManager, context);
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
        if (appContextObj != nullptr && appContextObj->aniRef != nullptr) {
            TAG_LOGD(AAFwkTag::APPKIT, "appContextObj is not nullptr");
            return reinterpret_cast<ani_object>(appContextObj->aniRef);
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