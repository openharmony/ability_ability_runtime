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
#include "event_hub.h"
#include "hilog_tag_wrapper.h"
#include "resourceManager.h"
#include "sts_error_utils.h"
#include "ani_common_util.h"
#include "ability_runtime_error_util.h"
#include "tokenid_kit.h"
#include "ipc_skeleton.h"
#include "js_runtime.h"
#include "js_runtime_utils.h"
#include "js_context_utils.h"
#include "native_engine/native_engine.h"

namespace OHOS {
namespace AbilityRuntime {
namespace ContextUtil {
namespace {
constexpr const char* AREA_MODE_ENUM_NAME = "L@ohos/app/ability/contextConstant/contextConstant/AreaMode;";
constexpr const char* CONTEXT_CLASS_NAME = "Lapplication/Context/Context;";

void BindContextDirInner(ani_env *aniEnv, ani_object contextObj, std::shared_ptr<Context> context)
{
    ani_status status = ANI_ERROR;
    auto cloudFileDir = context->GetCloudFileDir();
    ani_string cloudFileDirString = nullptr;
    aniEnv->String_NewUTF8(cloudFileDir.c_str(), cloudFileDir.size(), &cloudFileDirString);
    if ((status = aniEnv->Object_SetFieldByName_Ref(contextObj, "cloudFileDir", cloudFileDirString)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "cloudFileDir SetField status: %{public}d", status);
        return;
    }

    auto distributedFilesDir = context->GetDistributedFilesDir();
    ani_string distributedFilesDirString = nullptr;
    aniEnv->String_NewUTF8(distributedFilesDir.c_str(), distributedFilesDir.size(), &distributedFilesDirString);
    if ((status = aniEnv->Object_SetFieldByName_Ref(contextObj, "distributedFilesDir",
        distributedFilesDirString)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "distributedFilesDir SetField status: %{public}d", status);
        return;
    }

    auto bundleCodeDir = context->GetBundleCodeDir();
    ani_string bundleCodeDirString = nullptr;
    aniEnv->String_NewUTF8(bundleCodeDir.c_str(), bundleCodeDir.size(), &bundleCodeDirString);
    if ((status = aniEnv->Object_SetFieldByName_Ref(contextObj, "bundleCodeDir", bundleCodeDirString)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "bundleCodeDir SetField status: %{public}d", status);
        return;
    }

    auto resourceDir = context->GetResourceDir();
    ani_string resourceDirString = nullptr;
    aniEnv->String_NewUTF8(resourceDir.c_str(), resourceDir.size(), &resourceDirString);
    if ((status = aniEnv->Object_SetFieldByName_Ref(contextObj, "resourceDir", resourceDirString)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "resourceDir SetField status: %{public}d", status);
        return;
    }
}

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
    BindContextDirInner(aniEnv, contextObj, context);
}
} // namespace

static std::weak_ptr<Context> context_;

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
    BindContextDir(aniEnv, contextObj, context);

    // bind parent context property
    ani_field areaField;
    ani_status status = ANI_ERROR;
    if ((status = aniEnv->Class_FindField(contextClass, "area", &areaField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "find area failed, status: %{public}d", status);
        return;
    }
    auto area = context->GetArea();
    ani_enum_item areaModeItem = nullptr;
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvertNativeToSts(aniEnv, AREA_MODE_ENUM_NAME, area, areaModeItem);

    if ((status = aniEnv->Object_SetField_Ref(contextObj, areaField, (ani_ref)areaModeItem)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Int failed, status: %{public}d", status);
        return;
    }

    ani_field processNameField;
    if ((status = aniEnv->Class_FindField(contextClass, "processName", &processNameField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "find processName failed status: %{public}d", status);
        return;
    }
    auto processName = context->GetProcessName();
    ani_string processNameString = nullptr;
    aniEnv->String_NewUTF8(processName.c_str(), processName.size(), &processNameString);
    if ((status = aniEnv->Object_SetField_Ref(contextObj, processNameField,
        reinterpret_cast<ani_ref>(processNameString))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed, status: %{public}d", status);
        return;
    }
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

void StsCreateContext(ani_env* aniEnv, ani_class contextClass, ani_object contextObj, std::shared_ptr<Context> context)
{
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "aniEnv is nullptr");
        return;
    }
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "context is nullptr");
        return;
    }
    if (!SetHapModuleInfo(aniEnv, contextClass, contextObj, context)) {
        TAG_LOGE(AAFwkTag::APPKIT, "SetHapModuleInfo fail");
    }
    BindParentProperty(aniEnv, contextClass, contextObj, context);
    // set eventhub context
    TAG_LOGI(AAFwkTag::APPKIT, "set eventhub context");
    ani_ref eventHubRef = nullptr;
    ani_status status = ANI_OK;
    if ((status = aniEnv->Object_GetFieldByName_Ref(contextObj, "eventHub", &eventHubRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_GetFieldByName_Ref failed status: %{public}d", status);
        return;
    }
 
    AbilityRuntime::EventHub::SetEventHubContext(aniEnv, eventHubRef, reinterpret_cast<ani_ref>(contextObj));
}

std::shared_ptr<Context> GetBaseContext(ani_env *env, ani_object aniObj)
{
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    ani_class cls {};
    if ((status = env->FindClass(CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return nullptr;
    }
    ani_field contextField = nullptr;
    if ((status = env->Class_FindField(cls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return nullptr;
    }
    ani_long nativeContextLong = 0;
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
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(selfToken)) {
        return false;
    }
    return true;
}

ani_object CreateModuleResourceManagerSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_string bundleName, ani_string moduleName)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return {};
    }
    std::string bundleName_ = "";
    AppExecFwk::AniStringToStdString(env, bundleName, bundleName_);
    std::string moduleName_ = "";
    AppExecFwk::AniStringToStdString(env, moduleName, moduleName_);
    auto context = GetBaseContext(env, aniObj);
    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return {};
    }
    if (!CheckCallerIsSystemApp()) {
        TAG_LOGE(AAFwkTag::APPKIT, "not system-app");
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_NOT_SYSTEM_APP);
        return {};
    }
    auto resourceManager = context->CreateModuleResourceManager(bundleName_, moduleName_);
    if (resourceManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null resourceManager");
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return {};
    }
    return Global::Resource::ResMgrAddon::CreateResMgr(env, "", resourceManager, context);
}

ani_object GetApplicationContextSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj)
{
    auto appContextObj = ApplicationContextManager::GetApplicationContextManager().GetEtsGlobalObject();
    if (appContextObj != nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "appContextObj is not nullptr");
        return appContextObj->aniObj;
    }
    ThrowStsInvalidParamError(env, "appContextObj null");
    return {};
}

void NativeGetGroupDir([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_string dataGroupIdObj, ani_object callBackObj)
{
    TAG_LOGD(AAFwkTag::APPKIT, "NativeGetGroupDir");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env is nullptr");
        return;
    }
    std::string dataGroupId = "";
    if (!AppExecFwk::AniStringToStdString(env, dataGroupIdObj, dataGroupId)) {
        TAG_LOGE(AAFwkTag::APPKIT, "Parse groupId failed");
        AppExecFwk::AsyncCallback(env, callBackObj, CreateStsError(env,
            AbilityErrorCode::ERROR_CODE_INVALID_PARAM), nullptr);
        ThrowStsInvalidParamError(env, "Parse param groupId failed, groupId must be string.");
        return;
    }
    auto context = GetBaseContext(env, aniObj);
    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        AppExecFwk::AsyncCallback(env, callBackObj, CreateStsError(env,
            AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT), nullptr);
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        return;
    }
    ErrCode ret = ERR_OK;
    std::string path = context->GetGroupDir(dataGroupId);
    ani_object errorObject = CreateStsError(env, static_cast<AbilityErrorCode>(ret));
    ani_string aniPath = AppExecFwk::GetAniString(env, path);
    AppExecFwk::AsyncCallback(env, callBackObj, errorObject, aniPath);
}

void SwitchArea(ani_env *env, ani_object obj, ani_enum_item areaModeItem)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
    }
    int32_t areaMode = 0;
    if (!AAFwk::AniEnumConvertUtil::EnumConvertStsToNative(env, areaModeItem, areaMode)) {
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
    OHOS::AAFwk::AniEnumConvertUtil::EnumConvertNativeToSts(env, AREA_MODE_ENUM_NAME, areaMode, areaModeItem);
    return areaModeItem;
}

ani_object NativeCreateDisplayContext(ani_env *env, ani_object aniObj, ani_double displayId)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "NativeCreateDisplayContext");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    ani_ref undefRef = nullptr;
    ani_status status = env->GetUndefined(&undefRef);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "GetUndefined failed %{public}d", status);
        return nullptr;
    }
#ifdef SUPPORT_GRAPHICS
    auto context = GetBaseContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return reinterpret_cast<ani_object>(undefRef);
    }
    if (displayId < 0) {
        TAG_LOGE(AAFwkTag::APPKIT, "displayId is invalid, less than 0");
        ThrowStsError(env, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
        return reinterpret_cast<ani_object>(undefRef);
    }
    uint64_t validDisplayId = static_cast<uint64_t>(displayId);
    auto displayContext = context->CreateDisplayContext(validDisplayId);
    if (displayContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "Failed to create displayContext");
        return reinterpret_cast<ani_object>(undefRef);
    }
    ani_class contextClass = nullptr;
    status = env->FindClass(CONTEXT_CLASS_NAME, &contextClass);
    if (status != ANI_OK || contextClass == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass Context failed, status: %{public}d", status);
        AbilityRuntime::ThrowStsInvalidParamError(env, "FindClass failed");
        return reinterpret_cast<ani_object>(undefRef);
    }
    ani_object displayContextObj = CreateContextObject(env, contextClass, displayContext);
    if (displayContextObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null contextObj");
        return reinterpret_cast<ani_object>(undefRef);
    }
    return displayContextObj;
#else
    return reinterpret_cast<ani_object>(undefRef);
#endif
}

ani_object NativeCreateAreaModeContext(ani_env *env, ani_object aniObj, ani_object areaModeObj)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "NativeCreateAreaModeContext");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return nullptr;
    }
    ani_ref undefRef = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GetUndefined(&undefRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "GetUndefined failed %{public}d", status);
        return nullptr;
    }
    auto context = GetBaseContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return reinterpret_cast<ani_object>(undefRef);
    }
    int areaMode = 0;
    if (!AAFwk::AniEnumConvertUtil::EnumConvertStsToNative(env, areaModeObj, areaMode)) {
        TAG_LOGE(AAFwkTag::APPMGR, "param areaMode err");
        ThrowStsInvalidNumParametersError(env);
        return reinterpret_cast<ani_object>(undefRef);
    }
    auto areaContext = context->CreateAreaModeContext(areaMode);
    if (areaContext == nullptr) {
        ThrowStsError(env, ERR_ABILITY_RUNTIME_EXTERNAL_INVALID_PARAMETER);
        TAG_LOGE(AAFwkTag::APPKIT, "Failed to create areaContext");
        return reinterpret_cast<ani_object>(undefRef);
    }
    ani_class contextClass = nullptr;
    if ((status = env->FindClass(CONTEXT_CLASS_NAME, &contextClass)) != ANI_OK || contextClass == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass Context failed status: %{public}d", status);
        AbilityRuntime::ThrowStsInvalidParamError(env, "FindClass failed");
        return reinterpret_cast<ani_object>(undefRef);
    }
    ani_object areaContextObj = CreateContextObject(env, contextClass, areaContext);
    if (areaContextObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null areaContextObj");
        return reinterpret_cast<ani_object>(undefRef);
    }
    return areaContextObj;
}

ani_object NativeCreateSystemHspModuleResourceManager(ani_env *env, ani_object aniObj,
    ani_string bundleNameObj, ani_string moduleNameObj)
{
    TAG_LOGE(AAFwkTag::UIABILITY, "NativeCreateSystemHspModuleResourceManager");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env is nullptr");
        return nullptr;
    }
    ani_ref undefRef = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GetUndefined(&undefRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "GetUndefined failed %{public}d", status);
        return nullptr;
    }
    auto context = GetBaseContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
        return reinterpret_cast<ani_object>(undefRef);
    }
    std::string bundleName = "";
    if (!AppExecFwk::AniStringToStdString(env, bundleNameObj, bundleName)) {
        TAG_LOGE(AAFwkTag::APPKIT, "Parse bundleName failed");
        ThrowStsInvalidParamError(env, "Parse param bundleName failed, bundleName must be string.");
        return reinterpret_cast<ani_object>(undefRef);
    }
    std::string moduleName = "";
    if (!AppExecFwk::AniStringToStdString(env, moduleNameObj, moduleName)) {
        TAG_LOGE(AAFwkTag::APPKIT, "Parse moduleName failed");
        ThrowStsInvalidParamError(env, "Parse param moduleName failed, moduleName must be string.");
        return reinterpret_cast<ani_object>(undefRef);
    }
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager = nullptr;
    int32_t retCode = context->CreateSystemHspModuleResourceManager(bundleName, moduleName, resourceManager);
    if (resourceManager == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null resourceManager, errorCode:%{public}d", retCode);
        ThrowStsError(env, retCode);
        return reinterpret_cast<ani_object>(undefRef);
    }
    return Global::Resource::ResMgrAddon::CreateResMgr(env, "", resourceManager, context);
}

ani_object CreateContextObject(ani_env* env, ani_class contextClass, std::shared_ptr<Context> nativeContext)
{
    ani_object contextObj = nullptr;
    ani_method ctorMethod = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->Class_FindMethod(contextClass, "<ctor>", ":V", &ctorMethod)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Find ctor method failed, status: %{public}d", status);
        return nullptr;
    }
    if (ctorMethod == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null ctorMethod");
        return nullptr;
    }
    if ((status = env->Object_New(contextClass, ctorMethod, &contextObj)) != ANI_OK || contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_New failed, status: %{public}d", status);
        return nullptr;
    }
    StsCreateContext(env, contextClass, contextObj, nativeContext);
    ani_field contextField;
    if ((status = env->Class_FindField(contextClass, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "call Class_FindField nativeContext failed");
        return nullptr;
    }
    auto workContext = new (std::nothrow) std::weak_ptr<AbilityRuntime::Context>(nativeContext);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "workContext nullptr");
        return nullptr;
    }
    ani_long nativeContextLong = (ani_long)workContext;
    if ((status = env->Object_SetField_Long(contextObj, contextField, nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "call Object_SetField_Long contextField failed");
        delete workContext;
        return nullptr;
    }
    return contextObj;
}
}
} // namespace AbilityRuntime
} // namespace OHOS
