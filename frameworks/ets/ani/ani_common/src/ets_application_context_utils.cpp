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
#include "ets_application_context_utils.h"

#include "ani_enum_convert.h"
#include "application_context_manager.h"
#include "ets_context_utils.h"
#include "ets_error_utils.h"
#include "ets_native_reference.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
static std::once_flag g_bindNativeMethodsFlag;
constexpr const char* ETS_APPLICATION_CONTEXT_CLASS_NAME = "Lapplication/ApplicationContext/ApplicationContext;";
constexpr const char* CLEANER_CLASS = "Lapplication/ApplicationContext/Cleaner;";
constexpr double FOUNT_SIZE = 0.0;
}
void EtsApplicationContextUtils::Clean(ani_env *env, ani_object object)
{
    TAG_LOGD(AAFwkTag::APPKIT, "Clean Call");
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
        delete reinterpret_cast<EtsApplicationContextUtils *>(ptr);
    }
}

void EtsApplicationContextUtils::OnRestartApp(ani_env *env, ani_object aniObj, ani_object wantObj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null applicationContext");
        return;
    }
    AAFwk::Want want;
    if (!AppExecFwk::UnwrapWant(env, wantObj, want)) {
        TAG_LOGE(AAFwkTag::APPKIT, "Parse want failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param want failed, want must be Want.");
        return;
    }
    auto errCode = applicationContext->RestartApp(want);
    switch (errCode) {
        case ERR_INVALID_VALUE:
            EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
            break;
        case AAFwk::ERR_RESTART_APP_INCORRECT_ABILITY:
            EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_RESTART_APP_INCORRECT_ABILITY);
            break;
        case AAFwk::ERR_RESTART_APP_FREQUENT:
            EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_RESTART_APP_FREQUENT);
            break;
        case AAFwk::NOT_TOP_ABILITY:
            EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_NOT_TOP_ABILITY);
            break;
        default:
            EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
    }
    TAG_LOGD(AAFwkTag::APPKIT, "RestartApp errCode is %{public}d", errCode);
}

void EtsApplicationContextUtils::OnSetFont(ani_env *env, ani_object aniObj, ani_string font)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null applicationContext");
        return;
    }
    std::string stdFont = "";
    if (!AppExecFwk::GetStdString(env, font, stdFont) || stdFont.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "Parse font failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param font failed, font must be string.");
        return;
    }
    TAG_LOGD(AAFwkTag::APPKIT, "SetFont font %{public}s", stdFont.c_str());
    applicationContext->SetFont(stdFont);
}

void EtsApplicationContextUtils::OnSetColorMode(ani_env *env, ani_object aniObj, ani_enum_item colorMode)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null applicationContext");
        return;
    }
    ani_int mode = 0;
    if (!AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(env, colorMode, mode)) {
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param colorMode failed, colorMode must be number.");
        TAG_LOGE(AAFwkTag::APPKIT, "Parse colorMode failed");
        return;
    }
    TAG_LOGD(AAFwkTag::APPKIT, "colorMode is %{public}d", mode);
    applicationContext->SetColorMode(static_cast<int32_t>(mode));
}

void EtsApplicationContextUtils::OnSetLanguage(ani_env *env, ani_object aniObj, ani_string language)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null applicationContext");
        return;
    }
    std::string stdLanguage = "";
    if (!AppExecFwk::GetStdString(env, language, stdLanguage) || stdLanguage.empty()) {
        TAG_LOGE(AAFwkTag::APPKIT, "Parse language failed");
        EtsErrorUtil::ThrowInvalidParamError(env, "Parse param language failed, language must be string.");
        return;
    }
    applicationContext->SetLanguage(stdLanguage);
    TAG_LOGD(AAFwkTag::APPKIT, "stdLanguage language %{public}s", stdLanguage.c_str());
}

void EtsApplicationContextUtils::OnSetFontSizeScale(ani_env *env, ani_object aniObj, ani_double fontSizeScale)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null applicationContext");
        return;
    }

    double stdFontSizeScale = static_cast<double>(fontSizeScale);
    TAG_LOGD(AAFwkTag::APPKIT, "fontSizeScale: %{public}f", stdFontSizeScale);
    if (fontSizeScale < FOUNT_SIZE) {
        TAG_LOGE(AAFwkTag::APPKIT, "invalid size");
        EtsErrorUtil::ThrowInvalidParamError(env, "Invalid font size.");
        return;
    }
    applicationContext->SetFontSizeScale(stdFontSizeScale);
}

void EtsApplicationContextUtils::OnClearUpApplicationData(ani_env *env, ani_object aniObj, ani_object callback)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "nativeContext is null");
        AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateError(env,
            (ani_int)AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT,
            "applicationContext if already released."), nullptr);
        return;
    }
    AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), nullptr);
    applicationContext->ClearUpApplicationData();
}

void EtsApplicationContextUtils::OnGetRunningProcessInformation(ani_env *env, ani_object aniObj, ani_object callback)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    ani_object emptyArray = AppExecFwk::CreateEmptyArray(env);
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "nativeContext is null");
        AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateError(env,
            (ani_int)AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT,
            "applicationContext if already released."), emptyArray);
        return;
    }
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    AppExecFwk::RunningProcessInfo processInfo;
    ErrCode innerErrCode = applicationContext->GetProcessRunningInformation(processInfo);
    if (innerErrCode == ERR_OK) {
        infos.emplace_back(processInfo);
        ani_object aniInfosRef = AppExecFwk::CreateRunningProcessInfoArray(env, infos);
        if (aniInfosRef == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null array");
            AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateError(env,
                (ani_int)AbilityErrorCode::ERROR_CODE_INNER, "Initiate array failed."), emptyArray);
        } else {
            AppExecFwk::AsyncCallback(env, callback,
                EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK), aniInfosRef);
        }
    } else {
        AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateError(env,
            (ani_int)AbilityErrorCode::ERROR_CODE_INNER, "Get process infos failed."), emptyArray);
    }
}

void EtsApplicationContextUtils::OnkillAllProcesses(ani_env *env, ani_object aniObj,
    ani_boolean clearPageStack, ani_object callback)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env is nullptr");
        return;
    }
    ani_object aniObject = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    auto context = applicationContext_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "nativeContextLong is nullptr");
        aniObject = EtsErrorUtil::CreateError(env, (ani_int)AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT,
            "applicationContext is already released.");
        AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
    context->KillProcessBySelf(clearPageStack);
}

void EtsApplicationContextUtils::OnPreloadUIExtensionAbility(ani_env *env,
    ani_object aniObj, ani_object wantObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "PreloadUIExtensionAbility Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    AAFwk::Want want;
    if (!OHOS::AppExecFwk::UnwrapWant(env, wantObj, want)) {
        TAG_LOGE(AAFwkTag::APPKIT, "Parse want failed");
        AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateInvalidParamError(env,
            "Parse param want failed, want must be Want."), nullptr);
        return;
    }
    auto context = applicationContext_.lock();
    if (!context) {
        AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateErrorByNativeErr(env,
            (int32_t)AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT), nullptr);
        return;
    }
    auto hostBundleName = context->GetBundleName();
    TAG_LOGD(AAFwkTag::APPKIT, "HostBundleName is %{public}s", hostBundleName.c_str());
    auto innerErrCode = AAFwk::AbilityManagerClient::GetInstance()->PreloadUIExtensionAbility(want, hostBundleName);
    if (innerErrCode == ERR_OK) {
        AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateError(env,
            AbilityErrorCode::ERROR_OK), nullptr);
    } else {
        TAG_LOGE(AAFwkTag::APPKIT, "OnPreloadUIExtensionAbility failed %{public}d", innerErrCode);
        AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateErrorByNativeErr(env, innerErrCode), nullptr);
    }
}

void EtsApplicationContextUtils::OnSetSupportedProcessCacheSync(ani_env *env, ani_object aniObj, ani_boolean value)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null applicationContext");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        return;
    }
    int32_t errCode = applicationContext->SetSupportedProcessCacheSelf(value);
    if (errCode == AAFwk::ERR_CAPABILITY_NOT_SUPPORT) {
        EtsErrorUtil::ThrowError(env,
            AbilityErrorCode::ERROR_CODE_CAPABILITY_NOT_SUPPORT);
    } else if (errCode != ERR_OK) {
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
    }
}

void EtsApplicationContextUtils::RestartApp(ani_env *env, ani_object aniObj, ani_object wantObj)
{
    TAG_LOGD(AAFwkTag::APPKIT, "RestartApp Call");
    auto etsContext = GeApplicationContext(env, aniObj);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null etsContext");
        return;
    }
    etsContext->OnRestartApp(env, aniObj, wantObj);
}

void EtsApplicationContextUtils::SetFont(ani_env *env, ani_object aniObj, ani_string font)
{
    TAG_LOGD(AAFwkTag::APPKIT, "SetFont Call");
    auto etsContext = GeApplicationContext(env, aniObj);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null etsContext");
        return;
    }
    etsContext->OnSetFont(env, aniObj, font);
}

void EtsApplicationContextUtils::SetColorMode(ani_env *env, ani_object aniObj, ani_enum_item colorMode)
{
    TAG_LOGD(AAFwkTag::APPKIT, "SetColorMode Call");
    auto etsContext = GeApplicationContext(env, aniObj);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null etsContext");
        return;
    }
    etsContext->OnSetColorMode(env, aniObj, colorMode);
}

void EtsApplicationContextUtils::SetLanguage(ani_env *env, ani_object aniObj, ani_string language)
{
    TAG_LOGD(AAFwkTag::APPKIT, "SetLanguage Call");
    auto etsContext = GeApplicationContext(env, aniObj);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null etsContext");
        return;
    }
    etsContext->OnSetLanguage(env, aniObj, language);
}

void EtsApplicationContextUtils::SetFontSizeScale(ani_env *env, ani_object aniObj, ani_double fontSizeScale)
{
    TAG_LOGD(AAFwkTag::APPKIT, "SetFontSizeScale Call");
    auto etsContext = GeApplicationContext(env, aniObj);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null etsContext");
        return;
    }
    etsContext->OnSetFontSizeScale(env, aniObj, fontSizeScale);
}

void EtsApplicationContextUtils::ClearUpApplicationData(ani_env *env, ani_object aniObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "ClearUpApplicationData Call");
    auto etsContext = GeApplicationContext(env, aniObj);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null etsContext");
        return;
    }
    etsContext->OnClearUpApplicationData(env, aniObj, callback);
}

void EtsApplicationContextUtils::GetRunningProcessInformation(ani_env *env, ani_object aniObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "GetRunningProcessInformation Call");
    auto etsContext = GeApplicationContext(env, aniObj);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null etsContext");
        return;
    }
    etsContext->OnGetRunningProcessInformation(env, aniObj, callback);
}

void EtsApplicationContextUtils::killAllProcesses(ani_env *env, ani_object aniObj,
    ani_boolean clearPageStack, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "killAllProcesses Call");
    auto etsContext = GeApplicationContext(env, aniObj);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null etsContext");
        return;
    }
    etsContext->OnkillAllProcesses(env, aniObj, clearPageStack, callback);
}

void EtsApplicationContextUtils::PreloadUIExtensionAbility(ani_env *env,
    ani_object aniObj, ani_object wantObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "PreloadUIExtensionAbility Call");
    auto etsContext = GeApplicationContext(env, aniObj);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null etsContext");
        return;
    }
    etsContext->OnPreloadUIExtensionAbility(env, aniObj, wantObj, callback);
}

void EtsApplicationContextUtils::SetSupportedProcessCacheSync(ani_env *env, ani_object aniObj, ani_boolean value)
{
    TAG_LOGD(AAFwkTag::APPKIT, "SetSupportedProcessCacheSync Call");
    auto etsContext = GeApplicationContext(env, aniObj);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null etsContext");
        return;
    }
    etsContext->OnSetSupportedProcessCacheSync(env, aniObj, value);
}

EtsApplicationContextUtils* EtsApplicationContextUtils::GeApplicationContext(ani_env *env, ani_object aniObj)
{
    if (env == nullptr || aniObj == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env or aniObj");
        return nullptr;
    }
    ani_long etsApplicationContextPtr = 0;
    ani_status status = env->Object_GetFieldByName_Long(aniObj, "etsApplicationContextPtr", &etsApplicationContextPtr);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "etsApplicationContextPtr GetField status: %{public}d", status);
        return nullptr;
    }
    auto etsContext = reinterpret_cast<EtsApplicationContextUtils *>(etsApplicationContextPtr);
    return etsContext;
}

ani_object EtsApplicationContextUtils::SetApplicationContext(ani_env* aniEnv,
    const std::shared_ptr<ApplicationContext> &applicationContext)
{
    TAG_LOGD(AAFwkTag::APPKIT, "SetApplicationContext Call");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv");
        return nullptr;
    }
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    ani_class cls {};
    if ((status = aniEnv->FindClass(ETS_APPLICATION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return nullptr;
    }
    ani_method method {};
    if ((status = aniEnv->Class_FindMethod(cls, "<ctor>", "J:V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        return nullptr;
    }
    auto etsContext = new (std::nothrow) EtsApplicationContextUtils(applicationContext);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "workContext nullptr");
        return nullptr;
    }
    ani_object contextObj = nullptr;
    if ((status = aniEnv->Object_New(cls, method, &contextObj, reinterpret_cast<ani_long>(etsContext))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "status: %{public}d", status);
        delete etsContext;
        etsContext = nullptr;
        return nullptr;
    }
    auto workContext = new (std::nothrow) std::weak_ptr<ApplicationContext>(etsContext->applicationContext_);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null workContext");
        return nullptr;
    }
    ani_long nativeContextLong = reinterpret_cast<ani_long>(workContext);
    if (!ContextUtil::SetNativeContextLong(aniEnv, contextObj, nativeContextLong)) {
        TAG_LOGE(AAFwkTag::APPKIT, "SetNativeContextLong failed");
        delete workContext;
        workContext = nullptr;
        return nullptr;
    }
    return contextObj;
}

void EtsApplicationContextUtils::BindApplicationContextFunc(ani_env* aniEnv)
{
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv");
        return;
    }
    ani_class contextClass = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = aniEnv->FindClass(ETS_APPLICATION_CONTEXT_CLASS_NAME, &contextClass)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass ApplicationContext failed status: %{public}d", status);
        return;
    }
    std::call_once(g_bindNativeMethodsFlag, [&status, aniEnv, contextClass]() {
        std::array applicationContextFunctions = {
            ani_native_function {"setSupportedProcessCacheSync", "Z:V",
                reinterpret_cast<void *>(EtsApplicationContextUtils::SetSupportedProcessCacheSync)},
            ani_native_function {"nativekillAllProcessesSync", "ZLutils/AbilityUtils/AsyncCallbackWrapper;:V",
                reinterpret_cast<void *>(EtsApplicationContextUtils::killAllProcesses)},
            ani_native_function {"nativepreloadUIExtensionAbilitySync",
                "L@ohos/app/ability/Want/Want;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
                reinterpret_cast<void *>(EtsApplicationContextUtils::PreloadUIExtensionAbility)},
            ani_native_function {"nativegetRunningProcessInformation",
                "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
                reinterpret_cast<void *>(EtsApplicationContextUtils::GetRunningProcessInformation)},
            ani_native_function {"nativeclearUpApplicationData",
                "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
                reinterpret_cast<void *>(EtsApplicationContextUtils::ClearUpApplicationData)},
            ani_native_function {"nativesetLanguage", "Lstd/core/String;:V",
                reinterpret_cast<void *>(EtsApplicationContextUtils::SetLanguage)},
            ani_native_function {"nativesetFontSizeScale", "D:V",
                reinterpret_cast<void *>(EtsApplicationContextUtils::SetFontSizeScale)},
            ani_native_function {"nativesetColorMode",
                "L@ohos/app/ability/ConfigurationConstant/ConfigurationConstant/ColorMode;:V",
                reinterpret_cast<void *>(EtsApplicationContextUtils::SetColorMode)},
            ani_native_function {"nativesetFont", "Lstd/core/String;:V",
                reinterpret_cast<void *>(EtsApplicationContextUtils::SetFont)},
            ani_native_function {"nativerestartApp", "L@ohos/app/ability/Want/Want;:V",
                reinterpret_cast<void *>(EtsApplicationContextUtils::RestartApp)},
        };
        if ((status = aniEnv->Class_BindNativeMethods(contextClass, applicationContextFunctions.data(),
            applicationContextFunctions.size())) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "Class_BindNativeMethods failed status: %{public}d", status);
            return;
        }
        ani_class cleanerCls = nullptr;
        if ((status = aniEnv->FindClass(CLEANER_CLASS, &cleanerCls)) != ANI_OK || cleanerCls == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "Cleaner FindClass failed status: %{public}d, or null cleanerCls", status);
            return;
        }
        std::array cleanerMethods = {
            ani_native_function {"clean", nullptr, reinterpret_cast<void *>(EtsApplicationContextUtils::Clean) },
        };
        if ((status = aniEnv->Class_BindNativeMethods(cleanerCls, cleanerMethods.data(),
            cleanerMethods.size())) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "Class_BindNativeMethods failed status: %{public}d", status);
            return;
        }
    });
}

ani_object EtsApplicationContextUtils::CreateEtsApplicationContext(ani_env* aniEnv,
    const std::shared_ptr<ApplicationContext> &applicationContext)
{
    TAG_LOGD(AAFwkTag::APPKIT, "CreateEtsApplicationContext Call");
    if (applicationContext == nullptr || aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null applicationContext or aniEnv");
        return nullptr;
    }
    ani_object applicationContextObject = SetApplicationContext(aniEnv, applicationContext);
    ani_status status = ANI_ERROR;
    ani_ref applicationContextObjectRef = nullptr;
    if ((status = aniEnv->GlobalReference_Create(applicationContextObject, &applicationContextObjectRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Create failed status: %{public}d", status);
        return nullptr;
    }
    auto etsReference = std::make_shared<AppExecFwk::ETSNativeReference>();
    etsReference->aniObj = applicationContextObject;
    ApplicationContextManager::GetApplicationContextManager().SetEtsGlobalObject(etsReference);
    BindApplicationContextFunc(aniEnv);
    ani_class applicationContextClass = nullptr;
    if ((status = aniEnv->FindClass(ETS_APPLICATION_CONTEXT_CLASS_NAME, &applicationContextClass)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass ApplicationContext failed status: %{public}d", status);
        return nullptr;
    }
    ContextUtil::CreateEtsBaseContext(aniEnv, applicationContextClass, applicationContextObject, applicationContext);
    return applicationContextObject;
}
} // namespace AbilityRuntime
} // namespace OHOS