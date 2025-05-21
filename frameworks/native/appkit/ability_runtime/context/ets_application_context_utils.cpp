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
#include "application_context_manager.h"
#include "hilog_tag_wrapper.h"
#include "sts_app_manager_utils.h"
#include "ani_enum_convert.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
    constexpr const char* STS_APPLICATION_CONTEXT_CLASS_NAME = "Lapplication/ApplicationContext/ApplicationContext;";
}
std::weak_ptr<ApplicationContext> applicationContext_;
std::shared_ptr<EtsEnviromentCallback> etsEnviromentCallback_ = nullptr;

void EtsApplicationContextUtils::RestartApp([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_object wantObj)
{
    TAG_LOGD(AAFwkTag::APPKIT, "RestartApp Call");
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
        ThrowStsInvalidParamError(env, "Parse param want failed, want must be Want.");
        return;
    }
    auto errCode = applicationContext->RestartApp(want);
    if (errCode == ERR_INVALID_VALUE) {
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
    } else if (errCode == AAFwk::ERR_RESTART_APP_INCORRECT_ABILITY) {
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_RESTART_APP_INCORRECT_ABILITY);
    } else if (errCode == AAFwk::ERR_RESTART_APP_FREQUENT) {
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_RESTART_APP_FREQUENT);
    } else if (errCode == AAFwk::NOT_TOP_ABILITY) {
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_NOT_TOP_ABILITY);
    } else {
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
    }
    TAG_LOGD(AAFwkTag::APPKIT, "RestartApp errCode is %{public}d", errCode);
}

void EtsApplicationContextUtils::SetFont([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_string font)
{
    TAG_LOGD(AAFwkTag::APPKIT, "SetFont Call");
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
    if (!AppExecFwk::GetStdString(env, font, stdFont)) {
        TAG_LOGE(AAFwkTag::APPKIT, "Parse font failed");
        ThrowStsInvalidParamError(env, "Parse param font failed, font must be string.");
    }
    TAG_LOGD(AAFwkTag::APPKIT, "SetFont font %{public}s", stdFont.c_str());
    applicationContext->SetFont(stdFont);
}

void EtsApplicationContextUtils::SetColorMode([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_enum_item colorMode)
{
    TAG_LOGD(AAFwkTag::APPKIT, "SetColorMode Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null applicationContext");
        return;
    }
    ani_int mode;
    if (!AAFwk::AniEnumConvertUtil::EnumConvertStsToNative(env, colorMode, mode)) {
        ThrowStsInvalidParamError(env, "Parse param colorMode failed, colorMode must be number.");
        TAG_LOGE(AAFwkTag::APPKIT, "Parse colorMode failed");
        return;
    }
    TAG_LOGD(AAFwkTag::APPKIT, "colorMode is %{public}d", mode);
    applicationContext->SetColorMode(static_cast<int32_t>(mode));
}

void EtsApplicationContextUtils::ClearUpApplicationData([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "ClearUpApplicationData Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "nativeContext is null");
        AppExecFwk::AsyncCallback(env, callback, CreateStsError(env,
            (ani_int)AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT,
            "applicationContext if already released."), nullptr);
        return;
    }
    applicationContext->ClearUpApplicationData();
    AppExecFwk::AsyncCallback(env, callback, CreateStsError(env, AbilityErrorCode::ERROR_OK), nullptr);
}

void EtsApplicationContextUtils::GetRunningProcessInformation([[maybe_unused]]ani_env *env,
    [[maybe_unused]]ani_object aniObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "GetRunningProcessInformation Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    ani_object emptyArray = AppManagerSts::CreateEmptyAniArray(env);
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "nativeContext is null");
        AppExecFwk::AsyncCallback(env, callback, CreateStsError(env,
            (ani_int)AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT,
            "applicationContext if already released."), emptyArray);
        return;
    }
    std::vector<AppExecFwk::RunningProcessInfo> infos;
    AppExecFwk::RunningProcessInfo processInfo;
    ErrCode innerErrCode = applicationContext->GetProcessRunningInformation(processInfo);
    if (innerErrCode == ERR_OK) {
        infos.emplace_back(processInfo);
        ani_object aniInfosRef = AppManagerSts::CreateRunningProcessInfoArray(env, infos);
        if (aniInfosRef == nullptr) {
            TAG_LOGE(AAFwkTag::APPKIT, "null array");
            AppExecFwk::AsyncCallback(env, callback, CreateStsError(env,
                (ani_int)AbilityErrorCode::ERROR_CODE_INNER, "Initiate array failed."), emptyArray);
        } else {
            AppExecFwk::AsyncCallback(env, callback, CreateStsError(env, AbilityErrorCode::ERROR_OK), aniInfosRef);
        }
    } else {
        AppExecFwk::AsyncCallback(env, callback, CreateStsError(env,
            (ani_int)AbilityErrorCode::ERROR_CODE_INNER, "Get process infos failed."), emptyArray);
    }
}

ani_double EtsApplicationContextUtils::NativeOnSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_string type, ani_object envCallback)
{
    TAG_LOGD(AAFwkTag::APPKIT, "NativeOnSync Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env is nullptr");
        return ANI_ERROR;
    }
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "nativeContext is null");
        AbilityRuntime::ThrowStsInvalidParamError(env, "nativeContext is null");
        return ANI_ERROR;
    }
    if (etsEnviromentCallback_ != nullptr) {
        return ani_double(etsEnviromentCallback_->Register(envCallback));
    }

    etsEnviromentCallback_ = std::make_shared<EtsEnviromentCallback>(env);
    int32_t callbackId = etsEnviromentCallback_->Register(envCallback);
    applicationContext->RegisterEnvironmentCallback(etsEnviromentCallback_);

    return ani_double(callbackId);
}

void EtsApplicationContextUtils::NativeOffSync([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_string type, ani_double callbackId, ani_object call)
{
    TAG_LOGD(AAFwkTag::APPKIT, "NativeOffSync Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env is nullptr");
        return;
    }
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr) {
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

void EtsApplicationContextUtils::killAllProcesses([[maybe_unused]]ani_env *env, [[maybe_unused]]ani_object aniObj,
    ani_boolean clearPageStack, ani_object call)
{
    TAG_LOGD(AAFwkTag::APPKIT, "killAllProcesses Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "env is nullptr");
        return;
    }
    ani_object aniObject = AbilityRuntime::CreateStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_OK);
    ErrCode innerErrCode = ERR_OK;
    auto context = applicationContext_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::APPKIT, "nativeContextLong is nullptr");
        innerErrCode = AbilityRuntime::ERR_ABILITY_RUNTIME_EXTERNAL_CONTEXT_NOT_EXIST;
        aniObject = AbilityRuntime::CreateStsError(env, innerErrCode, "applicationContext is already released.");
        AppExecFwk::AsyncCallback(env, call, aniObject, nullptr);
        return;
    }
    AppExecFwk::AsyncCallback(env, call, aniObject, nullptr);
    context->KillProcessBySelf(clearPageStack);
}

void EtsApplicationContextUtils::PreloadUIExtensionAbility([[maybe_unused]]ani_env *env,
    [[maybe_unused]]ani_object aniObj, ani_object wantObj, ani_object call)
{
    TAG_LOGD(AAFwkTag::APPKIT, "PreloadUIExtensionAbility Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    AAFwk::Want want;
    if (!OHOS::AppExecFwk::UnwrapWant(env, wantObj, want)) {
        TAG_LOGE(AAFwkTag::APPKIT, "Parse want failed");
        AppExecFwk::AsyncCallback(env, call, AbilityRuntime::CreateStsInvalidParamError(env,
            "Parse param want failed, want must be Want."), nullptr);
        return;
    }
    auto context = applicationContext_.lock();
    if (!context) {
        AppExecFwk::AsyncCallback(env, call, AbilityRuntime::CreateStsErrorByNativeErr(env,
            (int32_t)AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT), nullptr);
        return;
    }
    auto hostBundleName = context->GetBundleName();
    TAG_LOGD(AAFwkTag::APPKIT, "HostBundleName is %{public}s", hostBundleName.c_str());
    auto innerErrCode = AAFwk::AbilityManagerClient::GetInstance()->PreloadUIExtensionAbility(want, hostBundleName);
    if (innerErrCode == ERR_OK) {
        AppExecFwk::AsyncCallback(env, call, AbilityRuntime::CreateStsError(env,
            AbilityRuntime::AbilityErrorCode::ERROR_OK), nullptr);
    } else {
        TAG_LOGE(AAFwkTag::APPKIT, "OnPreloadUIExtensionAbility failed %{public}d", innerErrCode);
        AppExecFwk::AsyncCallback(env, call, AbilityRuntime::CreateStsErrorByNativeErr(env, innerErrCode), nullptr);
    }
}

void EtsApplicationContextUtils::SetSupportedProcessCacheSync([[maybe_unused]]ani_env *env,
    [[maybe_unused]]ani_object aniObj, ani_boolean value)
{
    TAG_LOGD(AAFwkTag::APPKIT, "SetSupportedProcessCacheSync Call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null applicationContext");
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        return;
    }
    int32_t errCode = applicationContext->SetSupportedProcessCacheSelf(value);
    if (errCode == AAFwk::ERR_CAPABILITY_NOT_SUPPORT) {
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_CAPABILITY_NOT_SUPPORT);
    } else if (errCode != ERR_OK) {
        AbilityRuntime::ThrowStsError(env, AbilityRuntime::AbilityErrorCode::ERROR_CODE_INNER);
    }
}

void EtsApplicationContextUtils::SetApplicationContextToEts(const std::shared_ptr<ApplicationContext>
    &abilityRuntimeContext)
{
    TAG_LOGD(AAFwkTag::APPKIT, "SetApplicationContextToEts Call");
    if (abilityRuntimeContext == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null context");
        return;
    }
    applicationContext_ = abilityRuntimeContext;
}

void EtsApplicationContextUtils::BindApplicationContextFunc(ani_env* aniEnv, ani_class& contextClass)
{
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null aniEnv");
        return;
    }
    std::array applicationContextFunctions = {
        ani_native_function {"setSupportedProcessCacheSync", "Z:V",
            reinterpret_cast<void *>(EtsApplicationContextUtils::SetSupportedProcessCacheSync)},
        ani_native_function {"nativekillAllProcessesSync", "ZLutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsApplicationContextUtils::killAllProcesses)},
        ani_native_function {"nativepreloadUIExtensionAbilitySync",
            "L@ohos/app/ability/Want/Want;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsApplicationContextUtils::PreloadUIExtensionAbility)},
        ani_native_function {"nativeOnSync",
            "Lstd/core/String;L@ohos/app/ability/EnvironmentCallback/EnvironmentCallback;:D",
            reinterpret_cast<void *>(EtsApplicationContextUtils::NativeOnSync)},
        ani_native_function {"nativeOffSync",
            "Lstd/core/String;DLutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsApplicationContextUtils::NativeOffSync)},
        ani_native_function {"nativegetRunningProcessInformation",
            "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsApplicationContextUtils::GetRunningProcessInformation)},
        ani_native_function {"nativeclearUpApplicationData",
            "Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsApplicationContextUtils::ClearUpApplicationData)},
        ani_native_function {"nativesetColorMode",
            "L@ohos/app/ability/ConfigurationConstant/ConfigurationConstant/ColorMode;:V",
            reinterpret_cast<void *>(EtsApplicationContextUtils::SetColorMode)},
        ani_native_function {"nativesetFont", "Lstd/core/String;:V",
            reinterpret_cast<void *>(EtsApplicationContextUtils::SetFont)},
        ani_native_function {"nativerestartApp", "L@ohos/app/ability/Want/Want;:V",
            reinterpret_cast<void *>(EtsApplicationContextUtils::RestartApp)},
    };
    ani_status status = aniEnv->Class_BindNativeMethods(contextClass, applicationContextFunctions.data(),
    applicationContextFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_BindNativeMethods failed status: %{public}d", status);
    }
}

void EtsApplicationContextUtils::CreateEtsApplicationContext(ani_env* aniEnv, void* applicationContextObjRef)
{
    TAG_LOGD(AAFwkTag::APPKIT, "CreateEtsApplicationContext Call");
    auto applicationContext = applicationContext_.lock();
    if (applicationContext == nullptr || aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null applicationContext or aniEnv");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_class applicationContextCls = nullptr;
    if ((status = aniEnv->FindClass(STS_APPLICATION_CONTEXT_CLASS_NAME, &applicationContextCls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass ApplicationContext failed status: %{public}d", status);
        return;
    }
    BindApplicationContextFunc(aniEnv, applicationContextCls);
    ani_method contextCtorMethod = nullptr;
    if ((status = aniEnv->Class_FindMethod(applicationContextCls, "<ctor>", ":V", &contextCtorMethod)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod ctor failed status: %{public}d", status);
        return;
    }
    ani_object applicationContextObject = nullptr;
    if ((status = aniEnv->Object_New(applicationContextCls, contextCtorMethod, &applicationContextObject)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_New failed status: %{public}d", status);
        return;
    }
    ani_field contextField;
    if ((status = aniEnv->Class_FindField(applicationContextCls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindField failed status: %{public}d", status);
        return;
    }
    if ((status = aniEnv->Object_SetField_Long(applicationContextObject, contextField,
        (ani_long)applicationContext.get())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Long failed status: %{public}d", status);
        return;
    }
    ani_ref applicationContextObjectRef = nullptr;
    if ((status = aniEnv->GlobalReference_Create(applicationContextObject, &applicationContextObjectRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Create failed status: %{public}d", status);
        return;
    }
    auto stsReference = std::make_shared<AbilityRuntime::STSNativeReference>();
    stsReference->aniObj = applicationContextObject;
    AbilityRuntime::ApplicationContextManager::GetApplicationContextManager().AddStsGlobalObject(aniEnv, stsReference);
    applicationContextObjRef = reinterpret_cast<void*>(applicationContextObjectRef);
    applicationContext->SetApplicationCtxObjRef(applicationContextObjectRef);
}
} // namespace AbilityRuntime
} // namespace OHOS