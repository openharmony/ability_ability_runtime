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
#include "common_fun_ani.h"
#include "ani_common_want.h"
#include "ability_manager_client.h"
#include "sts_context_utils.h"
#include "sts_error_utils.h"
#include "sts_service_extension_context.h"
#include "ani_common_start_options.h"

namespace {
constexpr const char* SERVICE_EXTENSION_CONTEXT_CLASS_NAME =
    "Lapplication/ServiceExtensionContext/ServiceExtensionContext;";
}

const char *INVOKE_METHOD_NAME = "invoke";
static void TerminateSelfSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object obj,
    [[maybe_unused]] ani_object callback)
{
    TAG_LOGE(AAFwkTag::SERVICE_EXT, "terminateSelfSync call");
    ani_object aniObject = nullptr;
    OHOS::ErrCode ret = OHOS::ERR_INVALID_VALUE;
    auto context = StsServiceExtensionContext::GetAbilityContext(env, obj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "GetAbilityContext is nullptr");
        ret = static_cast<int32_t>(OHOS::AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        aniObject = CreateStsError(env, static_cast<OHOS::AbilityRuntime::AbilityErrorCode>(ret));
        OHOS::AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    ret = context->TerminateAbility();
    OHOS::AppExecFwk::AsyncCallback(env, callback,
        OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret)), nullptr);
}

static void StartServiceExtensionAbilitySync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
    [[maybe_unused]] ani_object wantObj, [[maybe_unused]] ani_object callbackobj)
{
    TAG_LOGE(AAFwkTag::SERVICE_EXT, "call");
    ani_object aniObject = nullptr;
    OHOS::ErrCode ret = OHOS::ERR_OK;
    auto context = StsServiceExtensionContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "GetAbilityContext is nullptr");
        ret = static_cast<int32_t>(OHOS::AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        aniObject = CreateStsError(env, static_cast< OHOS::AbilityRuntime::AbilityErrorCode>(ret));
        OHOS::AppExecFwk::AsyncCallback(env, callbackobj, aniObject, nullptr);
        return;
    }
    OHOS::AAFwk::Want want;
    if (!OHOS::AppExecFwk::UnwrapWant(env, wantObj, want)) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "UnwrapWant filed");
        aniObject =  OHOS::AbilityRuntime::CreateStsInvalidParamError(env, "UnwrapWant filed");
        OHOS::AppExecFwk::AsyncCallback(env, callbackobj, aniObject, nullptr);
        return;
    }
    ret = context->StartServiceExtensionAbility(want);
    if (ret == OHOS::ERR_OK) {
        aniObject = CreateStsError(env, static_cast< OHOS::AbilityRuntime::AbilityErrorCode>(ret));
    } else {
        aniObject = OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret));
    }
    OHOS::AppExecFwk::AsyncCallback(env, callbackobj, aniObject, nullptr);
}

static void StartAbility([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
    ani_object wantObj, ani_object call)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "StartAbility called");
    StsServiceExtensionContext::GetInstance().StartAbilityInner(env, aniObj, wantObj, nullptr, call);
}

static void StartAbilityWithOption([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
    ani_object wantObj, ani_object opt, ani_object call)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "StartAbilityWithOption called");
    StsServiceExtensionContext::GetInstance().StartAbilityInner(env, aniObj, wantObj, opt, call);
}

OHOS::AbilityRuntime::ServiceExtensionContext* StsServiceExtensionContext::GetAbilityContext(ani_env *env,
    ani_object obj)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "GetAbilityContext start");
    ani_class cls = nullptr;
    ani_long nativeContextLong;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(SERVICE_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "terminateSelfSync find class status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeServiceExtensionContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "terminateSelfSync find field status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_GetField_Long(obj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "terminateSelfSync get filed status : %{public}d", status);
        return nullptr;
    }
    return (OHOS::AbilityRuntime::ServiceExtensionContext*)nativeContextLong;
}

void StsServiceExtensionContext::AddFreeInstallObserver(ani_env *env, const OHOS::AAFwk::Want &want,
    ani_object callback, OHOS::AbilityRuntime::ServiceExtensionContext* context)
{
    // adapter free install async return install and start result
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
    int ret = 0;
    if (!context) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null context");
        return;
    }
    if (!env) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return;
    }
    if (freeInstallObserver_ == nullptr) {
        ani_vm *etsVm = nullptr;
        ani_status status = ANI_ERROR;
        if ((status = env->GetVM(&etsVm)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "status : %{public}d", status);
        }
        freeInstallObserver_ = new OHOS::AbilityRuntime::StsFreeInstallObserver(etsVm);
        ret = context->AddFreeInstallObserver(freeInstallObserver_);
    }
    if (ret != OHOS::ERR_OK) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "addFreeInstallObserver error");
    }
    std::string startTime = want.GetStringParam(OHOS::AAFwk::Want::PARAM_RESV_START_TIME);
    TAG_LOGI(AAFwkTag::SERVICE_EXT, "addStsObserver");
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    freeInstallObserver_->AddStsObserverObject(
        env, bundleName, abilityName, startTime, callback);
}

void StsServiceExtensionContext::StartAbilityInner([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
    ani_object wantObj, ani_object opt, ani_object call)
{
    ani_object aniObject = nullptr;
    OHOS::AAFwk::Want want;
    OHOS::ErrCode innerErrCode = OHOS::ERR_OK;
    if (!OHOS::AppExecFwk::UnwrapWant(env, wantObj, want)) {
        aniObject = OHOS::AbilityRuntime::CreateStsInvalidParamError(env, "UnwrapWant filed");
        OHOS::AppExecFwk::AsyncCallback(env, call, aniObject, nullptr);
        return;
    }
    auto context = StsServiceExtensionContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "GetAbilityContext is nullptr");
        innerErrCode = static_cast<int32_t>(OHOS::AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        aniObject = CreateStsError(env, static_cast<OHOS::AbilityRuntime::AbilityErrorCode>(innerErrCode));
        OHOS::AppExecFwk::AsyncCallback(env, call, aniObject, nullptr);
        return;
    }
    if ((want.GetFlags() & OHOS::AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == OHOS::AAFwk::Want::FLAG_INSTALL_ON_DEMAND) {
        std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
            system_clock::now().time_since_epoch()).count());
        want.SetParam(OHOS::AAFwk::Want::PARAM_RESV_START_TIME, startTime);
        AddFreeInstallObserver(env, want, call, context);
    }
    if (opt != nullptr) {
        OHOS::AAFwk::StartOptions startOptions;
        if (!OHOS::AppExecFwk::UnwrapStartOptionsWithProcessOption(env, opt, startOptions)) {
            TAG_LOGE(AAFwkTag::SERVICE_EXT, "UnwrapStartOptions filed");
            aniObject = OHOS::AbilityRuntime::CreateStsInvalidParamError(env, "UnwrapWant filed");
            OHOS::AppExecFwk::AsyncCallback(env, call, aniObject, nullptr);
            return;
        }
        innerErrCode = context->StartAbility(want, startOptions);
    } else {
        innerErrCode = context->StartAbility(want);
    }
    aniObject = CreateStsError(env, OHOS::AbilityRuntime::AbilityErrorCode::ERROR_OK);
    if (innerErrCode != OHOS::ERR_OK) {
        aniObject = OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, innerErrCode);
    }
    if ((want.GetFlags() & OHOS::AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == OHOS::AAFwk::Want::FLAG_INSTALL_ON_DEMAND) {
        if (innerErrCode != OHOS::ERR_OK && freeInstallObserver_ != nullptr) {
            std::string bundleName = want.GetElement().GetBundleName();
            std::string abilityName = want.GetElement().GetAbilityName();
            std::string startTime = want.GetStringParam(OHOS::AAFwk::Want::PARAM_RESV_START_TIME);
            freeInstallObserver_->OnInstallFinished(bundleName, abilityName, startTime, innerErrCode);
        }
    } else {
        OHOS::AppExecFwk::AsyncCallback(env, call, aniObject, nullptr);
    }
}

void BindExtensionInfo(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    std::shared_ptr<OHOS::AbilityRuntime::Context> context, std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo)
{
    TAG_LOGI(AAFwkTag::APPKIT, "BindExtensionInfo");
    if (aniEnv == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return;
    }
    auto hapModuleInfo = context->GetHapModuleInfo();
    ani_status status = ANI_OK;
    if (abilityInfo && hapModuleInfo) {
        auto isExist = [&abilityInfo](const OHOS::AppExecFwk::ExtensionAbilityInfo& info) {
            TAG_LOGD(AAFwkTag::CONTEXT, "%{public}s, %{public}s", info.bundleName.c_str(), info.name.c_str());
            return info.bundleName == abilityInfo->bundleName && info.name == abilityInfo->name;
        };
        auto infoIter = std::find_if(
            hapModuleInfo->extensionInfos.begin(), hapModuleInfo->extensionInfos.end(), isExist);
        if (infoIter == hapModuleInfo->extensionInfos.end()) {
            TAG_LOGE(AAFwkTag::CONTEXT, "set extensionAbilityInfo fail");
            return;
        }
        ani_field extensionAbilityInfoField;
        status = aniEnv->Class_FindField(contextClass, "extensionAbilityInfo", &extensionAbilityInfoField);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "find extensionAbilityInfo failed status: %{public}d", status);
            return;
        }
        ani_object extAbilityInfoObj = OHOS::AppExecFwk::CommonFunAni::ConvertExtensionInfo(aniEnv, *infoIter);
        status = aniEnv->Object_SetField_Ref(contextObj, extensionAbilityInfoField,
            reinterpret_cast<ani_ref>(extAbilityInfoObj));
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "Object_SetField_Ref failed status: %{public}d", status);
            return;
        }
    }
}

void StsCreatExtensionContext(ani_env* aniEnv, ani_class contextClass, ani_object contextObj,
    void* applicationCtxRef, std::shared_ptr<OHOS::AbilityRuntime::ExtensionContext> context)
{
    OHOS::AbilityRuntime::ContextUtil::StsCreatContext(aniEnv, contextClass, contextObj, applicationCtxRef, context);
    BindExtensionInfo(aniEnv, contextClass, contextObj, context, context->GetAbilityInfo());
}

ani_object CreateStsServiceExtensionContext(ani_env *env,
    std::shared_ptr<OHOS::AbilityRuntime::ServiceExtensionContext> context,
    const std::shared_ptr<OHOS::AppExecFwk::OHOSApplication> &application)
{
    TAG_LOGD(AAFwkTag::SERVICE_EXT, "called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::SERVICE_EXT, "null env");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_field field = nullptr;
    ani_object contextObj = nullptr;
    if ((env->FindClass(SERVICE_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "find class status : %{public}d", status);
        return nullptr;
    }
    std::array functions = {
        ani_native_function { "nativeTerminateSelfSync", nullptr, reinterpret_cast<ani_int*>(TerminateSelfSync) },
        ani_native_function { "nativeStartAbilitySync",
            "L@ohos/app/ability/Want/Want;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(StartAbility) },
        ani_native_function { "nativeStartAbilitySync",
            "L@ohos/app/ability/Want/Want;L@ohos/app/ability/StartOptions/StartOptions;Lutils/AbilityUtils/"
            "AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(StartAbilityWithOption) },
        ani_native_function { "nativeStartServiceExtensionAbilitySync", nullptr,
            reinterpret_cast<ani_int*>(StartServiceExtensionAbilitySync) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "bind method status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "find method status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "new object status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeServiceExtensionContext", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "find field status : %{public}d", status);
        return nullptr;
    }
    ani_long nativeContextLong = (ani_long)context.get();
    if ((status = env->Object_SetField_Long(contextObj, field, nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "set filed status : %{public}d", status);
        return nullptr;
    }
    if (application == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "application is null");
        return nullptr;
    }
    StsCreatExtensionContext(env, cls, contextObj, application->GetApplicationCtxObjRef(), context);
    return contextObj;
}
