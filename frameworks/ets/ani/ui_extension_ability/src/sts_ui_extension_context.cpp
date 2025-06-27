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

#include "ability_manager_client.h"
#include "ani_common_start_options.h"
#include "ani_common_want.h"
#include "ani_remote_object.h"
#include "common_fun_ani.h"
#include "ets_extension_context.h"
#include "sts_context_utils.h"
#include "sts_error_utils.h"
#include "ets_extension_context.h"
#include "ani_common_start_options.h"
#include "ani_common_ability_result.h"
#include "ani_common_util.h"
#include "ani_enum_convert.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
static std::mutex g_connectsMutex;
int32_t g_serialNumber = 0;
static std::map<EtsUIExtensionConnectionKey, sptr<EtsUIExtensionConnection>, Etskey_compare> g_connects;

constexpr const int FAILED_CODE = -1;
constexpr const char *UI_CONTEXT_CLASS_NAME = "Lapplication/UIExtensionContext/UIExtensionContext;";
constexpr const char *CONNECT_OPTIONS_CLASS_NAME = "Lability/connectOptions/ConnectOptionsInner;";
constexpr const char *SIGNATURE_ONCONNECT = "LbundleManager/ElementName/ElementName;L@ohos/rpc/rpc/IRemoteObject;:V";
constexpr const char *SIGNATURE_ONDISCONNECT = "LbundleManager/ElementName/ElementName;:V";
constexpr const char *SIGNATURE_CONNECT_SERVICE_EXTENSION =
    "L@ohos/app/ability/Want/Want;Lability/connectOptions/ConnectOptions;:D";
constexpr const char *SIGNATURE_DISCONNECT_SERVICE_EXTENSION = "DLutils/AbilityUtils/AsyncCallbackWrapper;:V";
}

static void TerminateSelfSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object obj,
    [[maybe_unused]] ani_object callback)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "TerminateSelfSync");
    ani_class cls = nullptr;
    ani_long nativeContextLong;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    ErrCode ret = ERR_INVALID_VALUE;
    if ((status = env->FindClass(UI_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return;
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return;
    }
    if ((status = env->Object_GetField_Long(obj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return;
    }
    ret = ((UIExtensionContext*)nativeContextLong)->TerminateSelf();
    AppExecFwk::AsyncCallback(env, callback,
        CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret)), nullptr);
}
static void TerminateSelfWithResultSync([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object obj,
    [[maybe_unused]] ani_object abilityResult, [[maybe_unused]] ani_object callback)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "TerminateSelfWithResultSync");
    ani_class cls = nullptr;
    ani_long nativeContextLong;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    ErrCode ret = ERR_INVALID_VALUE;
    if ((status = env->FindClass(UI_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return;
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return;
    }
    if ((status = env->Object_GetField_Long(obj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return;
    }
    auto context = ((UIExtensionContext*)nativeContextLong);
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "context is released");
        return;
    }

    AAFwk::Want want;
    int resultCode = 0;
    AppExecFwk::UnWrapAbilityResult(env, abilityResult, resultCode, want);
    auto token = context->GetToken();
    AAFwk::AbilityManagerClient::GetInstance()->TransferAbilityResultForExtension(token, resultCode, want);
    ret = context->TerminateSelf();
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::UI_EXT, "TerminateSelf failed, errorCode is %{public}d", ret);
        return;
    }
    AppExecFwk::AsyncCallback(env, callback,
        CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret)), nullptr);
}

static void StartAbility([[maybe_unused]] ani_env *env,
    [[maybe_unused]] ani_object aniObj, ani_object wantObj, ani_object call)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "StartAbility");
    StsUIExtensionContext::GetInstance().StartAbilityInner(env, aniObj, wantObj, nullptr, call);
}

static void StartAbilityWithOption([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
    ani_object wantObj, ani_object opt, ani_object call)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "StartAbilityWithOption");
    StsUIExtensionContext::GetInstance().StartAbilityInner(env, aniObj, wantObj, opt, call);
}

static void StartAbilityForResult(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "StartAbilityForResult called");
    StsUIExtensionContext::GetInstance().StartAbilityForResultInner(env, aniObj, wantObj, nullptr, callback);
}

static void StartAbilityForResultWithOptions(ani_env *env, ani_object aniObj, ani_object wantObj,
    ani_object startOptionsObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "StartAbilityForResultWithOptions called");
    StsUIExtensionContext::GetInstance().StartAbilityForResultInner(env, aniObj, wantObj, startOptionsObj, callback);
}

ani_double StsUIExtensionContext::OnConnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
    ani_object wantObj, ani_object connectOptionsObj)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "OnConnectServiceExtensionAbility");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return FAILED_CODE;
    }
    ani_status status = ANI_ERROR;
    auto context = StsUIExtensionContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        ThrowStsError(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
        return FAILED_CODE;
    }
    AAFwk::Want want;
    if (!OHOS::AppExecFwk::UnwrapWant(env, wantObj, want)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to UnwrapWant");
        ThrowStsInvalidParamError(env, "Failed to UnwrapWant");
        return FAILED_CODE;
    }
    ani_vm *etsVm = nullptr;
    if ((status = env->GetVM(&etsVm)) != ANI_OK || etsVm == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to getVM, status: %{public}d", status);
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return FAILED_CODE;
    }
    sptr<EtsUIExtensionConnection> connection = new (std::nothrow) EtsUIExtensionConnection(etsVm);
    if (connection == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null connection");
        ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return FAILED_CODE;
    }
    if (!CheckConnectionParam(env, connectOptionsObj, connection, want)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to CheckConnectionParam");
        ThrowStsInvalidParamError(env, "Failed to CheckConnectionParam");
        return FAILED_CODE;
    }
    auto innerErrCode = context->ConnectAbility(want, connection);
    double connectId = connection->GetConnectionId();
    if (innerErrCode != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Faied to ConnectAbility, innerErrCode is %{public}d", innerErrCode);
        connection->CallEtsFailed(connectId);
        return FAILED_CODE;
    }
    return connectId;
}

void StsUIExtensionContext::OnDisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
    ani_int connectId, ani_object callback)
{
    TAG_LOGE(AAFwkTag::UI_EXT, "OnDisconnectServiceExtensionAbility");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    ani_object aniObject = nullptr;
    auto context = StsUIExtensionContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        aniObject = CreateStsErrorByNativeErr(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
        AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    AAFwk::Want want;
    sptr<EtsUIExtensionConnection> connection = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_connectsMutex);
        auto item = std::find_if(
            g_connects.begin(), g_connects.end(), [&connectId](const auto &obj) { return connectId == obj.first.id; });
        if (item != g_connects.end()) {
            want = item->first.want;
            connection = item->second;
            g_connects.erase(item);
        } else {
            TAG_LOGI(AAFwkTag::UI_EXT, "Failed to found connection");
            return;
        }
    }
    if (!connection) {
        aniObject = CreateStsErrorByNativeErr(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER));
        AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
        TAG_LOGE(AAFwkTag::UI_EXT, "null connection");
        return;
    }
    ErrCode ret = context->DisconnectAbility(want, connection);
    aniObject = CreateStsErrorByNativeErr(env, static_cast<int32_t>(ret));
    AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
}

UIExtensionContext* StsUIExtensionContext::GetAbilityContext(ani_env *env, ani_object obj)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "GetAbilityContext start");
    ani_class cls = nullptr;
    ani_long nativeContextLong;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(UI_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetAbilityContext find class status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetAbilityContext find field status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_GetField_Long(obj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetAbilityContext get filed status: %{public}d", status);
        return nullptr;
    }
    return (UIExtensionContext*)nativeContextLong;
}

void StsUIExtensionContext::AddFreeInstallObserver(ani_env *env, const AAFwk::Want &want,
    ani_object callback, UIExtensionContext*context)
{
    // adapter free install async return install and start result
    TAG_LOGD(AAFwkTag::UI_EXT, "AddFreeInstallObserver");
    int ret = 0;
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return;
    }
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    if (freeInstallObserver_ == nullptr) {
        ani_vm *etsVm = nullptr;
        ani_status status = ANI_ERROR;
        if ((status = env->GetVM(&etsVm)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        }
        freeInstallObserver_ = new StsFreeInstallObserver(etsVm);
        ret = context->AddFreeInstallObserver(freeInstallObserver_);
    }
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "addFreeInstallObserver error");
    }
    std::string startTime = want.GetStringParam(AAFwk::Want::PARAM_RESV_START_TIME);
    TAG_LOGI(AAFwkTag::UI_EXT, "addStsObserver");
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    freeInstallObserver_->AddStsObserverObject(
        env, bundleName, abilityName, startTime, callback);
}

void StsUIExtensionContext::StartAbilityInner([[maybe_unused]] ani_env *env, [[maybe_unused]] ani_object aniObj,
    ani_object wantObj, ani_object opt, ani_object call)
{
    ani_object aniObject = nullptr;
    AAFwk::Want want;
    ErrCode innerErrCode = ERR_OK;
    if (!AppExecFwk::UnwrapWant(env, wantObj, want)) {
        aniObject = CreateStsInvalidParamError(env, "UnwrapWant filed");
        AppExecFwk::AsyncCallback(env, call, aniObject, nullptr);
        return;
    }
    auto context = StsUIExtensionContext::GetAbilityContext(env, aniObj);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetAbilityContext is nullptr");
        innerErrCode = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        aniObject = CreateStsError(env, static_cast<AbilityErrorCode>(innerErrCode));
        AppExecFwk::AsyncCallback(env, call, aniObject, nullptr);
        return;
    }
    if ((want.GetFlags() & AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == AAFwk::Want::FLAG_INSTALL_ON_DEMAND) {
        std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
            system_clock::now().time_since_epoch()).count());
        want.SetParam(AAFwk::Want::PARAM_RESV_START_TIME, startTime);
        AddFreeInstallObserver(env, want, call, context);
    }
    if (opt != nullptr) {
        AAFwk::StartOptions startOptions;
        if (!AppExecFwk::UnwrapStartOptionsWithProcessOption(env, opt, startOptions)) {
            TAG_LOGE(AAFwkTag::UI_EXT, "UnwrapStartOptions filed");
            aniObject = CreateStsInvalidParamError(env, "UnwrapWant filed");
            AppExecFwk::AsyncCallback(env, call, aniObject, nullptr);
            return;
        }
        innerErrCode = context->StartAbility(want, startOptions);
    } else {
        innerErrCode = context->StartAbility(want);
    }
    aniObject = CreateStsError(env, AbilityErrorCode::ERROR_OK);
    if (innerErrCode != ERR_OK) {
        aniObject = CreateStsErrorByNativeErr(env, innerErrCode);
    }
    if ((want.GetFlags() & AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == AAFwk::Want::FLAG_INSTALL_ON_DEMAND) {
        if (innerErrCode != ERR_OK && freeInstallObserver_ != nullptr) {
            std::string bundleName = want.GetElement().GetBundleName();
            std::string abilityName = want.GetElement().GetAbilityName();
            std::string startTime = want.GetStringParam(AAFwk::Want::PARAM_RESV_START_TIME);
            freeInstallObserver_->OnInstallFinished(bundleName, abilityName, startTime, innerErrCode);
        }
    } else {
        AppExecFwk::AsyncCallback(env, call, aniObject, nullptr);
    }
}

void StsUIExtensionContext::StartAbilityForResultInner(ani_env *env, ani_object aniObj, ani_object wantObj,
    ani_object startOptionsObj, ani_object callback)
{
    auto context = StsUIExtensionContext::GetAbilityContext(env, aniObj);
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "env is nullptr or GetAbilityContext is nullptr");
        ThrowStsErrorByNativeErr(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
        return;
    }

    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(env, wantObj, want);
    AAFwk::StartOptions startOptions;
    if (startOptionsObj) {
        OHOS::AppExecFwk::UnwrapStartOptions(env, startOptionsObj, startOptions);
    }
    
    ani_ref callbackRef = nullptr;
    env->GlobalReference_Create(callback, &callbackRef);
    ani_vm *etsVm = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GetVM(&etsVm)) != ANI_OK || etsVm == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetVM failed, status: %{public}d", status);
        return;
    }
    RuntimeTask task = [etsVm, callbackRef]
        (int resultCode, const AAFwk::Want &want, bool isInner) {
        TAG_LOGD(AAFwkTag::UI_EXT, "start async callback");
        ani_status status = ANI_ERROR;
        ani_env *env = nullptr;
        if ((status = etsVm->GetEnv(ANI_VERSION_1, &env)) != ANI_OK || env == nullptr) {
            TAG_LOGE(AAFwkTag::UI_EXT, "GetEnv failed, status: %{public}d", status);
            return;
        }
        
        ani_object abilityResult = AppExecFwk::WrapAbilityResult(env, resultCode, want);
        if (abilityResult == nullptr) {
            TAG_LOGW(AAFwkTag::UI_EXT, "null abilityResult");
            AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
                CreateStsError(env, AbilityErrorCode::ERROR_CODE_INNER), nullptr);
            env->GlobalReference_Delete(callbackRef);
            return;
        }
        auto errCode = isInner ? resultCode : 0;
        AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
            OHOS::AbilityRuntime::CreateStsErrorByNativeErr(env, errCode), abilityResult);
        env->GlobalReference_Delete(callbackRef);
    };
    want.SetParam(AAFwk::Want::PARAM_RESV_FOR_RESULT, true);
    auto requestCode = context->GenerateCurRequestCode();
    (startOptionsObj == nullptr) ? context->StartAbilityForResult(want, requestCode, std::move(task))
                                 : context->StartAbilityForResult(want, startOptions, requestCode, std::move(task));
    return;
}

void StsUIExtensionContext::NativeSetColorMode(ani_env *env, ani_object aniContext, ani_enum_item aniColorMode)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "NativeSetColorMode called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    ani_int colorMode = 0;
    if (!AAFwk::AniEnumConvertUtil::EnumConvertStsToNative(env, aniColorMode, colorMode)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "param aniColorMode err");
        ThrowStsInvalidParamError(env, "Parse param colorMode failed, colorMode must be number.");
        return;
    }
    auto context = StsUIExtensionContext::GetAbilityContext(env, aniContext);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetAbilityContext is nullptr");
        ThrowStsError(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
        return;
    }
    context->SetAbilityColorMode(colorMode);
    TAG_LOGD(AAFwkTag::UI_EXT, "NativeSetColorMode end");
}

void StsUIExtensionContext::NativeReportDrawnCompleted(ani_env* env, ani_object aniCls, ani_object callback)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "NativeReportDrawnCompleted called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    auto context = StsUIExtensionContext::GetAbilityContext(env, aniCls);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetAbilityContext is nullptr");
        AppExecFwk::AsyncCallback(env, callback,
            CreateStsErrorByNativeErr(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT)),
            nullptr);
        return;
    }
    int32_t innerErrorCode = context->ReportDrawnCompleted();
    AppExecFwk::AsyncCallback(env, callback, CreateStsErrorByNativeErr(env,
        static_cast<int32_t>(innerErrorCode)), nullptr);
    TAG_LOGD(AAFwkTag::UI_EXT, "NativeReportDrawnCompleted end");
}

bool StsUIExtensionContext::CheckConnectionParam(ani_env *env, ani_object connectOptionsObj,
    sptr<EtsUIExtensionConnection> &connection, AAFwk::Want &want)
{
    ani_type type = nullptr;
    ani_boolean res = ANI_FALSE;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetType(connectOptionsObj, &type)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to Object_GetType, status: %{public}d", status);
        return false;
    }
    if (type == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null type");
        return false;
    }
    if ((status = env->Object_InstanceOf(connectOptionsObj, type, &res)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to Object_InstanceOf, status: %{public}d", status);
        return false;
    }
    if (res != ANI_TRUE) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to CheckConnectionParam");
        return false;
    }
    connection->SetConnectionRef(connectOptionsObj);
    EtsUIExtensionConnectionKey key;
    {
        std::lock_guard guard(g_connectsMutex);
        key.id = g_serialNumber;
        key.want = want;
        connection->SetConnectionId(key.id);
        g_connects.emplace(key, connection);
        if (g_serialNumber < INT32_MAX) {
            g_serialNumber++;
        } else {
            g_serialNumber = 0;
        }
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "Failed to find connection, make new one");
    return true;
}

bool BindNativeMethods(ani_env *env, ani_class &cls)
{
    ani_status status = ANI_ERROR;
    std::array functions = {
        ani_native_function { "terminateSelfSync", nullptr, reinterpret_cast<ani_int*>(TerminateSelfSync) },
        ani_native_function { "terminateSelfWithResultSync", nullptr,
            reinterpret_cast<ani_int*>(TerminateSelfWithResultSync) },
        ani_native_function { "nativeStartAbilitySync",
            "L@ohos/app/ability/Want/Want;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(StartAbility) },
        ani_native_function { "nativeStartAbilitySync",
            "L@ohos/app/ability/Want/Want;L@ohos/app/ability/StartOptions/StartOptions;Lutils/AbilityUtils/"
            "AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(StartAbilityWithOption) },
        ani_native_function { "nativeStartAbilityForResult",
            "L@ohos/app/ability/Want/Want;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(StartAbilityForResult) },
        ani_native_function { "nativeStartAbilityForResult",
            "L@ohos/app/ability/Want/Want;L@ohos/app/ability/StartOptions/StartOptions;Lutils/AbilityUtils/"
            "AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(StartAbilityForResultWithOptions) },
        ani_native_function { "setColorMode", nullptr,
            reinterpret_cast<void*>(StsUIExtensionContext::NativeSetColorMode)},
        ani_native_function { "nativeReportDrawnCompleted", nullptr,
            reinterpret_cast<void*>(StsUIExtensionContext::NativeReportDrawnCompleted)},
        ani_native_function { "nativeConnectServiceExtensionAbility", SIGNATURE_CONNECT_SERVICE_EXTENSION,
            reinterpret_cast<void *>(StsUIExtensionContext::OnConnectServiceExtensionAbility) },
        ani_native_function { "nativeDisconnectServiceExtensionAbilitySync", SIGNATURE_DISCONNECT_SERVICE_EXTENSION,
            reinterpret_cast<void *>(StsUIExtensionContext::OnDisconnectServiceExtensionAbility) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to bindNativeMethods status: %{public}d", status);
        return false;
    }
    return true;
}

ani_object CreateStsUIExtensionContext(ani_env *env, std::shared_ptr<UIExtensionContext> context)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "CreateStsUIExtensionContext");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_field field = nullptr;
    ani_object contextObj = nullptr;
    if ((env->FindClass(UI_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    if (!BindNativeMethods(env, cls)) {
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &contextObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeContext", &field)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    ani_long nativeContextLong = (ani_long)context.get();
    if ((status = env->Object_SetField_Long(contextObj, field, nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    OHOS::AbilityRuntime::ContextUtil::StsCreateContext(env, cls, contextObj, context);
    OHOS::AbilityRuntime::CreatEtsExtensionContext(env, cls, contextObj, context, context->GetAbilityInfo());
    return contextObj;
}

EtsUIExtensionConnection::EtsUIExtensionConnection(ani_vm *etsVm) : etsVm_(etsVm) {}

EtsUIExtensionConnection::~EtsUIExtensionConnection()
{
    if (etsVm_ != nullptr && stsConnectionRef_ != nullptr) {
        ani_env* env = nullptr;
        if (etsVm_->GetEnv(ANI_VERSION_1, &env) == ANI_OK) {
            env->GlobalReference_Delete(stsConnectionRef_);
            stsConnectionRef_ = nullptr;
        }
    }
}

void EtsUIExtensionConnection::SetConnectionId(int32_t id)
{
    connectionId_ = id;
}

void EtsUIExtensionConnection::CallEtsFailed(int32_t errorCode)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "CallEtsFailed");
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "etsVm_ is nullptr");
        return;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_OK;
    if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return;
    }
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    if (stsConnectionRef_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null stsConnectionRef_");
        return;
    }
    ani_class cls = nullptr;
    if ((status = env->FindClass(CONNECT_OPTIONS_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to find connectOptions calss, status: %{public}d", status);
        return;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null class");
        return;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "onFailed", "D:V", &method))) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to find onFailed method, status: %{public}d", status);
        return;
    }
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null method");
        return;
    }
    status = env->Object_CallMethod_Void(
        reinterpret_cast<ani_object>(stsConnectionRef_), method, static_cast<double>(errorCode));
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Object_CallMethod_Void status: %{public}d", status);
    }
}

void EtsUIExtensionConnection::SetConnectionRef(ani_object connectOptionsObj)
{
    TAG_LOGI(AAFwkTag::UI_EXT, "called");
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null etsVm");
        return;
    }

    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Faied to getEnv, status: %{public}d", status);
        return;
    }
    if ((status = env->GlobalReference_Create(connectOptionsObj, &stsConnectionRef_)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Faied to createReference, status: %{public}d", status);
    }
}

void EtsUIExtensionConnection::OnAbilityConnectDone(const AppExecFwk::ElementName &element,
    const sptr<IRemoteObject> &remoteObject, int resultCode)
{
    if (etsVm_ == nullptr || stsConnectionRef_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null stsConnectionRef or etsVm");
        return;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    ani_option interopEnabled { "--interop=disable", nullptr };
    ani_options aniArgs { 1, &interopEnabled };
    if ((status = (etsVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return;
    }
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    ani_class cls = nullptr;
    if ((status = env->FindClass(CONNECT_OPTIONS_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to find connectOptions calss, status: %{public}d", status);
        return;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null cls");
        return;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "onConnect", SIGNATURE_ONCONNECT, &method))) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to find onConnect method, status: %{public}d", status);
        return;
    }
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null method");
        return;
    }
    ani_ref refElement = AppExecFwk::WrapElementName(env, element);
    if (refElement == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null refElement");
        return;
    }
    ani_object refRemoteObject = ANI_ohos_rpc_CreateJsRemoteObject(env, remoteObject);
    status = env->Object_CallMethod_Void(
        reinterpret_cast<ani_object>(stsConnectionRef_), method, refElement, refRemoteObject);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Object_CallMethod_Void status: %{public}d", status);
    }
    if ((status = etsVm_->DetachCurrentThread()) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
    }
}

void EtsUIExtensionConnection::OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int resultCode)
{
    if (etsVm_ == nullptr || stsConnectionRef_ == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null stsConnectionRef or etsVm");
        return;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    ani_option interopEnabled { "--interop=disable", nullptr };
    ani_options aniArgs { 1, &interopEnabled };
    if ((status = (etsVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return;
    }
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    ani_class cls = nullptr;
    if ((status = env->FindClass(CONNECT_OPTIONS_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to find connectOptions calss, status: %{public}d", status);
        return;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null cls");
        return;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "onDisconnect", SIGNATURE_ONDISCONNECT, &method))) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to find onDisconnect method, status: %{public}d", status);
        return;
    }
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null method");
        return;
    }
    ani_ref refElement = AppExecFwk::WrapElementName(env, element);
    if (refElement == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null refElement");
        return;
    }
    status = env->Object_CallMethod_Void(reinterpret_cast<ani_object>(stsConnectionRef_), method, refElement);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Object_CallMethod_Void status: %{public}d", status);
    }
    if ((status = etsVm_->DetachCurrentThread()) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
    }
}

} // AbilityRuntime
} // OHOS
