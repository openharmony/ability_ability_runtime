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
#include "ets_ui_extension_context.h"

#include "ability_manager_client.h"
#include "ani_common_ability_result.h"
#include "ani_common_start_options.h"
#include "ani_common_want.h"
#include "ani_remote_object.h"
#include "common_fun_ani.h"
#include "ets_context_utils.h"
#include "ets_error_utils.h"
#include "ets_extension_context.h"
#include "ui_extension_context.h"


namespace OHOS {
namespace AbilityRuntime {
static std::mutex g_connectsMutex;
int32_t g_serialNumber = 0;
static std::map<EtsUIExtensionConnectionKey, sptr<EtsUIExtensionConnection>, Etskey_compare> g_connects;
const char *UI_EXTENSION_CONTEXT_CLASS_NAME = "Lapplication/UIExtensionContext/UIExtensionContext;";
const char *UI_EXTENSION_CONTEXT_CLEANER_CLASS_NAME = "Lapplication/UIExtensionContext/Cleaner;";
constexpr const int FAILED_CODE = -1;
constexpr const char *CONNECT_OPTIONS_CLASS_NAME = "Lability/connectOptions/ConnectOptionsInner;";
constexpr const char *SIGNATURE_ONCONNECT = "LbundleManager/ElementName/ElementName;L@ohos/rpc/rpc/IRemoteObject;:V";
constexpr const char *SIGNATURE_ONDISCONNECT = "LbundleManager/ElementName/ElementName;:V";
constexpr const char *SIGNATURE_CONNECT_SERVICE_EXTENSION =
    "L@ohos/app/ability/Want/Want;Lability/connectOptions/ConnectOptions;:J";
constexpr const char *SIGNATURE_DISCONNECT_SERVICE_EXTENSION = "JLutils/AbilityUtils/AsyncCallbackWrapper;:V";

void EtsUIExtensionContext::TerminateSelfSync(ani_env *env, ani_object obj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "TerminateSelfSync called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    auto etsUiExtensionContext = GetEtsUIExtensionContext(env, obj);
    if (etsUiExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null etsUiExtensionContext");
        return;
    }
    etsUiExtensionContext->OnTerminateSelf(env, obj, callback);
}

void EtsUIExtensionContext::TerminateSelfWithResultSync(ani_env *env,  ani_object obj,
    ani_object abilityResult, ani_object callback)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "TerminateSelfWithResultSync called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    auto etsUiExtensionContext = GetEtsUIExtensionContext(env, obj);
    if (etsUiExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null etsUiExtensionContext");
        return;
    }
    etsUiExtensionContext->OnTerminateSelfWithResult(env, obj, abilityResult, callback);
}

void EtsUIExtensionContext::StartAbility(ani_env *env, ani_object aniObj, ani_object wantObj, ani_object call)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "StartAbility");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    auto etsUiExtensionContext = GetEtsUIExtensionContext(env, aniObj);
    if (etsUiExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null etsUiExtensionContext");
        return;
    }
    etsUiExtensionContext->OnStartAbility(env, aniObj, wantObj, nullptr, call);
}

ani_long EtsUIExtensionContext::ConnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
    ani_object wantObj, ani_object connectOptionsObj)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "ConnectServiceExtensionAbility");
    auto etsUiExtensionContext = GetEtsUIExtensionContext(env, aniObj);
    if (etsUiExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null etsUiExtensionContext");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return FAILED_CODE;
    }
    return etsUiExtensionContext->OnConnectServiceExtensionAbility(env, aniObj, wantObj, connectOptionsObj);
}

void EtsUIExtensionContext::DisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
    ani_long connectId, ani_object callback)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "DisconnectServiceExtensionAbility");
    auto etsUiExtensionContext = GetEtsUIExtensionContext(env, aniObj);
    if (etsUiExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null etsUiExtensionContext");
        return;
    }
    etsUiExtensionContext->OnDisconnectServiceExtensionAbility(env, aniObj, connectId, callback);
}

void EtsUIExtensionContext::StartAbilityWithOption(
    ani_env *env, ani_object aniObj, ani_object wantObj, ani_object opt, ani_object call)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "StartAbilityWithOption");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    auto etsUiExtensionContext = GetEtsUIExtensionContext(env, aniObj);
    if (etsUiExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null etsUiExtensionContext");
        return;
    }
    etsUiExtensionContext->OnStartAbility(env, aniObj, wantObj, opt, call);
}

void EtsUIExtensionContext::StartAbilityForResult(ani_env *env, ani_object aniObj, ani_object wantObj,
    ani_object callback)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "StartAbilityForResult called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    auto etsUiExtensionContext = GetEtsUIExtensionContext(env, aniObj);
    if (etsUiExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null etsUiExtensionContext");
        return;
    }
    etsUiExtensionContext->OnStartAbilityForResult(env, aniObj, wantObj, nullptr, callback);
}

void EtsUIExtensionContext::StartAbilityForResultWithOptions(ani_env *env, ani_object aniObj, ani_object wantObj,
    ani_object startOptionsObj, ani_object callback)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "StartAbilityForResultWithOptions called");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    auto etsUiExtensionContext = GetEtsUIExtensionContext(env, aniObj);
    if (etsUiExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null etsUiExtensionContext");
        return;
    }
    etsUiExtensionContext->OnStartAbilityForResult(env, aniObj, wantObj, startOptionsObj, callback);
}

void EtsUIExtensionContext::OnTerminateSelf(ani_env *env, ani_object obj, ani_object callback)
{
    ani_object aniObject = nullptr;
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "context is nullptr");
        auto errCode = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        aniObject = EtsErrorUtil::CreateError(env, static_cast<AbilityErrorCode>(errCode));
        AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }
    context->SetTerminating(true);
    auto ret = context->TerminateSelf();
    OHOS::AppExecFwk::AsyncCallback(env, callback,
        OHOS::AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret)), nullptr);
}

void EtsUIExtensionContext::OnTerminateSelfWithResult(ani_env *env, ani_object obj,
    ani_object abilityResult, ani_object callback)
{
    ani_object aniObject = nullptr;
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "context is nullptr");
        auto errCode = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        aniObject = EtsErrorUtil::CreateError(env, static_cast<AbilityErrorCode>(errCode));
        AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
        return;
    }

    OHOS::AAFwk::Want want;
    int resultCode = 0;
    OHOS::AppExecFwk::UnWrapAbilityResult(env, abilityResult, resultCode, want);
    auto token = context->GetToken();
    OHOS::AAFwk::AbilityManagerClient::GetInstance()->TransferAbilityResultForExtension(token, resultCode, want);
#ifdef SUPPORT_SCREEN
    OHOS::sptr<OHOS::Rosen::Window> uiWindow = context->GetWindow();
    if (!uiWindow) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null uiWindow");
        OHOS::AppExecFwk::AsyncCallback(env, callback, OHOS::AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env,
            static_cast<int32_t>(OHOS::AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM)), nullptr);
        return;
    }
    auto result = uiWindow->TransferAbilityResult(resultCode, want);
    if (result != OHOS::Rosen::WMError::WM_OK) {
        OHOS::AppExecFwk::AsyncCallback(env, callback, OHOS::AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env,
            static_cast<int32_t>(OHOS::AbilityRuntime::AbilityErrorCode::ERROR_CODE_INVALID_PARAM)), nullptr);
        return;
    }
#endif // SUPPORT_SCREEN
    auto ret = context->TerminateSelf();
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::UI_EXT, "TerminateSelf failed, errorCode is %{public}d", ret);
        return;
    }
    OHOS::AppExecFwk::AsyncCallback(env, callback,
        OHOS::AbilityRuntime::EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret)), nullptr);
}

void EtsUIExtensionContext::OnStartAbility(
    ani_env *env, ani_object aniObj, ani_object wantObj, ani_object opt, ani_object callbackObj)
{
    ani_object aniObject = nullptr;
    AAFwk::Want want;
    ErrCode errCode = ERR_OK;
    if (!AppExecFwk::UnwrapWant(env, wantObj, want)) {
        aniObject = EtsErrorUtil::CreateInvalidParamError(env, "UnwrapWant filed");
        AppExecFwk::AsyncCallback(env, callbackObj, aniObject, nullptr);
        return;
    }
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "context is nullptr");
        errCode = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        aniObject = EtsErrorUtil::CreateError(env, static_cast<AbilityErrorCode>(errCode));
        AppExecFwk::AsyncCallback(env, callbackObj, aniObject, nullptr);
        return;
    }
    if ((want.GetFlags() & AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == AAFwk::Want::FLAG_INSTALL_ON_DEMAND) {
        std::string startTime = std::to_string(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count());
        want.SetParam(AAFwk::Want::PARAM_RESV_START_TIME, startTime);
        AddFreeInstallObserver(env, want, callbackObj, context);
    }
    if (opt != nullptr) {
        AAFwk::StartOptions startOptions;
        if (!AppExecFwk::UnwrapStartOptions(env, opt, startOptions)) {
            TAG_LOGE(AAFwkTag::UI_EXT, "UnwrapStartOptions filed");
            aniObject = EtsErrorUtil::CreateInvalidParamError(env, "UnwrapWant filed");
            AppExecFwk::AsyncCallback(env, callbackObj, aniObject, nullptr);
            return;
        }
        errCode = context->StartAbility(want, startOptions);
    } else {
        errCode = context->StartAbility(want);
    }
    aniObject = EtsErrorUtil::CreateErrorByNativeErr(env, errCode);
    if ((want.GetFlags() & AAFwk::Want::FLAG_INSTALL_ON_DEMAND) == AAFwk::Want::FLAG_INSTALL_ON_DEMAND) {
        if (errCode != ERR_OK && freeInstallObserver_ != nullptr) {
            std::string bundleName = want.GetElement().GetBundleName();
            std::string abilityName = want.GetElement().GetAbilityName();
            std::string startTime = want.GetStringParam(AAFwk::Want::PARAM_RESV_START_TIME);
            freeInstallObserver_->OnInstallFinished(bundleName, abilityName, startTime, errCode);
        }
    } else {
        AppExecFwk::AsyncCallback(env, callbackObj, aniObject, nullptr);
    }
}

void EtsUIExtensionContext::OnStartAbilityForResult(ani_env *env, ani_object aniObj, ani_object wantObj,
    ani_object startOptionsObj, ani_object callback)
{
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "context is nullptr");
        AppExecFwk::AsyncCallback(env, callback,
            EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT), nullptr);
        return;
    }

    AAFwk::Want want;
    OHOS::AppExecFwk::UnwrapWant(env, wantObj, want);
    if (!want.HasParameter(AAFwk::Want::PARAM_BACK_TO_OTHER_MISSION_STACK)) {
        want.SetParam(AAFwk::Want::PARAM_BACK_TO_OTHER_MISSION_STACK, true);
    }
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
                EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_CODE_INNER), nullptr);
            env->GlobalReference_Delete(callbackRef);
            return;
        }
        auto errCode = isInner ? resultCode : 0;
        AppExecFwk::AsyncCallback(env, reinterpret_cast<ani_object>(callbackRef),
            EtsErrorUtil::CreateErrorByNativeErr(env, errCode), abilityResult);
        env->GlobalReference_Delete(callbackRef);
    };
    want.SetParam(AAFwk::Want::PARAM_RESV_FOR_RESULT, true);
    auto requestCode = context->GenerateCurRequestCode();
    (startOptionsObj == nullptr) ? context->StartAbilityForResult(want, requestCode, std::move(task))
                                 : context->StartAbilityForResult(want, startOptions, requestCode, std::move(task));
    return;
}

ani_long EtsUIExtensionContext::OnConnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
    ani_object wantObj, ani_object connectOptionsObj)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "OnConnectServiceExtensionAbility");
    ani_status status = ANI_ERROR;
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        EtsErrorUtil::ThrowError(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
        return FAILED_CODE;
    }
    AAFwk::Want want;
    if (!OHOS::AppExecFwk::UnwrapWant(env, wantObj, want)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to UnwrapWant");
        EtsErrorUtil::ThrowInvalidParamError(env, "Failed to UnwrapWant");
        return FAILED_CODE;
    }
    ani_vm *etsVm = nullptr;
    if ((status = env->GetVM(&etsVm)) != ANI_OK || etsVm == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to getVM, status: %{public}d", status);
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return FAILED_CODE;
    }
    sptr<EtsUIExtensionConnection> connection = new (std::nothrow) EtsUIExtensionConnection(etsVm);
    if (connection == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null connection");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return FAILED_CODE;
    }
    if (!CheckConnectionParam(env, connectOptionsObj, connection, want)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Failed to CheckConnectionParam");
        EtsErrorUtil::ThrowInvalidParamError(env, "Failed to CheckConnectionParam");
        return FAILED_CODE;
    }
    auto innerErrCode = context->ConnectAbility(want, connection);
    int32_t connectId = connection->GetConnectionId();
    if (innerErrCode != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Faied to ConnectAbility, innerErrCode is %{public}d", innerErrCode);
        connection->CallEtsFailed(connectId);
        return FAILED_CODE;
    }
    return static_cast<ani_long>(connectId);
}

void EtsUIExtensionContext::OnDisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
    ani_long connectId, ani_object callback)
{
    TAG_LOGE(AAFwkTag::UI_EXT, "OnDisconnectServiceExtensionAbility");
    ani_object aniObject = nullptr;
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        aniObject = EtsErrorUtil::CreateErrorByNativeErr(env,
            static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT));
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
        aniObject = EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER));
        AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
        TAG_LOGE(AAFwkTag::UI_EXT, "null connection");
        return;
    }
    ErrCode ret = context->DisconnectAbility(want, connection);
    aniObject = EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret));
    AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
}

void EtsUIExtensionContext::AddFreeInstallObserver(
    ani_env *env, const AAFwk::Want &want, ani_object callbackObj, std::shared_ptr<UIExtensionContext> context)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return;
    }
    if (!env) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return;
    }
    if (freeInstallObserver_ == nullptr) {
        ani_vm *etsVm = nullptr;
        ani_status status = ANI_ERROR;
        if ((status = env->GetVM(&etsVm)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
            return;
        }
        freeInstallObserver_ = new EtsFreeInstallObserver(etsVm);
        if (context->AddFreeInstallObserver(freeInstallObserver_)) {
            TAG_LOGE(AAFwkTag::UI_EXT, "addFreeInstallObserver error");
            return;
        }
    }
    std::string startTime = want.GetStringParam(AAFwk::Want::PARAM_RESV_START_TIME);
    TAG_LOGD(AAFwkTag::UI_EXT, "addEtsObserver");
    std::string bundleName = want.GetElement().GetBundleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    freeInstallObserver_->AddEtsObserverObject(env, bundleName, abilityName, startTime, callbackObj);
}

bool EtsUIExtensionContext::CheckConnectionParam(ani_env *env, ani_object connectOptionsObj,
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

void EtsUIExtensionContext::Clean(ani_env *env, ani_object object)
{
    ani_long ptr = 0;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativeExtensionContext", &ptr)) {
        return;
    }

    if (ptr != 0) {
        delete reinterpret_cast<EtsUIExtensionContext*>(ptr);
        ptr = 0;
    }
}

bool EtsUIExtensionContext::BindNativePtrCleaner(ani_env *env)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "nullptr env");
        return false;
    }
    ani_class cleanerCls;
    ani_status status = env->FindClass(UI_EXTENSION_CONTEXT_CLEANER_CLASS_NAME, &cleanerCls);
    if (ANI_OK != status) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Not found Cleaner. status:%{public}d.", status);
        return false;
    }
    std::array methods = {
        ani_native_function { "clean", nullptr, reinterpret_cast<void *>(EtsUIExtensionContext::Clean) },
    };
    if (ANI_OK != env->Class_BindNativeMethods(cleanerCls, methods.data(), methods.size())) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return false;
    };
    return true;
}

ani_object CreateEtsUIExtensionContext(ani_env *env, std::shared_ptr<OHOS::AbilityRuntime::UIExtensionContext> context)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "called");
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object contextObj = nullptr;
    if ((env->FindClass(UI_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "J:V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    std::unique_ptr<EtsUIExtensionContext> etsContext = std::make_unique<EtsUIExtensionContext>(context);
    if ((status = env->Object_New(cls, method, &contextObj, reinterpret_cast<ani_long>(etsContext.release()))) !=
        ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    std::array functions = {
        ani_native_function { "terminateSelfSync", nullptr,
            reinterpret_cast<ani_int*>(EtsUIExtensionContext::TerminateSelfSync) },
        ani_native_function { "terminateSelfWithResultSync", nullptr,
            reinterpret_cast<ani_int*>(EtsUIExtensionContext::TerminateSelfWithResultSync) },
        ani_native_function { "nativeStartAbility",
            "L@ohos/app/ability/Want/Want;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsUIExtensionContext::StartAbility) },
        ani_native_function { "nativeStartAbility", "L@ohos/app/ability/Want/Want;L@ohos/app/ability/"
            "StartOptions/StartOptions;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void *>(EtsUIExtensionContext::StartAbilityWithOption) },
        ani_native_function { "nativeConnectServiceExtensionAbility", SIGNATURE_CONNECT_SERVICE_EXTENSION,
            reinterpret_cast<void *>(EtsUIExtensionContext::ConnectServiceExtensionAbility) },
        ani_native_function { "nativeDisconnectServiceExtensionAbilitySync", SIGNATURE_DISCONNECT_SERVICE_EXTENSION,
            reinterpret_cast<void *>(EtsUIExtensionContext::DisconnectServiceExtensionAbility) },
        ani_native_function { "nativeStartAbilityForResult",
            "L@ohos/app/ability/Want/Want;Lutils/AbilityUtils/AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(EtsUIExtensionContext::StartAbilityForResult) },
        ani_native_function { "nativeStartAbilityForResult",
            "L@ohos/app/ability/Want/Want;L@ohos/app/ability/StartOptions/StartOptions;Lutils/AbilityUtils/"
            "AsyncCallbackWrapper;:V",
            reinterpret_cast<void*>(EtsUIExtensionContext::StartAbilityForResultWithOptions) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetFieldByName_Long(contextObj, "nativeContext", (ani_long)context.get())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    if (!EtsUIExtensionContext::BindNativePtrCleaner(env)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    OHOS::AbilityRuntime::ContextUtil::CreateEtsBaseContext(env, cls, contextObj, context);
    OHOS::AbilityRuntime::CreateEtsExtensionContext(env, cls, contextObj, context, context->GetAbilityInfo());
    return contextObj;
}

EtsUIExtensionContext* EtsUIExtensionContext::GetEtsUIExtensionContext(ani_env *env, ani_object obj)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null env");
        return nullptr;
    }
    EtsUIExtensionContext *etsContext = nullptr;
    ani_status status = ANI_ERROR;
    ani_long etsContextLong = 0;
    if ((status = env->Object_GetFieldByName_Long(obj, "nativeExtensionContext", &etsContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return nullptr;
    }
    etsContext = reinterpret_cast<EtsUIExtensionContext *>(etsContextLong);
    if (etsContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "etsContext null");
        return nullptr;
    }
    return etsContext;
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
} // namespace AbilityRuntime
} // namespace OHOS