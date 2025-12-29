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

#include "ets_app_service_extension_context.h"
#include "ets_service_extension_context.h"
#include <chrono>
#include <cstdint>
#include <thread>
#include "ability_manager_client.h"
#include "ani_common_start_options.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ets_context_utils.h"
#include "ets_data_struct_converter.h"
#include "ets_error_utils.h"
#include "ets_extension_context.h"
#include "ets_runtime.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "open_link_options.h"
#include "start_options.h"
#include "uri.h"
#include "ability_runtime/js_caller_complex.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *CONTEXT_CLASS_NAME = "application.AppServiceExtensionContext.AppServiceExtensionContext";
constexpr const char *APP_SERVICE_EXTENSION_CONTEXT_CLASS_NAME =
"application.AppServiceExtensionContext.AppServiceExtensionContext";
static std::mutex g_connectsMutex;
static std::recursive_mutex g_connectsLock;
static std::map<EtsConnectionKey, sptr<ETSAppServiceExtensionConnection>, EtsKeyCompare> g_connects;
static int64_t g_serialNumber = 0;
constexpr const int FAILED_CODE = -1;
constexpr const char *CLEANER_CLASS_NAME = "application.AppServiceExtensionContext.Cleaner";
constexpr const int ANI_ALREADY_BINDED = 8;
}

bool BindNativeMethods(ani_env *env, ani_class &cls)
{
    ani_status status = ANI_ERROR;
    std::array functions = {
        ani_native_function { "nativeTerminateSelf", "C{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsAppServiceExtensionContext::TerminateSelf) },
        ani_native_function { "nativeStartAbility",
            "C{@ohos.app.ability.Want.Want}C{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsAppServiceExtensionContext::StartAbility) },
        ani_native_function { "nativeStartAbility",
            "C{@ohos.app.ability.Want.Want}C{@ohos.app.ability.StartOptions.StartOptions}"
            "C{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsAppServiceExtensionContext::StartAbilityWithOption) },
        ani_native_function { "nativeConnectServiceExtensionAbility",
            "C{@ohos.app.ability.Want.Want}C{ability.connectOptions.ConnectOptions}:l",
            reinterpret_cast<void *>(EtsAppServiceExtensionContext::ConnectServiceExtensionAbility) },
        ani_native_function { "nativeDisconnectServiceExtensionAbility",
            "lC{utils.AbilityUtils.AsyncCallbackWrapper}:",
            reinterpret_cast<void *>(EtsAppServiceExtensionContext::DisconnectServiceExtensionAbility) },
    };
    if ((status = env->Class_BindNativeMethods(cls, functions.data(), functions.size())) != ANI_OK
        && status != ANI_ALREADY_BINDED) {
        TAG_LOGE(AAFwkTag::UI_EXT, "bind method status : %{public}d", status);
        return false;
    }
    ani_class cleanerCls = nullptr;
    status = env->FindClass(CLEANER_CLASS_NAME, &cleanerCls);
    if (status != ANI_OK || cleanerCls == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to find class, status : %{public}d", status);
        return false;
    }
    std::array CleanerMethods = {
        ani_native_function { "clean", nullptr, reinterpret_cast<void *>(EtsAppServiceExtensionContext::Finalizer) },
    };
    if ((status = env->Class_BindNativeMethods(cleanerCls, CleanerMethods.data(), CleanerMethods.size())) != ANI_OK
        && status != ANI_ALREADY_BINDED) {
        TAG_LOGE(AAFwkTag::UI_EXT, "bind method status : %{public}d", status);
        return false;
    }
    return true;
}

int64_t InsertConnection(sptr<ETSAppServiceExtensionConnection> connection,
    const AAFwk::Want &want, int32_t accountId = -1)
{
    std::lock_guard<std::recursive_mutex> lock(g_connectsLock);
    if (connection == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null connection");
        return -1;
    }
    int64_t connectId = g_serialNumber;
    EtsConnectionKey key;
    key.id = g_serialNumber;
    key.want = want;
    key.accountId = accountId;
    connection->SetConnectionId(key.id);
    g_connects.emplace(key, connection);
    g_serialNumber++;
    return connectId;
}
void RemoveConnection(int32_t connectId)
{
    std::lock_guard<std::recursive_mutex> lock(g_connectsLock);
    auto item = std::find_if(g_connects.begin(), g_connects.end(),
    [&connectId](const auto &obj) {
        return connectId == obj.first.id;
    });
    if (item != g_connects.end()) {
        TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "remove connection ability exist");
        if (item->second) {
            item->second->RemoveConnectionObject();
        }
        g_connects.erase(item);
    } else {
        TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "remove connection ability not exist");
    }
}

void ETSServiceExtensionConnection::RemoveConnectionObject()
{
    if (etsVm_ != nullptr && stsConnectionRef_ != nullptr) {
        ani_env *env = nullptr;
        if (etsVm_->GetEnv(ANI_VERSION_1, &env) == ANI_OK && env != nullptr) {
            env->GlobalReference_Delete(stsConnectionRef_);
            stsConnectionRef_ = nullptr;
        }
    }
}

void EtsAppServiceExtensionContext::Finalizer(ani_env *env, void *data, void *hint)
{
    TAG_LOGI(AAFwkTag::APP_SERVICE_EXT, "EtsAppServiceExtensionContext::Finalizer called");
    std::unique_ptr<EtsAppServiceExtensionContext>(static_cast<EtsAppServiceExtensionContext*>(data));
}

EtsAppServiceExtensionContext *EtsAppServiceExtensionContext::GetEtsAbilityContext(
    ani_env *env, ani_object aniObj)
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "GetEtsAbilityContext");
    ani_class cls = nullptr;
    ani_long nativeContextLong;
    ani_field contextField = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null env");
        return nullptr;
    }
    if ((status = env->FindClass(CONTEXT_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to find class, status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindField(cls, "nativeEtsContext", &contextField)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to find filed, status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_GetField_Long(aniObj, contextField, &nativeContextLong)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to get filed, status : %{public}d", status);
        return nullptr;
    }
    auto weakContext = reinterpret_cast<EtsAppServiceExtensionContext *>(nativeContextLong);
    return weakContext;
}

void EtsAppServiceExtensionContext::TerminateSelf(ani_env *env, ani_object obj, ani_object callback)
{
    TAG_LOGI(AAFwkTag::APP_SERVICE_EXT, "TerminateSelf");
    if (env == nullptr) {
        TAG_LOGW(AAFwkTag::APP_SERVICE_EXT, "null env");
        return;
    }
    auto etsAppServiceExtensionContext = EtsAppServiceExtensionContext::GetEtsAbilityContext(env, obj);
    if (etsAppServiceExtensionContext == nullptr) {
        TAG_LOGW(AAFwkTag::APP_SERVICE_EXT, "null etsAppServiceExtensionContext");
        return;
    }
    etsAppServiceExtensionContext->OnTerminateSelf(env, obj, callback);
}

ani_long EtsAppServiceExtensionContext::ConnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
    ani_object wantObj, ani_object connectOptionsObj)
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "ConnectServiceExtensionAbility");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null env");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return FAILED_CODE;
    }
    auto etsAppServiceExtensionContext = EtsAppServiceExtensionContext::GetEtsAbilityContext(env, aniObj);
    if (etsAppServiceExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null etsAppServiceExtensionContext");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return FAILED_CODE;
    }
    return etsAppServiceExtensionContext->OnConnectAppServiceExtensionAbility(env, aniObj, wantObj, connectOptionsObj);
}

void EtsAppServiceExtensionContext::DisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
    ani_long connectId, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "DisconnectServiceExtensionAbility");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null env");
        return;
    }
    auto etsAppServiceExtensionContext = EtsAppServiceExtensionContext::GetEtsAbilityContext(env, aniObj);
    if (etsAppServiceExtensionContext == nullptr) {
        TAG_LOGW(AAFwkTag::APP_SERVICE_EXT, "null etsAppServiceExtensionContext");
        return;
    }
    etsAppServiceExtensionContext->OnDisconnectAppServiceExtensionAbility(env, aniObj, connectId, callback);
}

void EtsAppServiceExtensionContext::StartAbility(ani_env *env, ani_object aniObj, ani_object wantObj,
    ani_object call)
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "StartAbility");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null env");
        return;
    }
    auto etsAppServiceExtensionContext = EtsAppServiceExtensionContext::GetEtsAbilityContext(env, aniObj);
    if (etsAppServiceExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null etsAppServiceExtensionContext");
        return;
    }
    etsAppServiceExtensionContext->OnStartAbility(env, aniObj, wantObj, nullptr, call);
}

void EtsAppServiceExtensionContext::StartAbilityWithOption(ani_env *env, ani_object aniObj, ani_object wantObj,
    ani_object startOptionsObj, ani_object call)
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "StartAbility");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null env");
        return;
    }
    auto etsAppServiceExtensionContext = EtsAppServiceExtensionContext::GetEtsAbilityContext(env, aniObj);
    if (etsAppServiceExtensionContext == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null etsAppServiceExtensionContext");
        return;
    }
    etsAppServiceExtensionContext->OnStartAbility(env, aniObj, wantObj, startOptionsObj, call);
}

ani_object CreateEtsAppServiceExtensionContext(ani_env *env, std::shared_ptr<AppServiceExtensionContext> context)
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "CreateEtsAppServiceExtensionContext");
    if (env == nullptr || context == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null env or context");
        return nullptr;
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    ani_method method = nullptr;
    ani_object contextObj = nullptr;
    if ((env->FindClass(APP_SERVICE_EXTENSION_CONTEXT_CLASS_NAME, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to find class, status : %{public}d", status);
        return nullptr;
    }
    if (!BindNativeMethods(env, cls)) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to BindNativeMethods");
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "l:", &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to find constructor, status : %{public}d", status);
        return nullptr;
    }
    std::unique_ptr<EtsAppServiceExtensionContext> workContext =
        std::make_unique<EtsAppServiceExtensionContext>(context);
    if (workContext == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to create etsAppServiceExtensionContext");
        return nullptr;
    }
    auto serviceContextPtr = new (std::nothrow)
        std::weak_ptr<AppServiceExtensionContext> (workContext->GetAbilityContext());
    if ((status = env->Object_New(cls, method, &contextObj, (ani_long)workContext.release())) != ANI_OK ||
        contextObj == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to create object, status : %{public}d", status);
        return nullptr;
    }
    if (!ContextUtil::SetNativeContextLong(env, contextObj, (ani_long)(serviceContextPtr))) {
        TAG_LOGE(AAFwkTag::CONTEXT, "Failed to setNativeContextLong ");
        return nullptr;
    }
    ContextUtil::CreateEtsBaseContext(env, cls, contextObj, context);
    CreateEtsExtensionContext(env, cls, contextObj, context, context->GetAbilityInfo());
    ani_ref *contextGlobalRef = new (std::nothrow) ani_ref;
    if (contextGlobalRef == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "new contextGlobalRef failed");
        return nullptr;
    }
    if ((status = env->GlobalReference_Create(contextObj, contextGlobalRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "GlobalReference_Create failed status: %{public}d", status);
        delete contextGlobalRef;
        return nullptr;
    }
    context->Bind(contextGlobalRef);
    return contextObj;
}

void EtsAppServiceExtensionContext::OnTerminateSelf(ani_env *env, ani_object obj, ani_object callback)
{
    TAG_LOGI(AAFwkTag::APP_SERVICE_EXT, "OnTerminateSelf");
    ErrCode ret = ERR_OK;
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGW(AAFwkTag::APP_SERVICE_EXT, "context is nullptr");
        ret = static_cast<ErrCode>(AAFwk::ERR_INVALID_CONTEXT);
    } else {
        ret = context->TerminateSelf();
    }
    AppExecFwk::AsyncCallback(env, callback, EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ret)),
        nullptr);
}

ani_long EtsAppServiceExtensionContext::OnConnectAppServiceExtensionAbility(ani_env *env, ani_object aniObj,
    ani_object wantObj, ani_object connectOptionsObj)
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "OnConnectAppServiceExtensionAbility call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null env");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return FAILED_CODE;
    }
    AAFwk::Want want;
    if (!OHOS::AppExecFwk::UnwrapWant(env, wantObj, want)) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to UnwrapWant");
        EtsErrorUtil::ThrowInvalidParamError(env, "Failed to UnwrapWant");
        return FAILED_CODE;
    }
    ani_vm *etsVm = nullptr;
    if (env->GetVM(&etsVm) != ANI_OK || etsVm == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "Failed to getVM");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return FAILED_CODE;
    }
    sptr<ETSAppServiceExtensionConnection> connection = sptr<ETSAppServiceExtensionConnection>::MakeSptr(etsVm);
    connection->SetConnectionRef(connectOptionsObj);
    int32_t connectId = InsertConnection(connection, want);
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null context");
        RemoveConnection(connectId);
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        return FAILED_CODE;
    }
    auto innerErrCode = context->ConnectAbility(want, connection);
    int32_t errcode = static_cast<int32_t>(GetJsErrorCodeByNativeError(innerErrCode));
    if (errcode) {
        connection->CallEtsFailed(errcode);
        RemoveConnection(connectId);
        return FAILED_CODE;
    }
    return connectId;
}

void EtsAppServiceExtensionContext::OnDisconnectAppServiceExtensionAbility(ani_env *env, ani_object aniObj,
    ani_long connectId, ani_object callback)
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "OnDisconnectAppServiceExtensionAbility call");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null env");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    auto context = context_.lock();
    ani_object errorObject = nullptr;
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null context");
        AppExecFwk::AsyncCallback(env, callback, errorObject, nullptr);
        return;
    }
    sptr<ETSAppServiceExtensionConnection> connection = nullptr;
    AAFwk::Want want;
    int32_t accountId = -1;
    {
        std::lock_guard<std::mutex> lock(g_connectsMutex);
        auto iter = std::find_if(
            g_connects.begin(), g_connects.end(), [&connectId](const auto &obj) { return connectId == obj.first.id; });
        if (iter != g_connects.end()) {
            want = iter->first.want;
            connection = iter->second;
            accountId = iter->first.accountId;
            g_connects.erase(iter);
        } else {
            TAG_LOGI(AAFwkTag::APP_SERVICE_EXT, "Failed to found connection");
        }
    }
        if (connection == nullptr) {
        TAG_LOGW(AAFwkTag::APP_SERVICE_EXT, "null connection");
        AppExecFwk::AsyncCallback(env, callback,
            EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(ERR_INVALID_VALUE)), nullptr);
        return;
    }
    
    ErrCode errCode = context->DisconnectAbility(want, connection, accountId);
    AppExecFwk::AsyncCallback(env, callback,
        EtsErrorUtil::CreateErrorByNativeErr(env, static_cast<int32_t>(errCode)), nullptr);
}

void EtsAppServiceExtensionContext::OnStartAbility(ani_env *env, ani_object aniObj, ani_object wantObj,
    ani_object startOptionsObj, ani_object callbackObj)
{
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "OnStartAbility");
    ani_object aniObject = nullptr;
    AAFwk::Want want;
    ErrCode errCode = ERR_OK;
    if (!AppExecFwk::UnwrapWant(env, wantObj, want)) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "UnwrapWant failed");
        aniObject = EtsErrorUtil::CreateInvalidParamError(env, "UnwrapWant failed");
        AppExecFwk::AsyncCallback(env, callbackObj, aniObject, nullptr);
        return;
    }
    ani_status status = ANI_ERROR;
    ani_boolean isOptionsUndefined = true;
    if (startOptionsObj != nullptr) {
        if ((status = env->Reference_IsUndefined(reinterpret_cast<ani_ref>(startOptionsObj),
        &isOptionsUndefined)) != ANI_OK) {
            TAG_LOGW(AAFwkTag::APP_SERVICE_EXT, "Check undefined status: %{public}d", status);
        }
    }
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "context is nullptr");
        errCode = static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
        aniObject = EtsErrorUtil::CreateError(env, static_cast<AbilityErrorCode>(errCode));
        AppExecFwk::AsyncCallback(env, callbackObj, aniObject, nullptr);
        return;
    }
    if (startOptionsObj != nullptr && !isOptionsUndefined) {
        AAFwk::StartOptions startOptions;
        if (AppExecFwk::UnwrapStartOptions(env, startOptionsObj, startOptions)) {
            errCode = context->StartAbility(want, startOptions);
        } else {
            TAG_LOGW(AAFwkTag::APP_SERVICE_EXT, "UnwrapStartOptions failed, fallback to StartAbility(want)");
            errCode = context->StartAbility(want);
        }
    } else {
        errCode = context->StartAbility(want);
    }
    aniObject = EtsErrorUtil::CreateErrorByNativeErr(env, errCode);
    AppExecFwk::AsyncCallback(env, callbackObj, aniObject, nullptr);
}
}  // namespace AbilityRuntime
}  // namespace OHOS