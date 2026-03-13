/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ani.h"

#include <cstdint>
#include <unistd.h>
#include <memory>
#include <mutex>
#include "ability_business_error.h"
#include "application_data_manager.h"
#include "event_runner.h"
#include "hilog_tag_wrapper.h"
#include "ierror_observer.h"
#include "event_runner.h"
#include "ani_common_util.h"
#include "ets_error_utils.h"
#include "error_manager_ani_util.h"
#include "app_recovery.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr char CLASS_NAME_BUSINESSERROR[] = "@ohos.base.BusinessError";

struct ObserverItem {
    ani_ref ref;
    ani_vm* vm;
    bool operator<(const ObserverItem& other) const
    {
        return ref < other.ref;
    }
};
static ObserverItem g_freezeObserver;
static ObserverItem g_defaultHandler;
static std::mutex g_defaultHandlerMtx;
static std::mutex g_freezeMtx;
static bool g_freezeCallbackRegistered = false;

static std::set<ani_ref> g_unhandledRejectionObservers;
static std::mutex g_unhandledRejectionMtx;
static ani_vm* g_unhandledRejectionVm = nullptr;
} // namespace

class ErrorManagerAni final {
public:
    ErrorManagerAni() {}
    ~ErrorManagerAni() = default;

    static void Finalizer(ani_env *env, void* data, void* hint)
    {
        TAG_LOGI(AAFwkTag::RECOVERY, "finalizer called");
        std::unique_ptr<ErrorManagerAni>(static_cast<ErrorManagerAni*>(data));
        ClearReference(env);
    }

    static void ClearReference(ani_env *env)
    {
        std::lock_guard<std::mutex> lock(g_unhandledRejectionMtx);
        for (auto& iter : g_unhandledRejectionObservers) {
            env->GlobalReference_Delete(iter);
        }
        g_unhandledRejectionObservers.clear();
    }

    static ani_object CreateErrorObject(ani_env *env, const AppExecFwk::ErrorObject &errorObj)
    {
        ani_object error {};
        if (env == nullptr) {
            return error;
        }
        ani_class cls {};
        if (env->FindClass(CLASS_NAME_BUSINESSERROR, &cls) != ANI_OK) {
            TAG_LOGE(AAFwkTag::RECOVERY, "find class %{public}s failed", CLASS_NAME_BUSINESSERROR);
            return error;
        }
        ani_method ctor {};
        if (env->Class_FindMethod(cls, "<ctor>", ":", &ctor) != ANI_OK) {
            TAG_LOGE(AAFwkTag::RECOVERY, "find method BusinessError constructor failed");
            return error;
        }
        if (env->Object_New(cls, ctor, &error) != ANI_OK) {
            TAG_LOGE(AAFwkTag::RECOVERY, "new object %{public}s failed", CLASS_NAME_BUSINESSERROR);
            return error;
        }
        ani_string messageRef {};
        std::string message = errorObj.message;
        if (env->String_NewUTF8(message.c_str(), message.size(), &messageRef) != ANI_OK) {
            TAG_LOGE(AAFwkTag::RECOVERY, "new message string failed");
            return error;
        }
        if (env->Object_SetPropertyByName_Ref(error, "message", static_cast<ani_ref>(messageRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::RECOVERY, "set property BusinessError.message failed");
            return error;
        }
        return error;
    }

    static void DoErrorCallback(const AppExecFwk::ErrorObject &errorObj)
    {
        if (g_defaultHandler.vm == nullptr) {
            TAG_LOGE(AAFwkTag::RECOVERY, "null vm");
            return;
        }
        if (g_defaultHandler.ref == nullptr) {
            TAG_LOGE(AAFwkTag::RECOVERY, "null defaultHandler ref");
            return;
        }
        std::lock_guard<std::mutex> lock(g_defaultHandlerMtx);
        ani_env *env = nullptr;
        bool isAttachThread = false;
        env = AppExecFwk::AttachAniEnv(g_defaultHandler.vm, isAttachThread);
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::RECOVERY, "null env");
            return;
        }
        TAG_LOGW(AAFwkTag::RECOVERY, "Error name: %{public}s, message: %{public}s", errorObj.name.c_str(),
            errorObj.message.c_str());
        TAG_LOGW(AAFwkTag::RECOVERY, "Error stack: %{public}s", errorObj.stack.c_str());
        AppExecFwk::DetachAniEnv(g_defaultHandler.vm, isAttachThread);
    }

    static void NotifyUnhandledRejectionHandler(ani_object promise, ani_object reason)
    {
        std::lock_guard<std::mutex> lock(g_unhandledRejectionMtx);
        ani_env *env = nullptr;
        bool isAttachThread = false;
        env = AppExecFwk::AttachAniEnv(g_unhandledRejectionVm, isAttachThread);
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::RECOVERY, "null env");
            return;
        }
        for (auto& iter : g_unhandledRejectionObservers) {
            ani_object callback = static_cast<ani_object>(iter);
            if (!ValidateFunction(env, callback)) {
                return;
            }
            TAG_LOGW(AAFwkTag::RECOVERY, "UnhandledRejection callback execute success.");
        }
        AppExecFwk::DetachAniEnv(g_unhandledRejectionVm, isAttachThread);
        return;
    }

    static ani_object SetDefaultErrorHandler(ani_env *env, ani_object function)
    {
        ani_object result = nullptr;
        if (IsRefUndefined(env, function)) {
            TAG_LOGE(AAFwkTag::RECOVERY, "invalid func");
            EtsErrorUtil::ThrowInvalidNumParametersError(env);
            return result;
        }
        if (IsNull(env, function)) {
            function = nullptr;
        }
        std::lock_guard<std::mutex> lock(g_defaultHandlerMtx);
        if (g_defaultHandler.ref) {
            result = static_cast<ani_object>(g_defaultHandler.ref);
            env->GlobalReference_Delete(g_defaultHandler.ref);
            g_defaultHandler.ref = nullptr;
        }
        if (function) {
            auto status = env->GlobalReference_Create(function, &g_defaultHandler.ref);
            if (status != ANI_OK) {
                TAG_LOGE(AAFwkTag::RECOVERY, "create defaultHandler function failed.");
                return result;
            }
        }
        g_defaultHandler.vm = GetAniVm(env);
        return result;
    }

    static void FreezeCallback()
    {
        TAG_LOGD(AAFwkTag::RECOVERY, "FreezeCallback begin");
        std::lock_guard<std::mutex> lock(g_freezeMtx);
        ani_env *env = nullptr;
        bool isAttachThread = false;
        env = AppExecFwk::AttachAniEnv(g_freezeObserver.vm, isAttachThread);
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::RECOVERY, "null env");
            return;
        }
        if (g_freezeObserver.ref == nullptr) {
            TAG_LOGE(AAFwkTag::RECOVERY, "null freezeObserver ref");
            return;
        }
        std::vector<ani_ref> args = {};
        ani_ref result{};
        ani_status status = env->FunctionalObject_Call(
            reinterpret_cast<ani_fn_object>(g_freezeObserver.ref), 0, args.data(), &result);
        if (status != ANI_OK) {
            TAG_LOGE(AAFwkTag::RECOVERY, "failed to call function, status: %{public}d", status);
        }
        TAG_LOGD(AAFwkTag::RECOVERY, "FreezeCallback end");
        AppExecFwk::DetachAniEnv(g_freezeObserver.vm, isAttachThread);
    }

    static ani_object OnFreeze(ani_env *env, ani_object function)
    {
        ani_object result{};
        if (!AppExecFwk::EventRunner::IsAppMainThread()) {
            TAG_LOGE(AAFwkTag::RECOVERY, "not mainThread");
            EtsErrorUtil::ThrowInvalidCallerError(env);
            return result;
        }
        if (!ValidateFunction(env, function)) {
            return result;
        }
        std::lock_guard<std::mutex> lock(g_freezeMtx);
        if (g_freezeObserver.ref) {
            env->GlobalReference_Delete(g_freezeObserver.ref);
            g_freezeObserver.ref = nullptr;
        }
        if (function) {
            auto status = env->GlobalReference_Create(function, &g_freezeObserver.ref);
            if (status != ANI_OK) {
                TAG_LOGE(AAFwkTag::RECOVERY, "create freeze function failed.");
                return result;
            }
        }
        g_freezeObserver.vm = GetAniVm(env);
        if (!g_freezeCallbackRegistered) {
            AppExecFwk::AppRecovery::GetInstance().SetFreezeCallback(FreezeCallback);
            g_freezeCallbackRegistered = true;
            TAG_LOGI(AAFwkTag::RECOVERY, "Freeze callback registered to AppRecovery successfully");
        }
        return result;
    }

    static ani_object OffFreeze(ani_env *env, ani_object function)
    {
        ani_object result{};
        if (!AppExecFwk::EventRunner::IsAppMainThread()) {
            TAG_LOGE(AAFwkTag::RECOVERY, "not mainThread");
            EtsErrorUtil::ThrowInvalidCallerError(env);
            return result;
        }
        std::lock_guard<std::mutex> lock(g_freezeMtx);
        if (g_freezeObserver.ref == nullptr) {
            TAG_LOGE(AAFwkTag::RECOVERY, "null freezeObserver");
            return result;
        }

        if (function == nullptr) {
            env->GlobalReference_Delete(g_freezeObserver.ref);
            g_freezeObserver.ref = nullptr;
            g_freezeObserver = {};
            if (g_freezeCallbackRegistered) {
                AppExecFwk::AppRecovery::GetInstance().SetFreezeCallback(nullptr);
                g_freezeCallbackRegistered = false;
                TAG_LOGI(AAFwkTag::RECOVERY, "Freeze callback unregistered from AppRecovery successfully");
            }
            return result;
        }
        if (!ValidateFunction(env, function)) {
            return result;
        }
        ani_object observer = static_cast<ani_object>(g_freezeObserver.ref);
        ani_boolean equals = false;
        env->Reference_StrictEquals(observer, function, &equals);
        if (equals) {
            env->GlobalReference_Delete(g_freezeObserver.ref);
            g_freezeObserver.ref = nullptr;
            g_freezeObserver = {};
            if (g_freezeCallbackRegistered) {
                AppExecFwk::AppRecovery::GetInstance().SetFreezeCallback(nullptr);
                g_freezeCallbackRegistered = false;
                TAG_LOGI(AAFwkTag::RECOVERY, "Freeze callback unregistered from AppRecovery successfully");
            }
            return result;
        }
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_OBSERVER_NOT_FOUND);
        return result;
    }

    static ani_object OnUnhandledRejectionInner(ani_env *env, ani_object function)
    {
        ani_object result{};
        if (!ValidateFunction(env, function)) {
            return result;
        }
        std::lock_guard<std::mutex> lock(g_unhandledRejectionMtx);
        for (auto& iter : g_unhandledRejectionObservers) {
            ani_object observer = static_cast<ani_object>(iter);
            ani_boolean equals = false;
            env->Reference_StrictEquals(observer, function, &equals);
            if (equals) {
                env->GlobalReference_Delete(iter);
                g_unhandledRejectionObservers.erase(iter);
                break;
            }
        }
        ani_ref ref = nullptr;
        if (function) {
            auto status = env->GlobalReference_Create(function, &ref);
            if (status != ANI_OK) {
                TAG_LOGE(AAFwkTag::RECOVERY, "create unhandledRejection function failed.");
                return result;
            }
        }
        g_unhandledRejectionVm = GetAniVm(env);
        g_unhandledRejectionObservers.insert(ref);
        return result;
    }

    static ani_object OffUnhandledRejection(ani_env *env, ani_object function)
    {
        ani_object result{};
        std::lock_guard<std::mutex> lock(g_unhandledRejectionMtx);
        if (function == nullptr) {
            for (auto& iter : g_unhandledRejectionObservers) {
                env->GlobalReference_Delete(iter);
            }
            g_unhandledRejectionObservers.clear();
            return result;
        }

        if (!ValidateFunction(env, function)) {
            return result;
        }

        for (auto& iter : g_unhandledRejectionObservers) {
            ani_object observer = static_cast<ani_object>(iter);
            ani_boolean equals = false;
            env->Reference_StrictEquals(observer, function, &equals);
            if (equals) {
                env->GlobalReference_Delete(iter);
                g_unhandledRejectionObservers.erase(iter);
                return result;
            }
        }
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_OBSERVER_NOT_FOUND);
        return result;
    }

    static bool ValidateFunction(ani_env *env, ani_object function)
    {
        if (env == nullptr) {
            TAG_LOGE(AAFwkTag::RECOVERY, "null env");
            return false;
        }
        if (function == nullptr || IsRefUndefined(env, function) || IsNull(env, function)) {
            TAG_LOGE(AAFwkTag::RECOVERY, "invalid func");
            EtsErrorUtil::ThrowInvalidNumParametersError(env);
            return false;
        }
        return true;
    }
};

static void EtsErrorManagerInit(ani_env *env)
{
    TAG_LOGD(AAFwkTag::RECOVERY, "ErrorManager ets called.");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::RECOVERY, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::RECOVERY, "ResetError failed");
    }

    ani_namespace ns;
    status = env->FindNamespace("@ohos.app.ability.errorManager.errorManager", &ns);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::RECOVERY, "FindNamespace errorManager failed status: %{public}d", status);
        return;
    }

    std::array kitFunctions = {
        ani_native_function {"setDefaultErrorHandler", nullptr, reinterpret_cast<void *>(
            ErrorManagerAni::SetDefaultErrorHandler)},
        ani_native_function {"onFreeze", nullptr, reinterpret_cast<void *>(ErrorManagerAni::OnFreeze)},
        ani_native_function {"offFreeze", nullptr, reinterpret_cast<void *>(ErrorManagerAni::OffFreeze)},
        ani_native_function {"notifyUnhandledRejectionHandler", nullptr, reinterpret_cast<void *>(
            ErrorManagerAni::NotifyUnhandledRejectionHandler)},
        ani_native_function {"onUnhandledRejectionInner", nullptr, reinterpret_cast<void *>(
            ErrorManagerAni::OnUnhandledRejectionInner)},
        ani_native_function {"offUnhandledRejection", nullptr, reinterpret_cast<void *>(
            ErrorManagerAni::OffUnhandledRejection)},
    };

    status = env->Namespace_BindNativeFunctions(ns, kitFunctions.data(), kitFunctions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::RECOVERY, "Namespace_BindNativeFunctions failed status: %{public}d", status);
    }

    if (env->ResetError() != ANI_OK) {
        TAG_LOGE(AAFwkTag::RECOVERY, "ResetError failed");
    }
    TAG_LOGD(AAFwkTag::RECOVERY, "ErrorManager ets called end");
}
}  // namespace AbilityRuntime
}  // namespace OHOS

ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGD(AAFwkTag::RECOVERY, "ANI_Constructor start.");
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    if (vm == nullptr) {
        TAG_LOGE(AAFwkTag::RECOVERY, "null vm");
        return ANI_ERROR;
    }
    status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::RECOVERY, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    }

    OHOS::AbilityRuntime::EtsErrorManagerInit(env);
    *result = ANI_VERSION_1;
    OHOS::AppExecFwk::ApplicationDataManager::GetInstance().SetErrorHandlerCallback(
        OHOS::AbilityRuntime::ErrorManagerAni::DoErrorCallback);

    TAG_LOGD(AAFwkTag::RECOVERY, "ANI_Constructor finish");
    return ANI_OK;
}
