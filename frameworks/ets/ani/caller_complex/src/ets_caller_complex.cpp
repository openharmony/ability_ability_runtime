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

#include "ets_caller_complex.h"

#include "ability_business_error.h"
#include "ability_runtime/js_caller_complex.h"
#include "ani_remote_object.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "js_runtime.h"

namespace { // nameless
using namespace OHOS;
using namespace OHOS::AbilityRuntime;
constexpr const char* CALLER_CLASS_NAME = "Lapplication/Caller/CallerImpl;";

void ReleaseNativeRemote(ani_env *env, ani_ref aniObj)
{
    TAG_LOGI(AAFwkTag::UIABILITY, "ReleaseNativeRemote");
}
} // nameless

namespace OHOS {
namespace AbilityRuntime {
std::mutex EtsCallerComplex::staticTransferRecordMutex_;
std::unordered_map<uintptr_t, std::shared_ptr<EtsRefWrap>> EtsCallerComplex::staticTransferRecords_;

EtsCallerComplex* EtsCallerComplex::GetComplexPtrFrom(ani_env *env, ani_object aniObj)
{
    if (env == nullptr || aniObj == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env or aniObj");
        return nullptr;
    }
    ani_long nativeCaller;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Long(aniObj, "nativeCaller", &nativeCaller)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "get nativeCaller status : %{public}d", status);
        return nullptr;
    }
    return reinterpret_cast<EtsCallerComplex*>(nativeCaller);
}

ani_ref EtsCallerComplex::GetEtsRemoteObj(ani_env *env, ani_object aniObj)
{
    if (env == nullptr || aniObj == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env or aniObj");
        return nullptr;
    }
    ani_ref etsRemoteObj = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->Object_GetFieldByName_Ref(aniObj, "callee", &etsRemoteObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "get callee status : %{public}d", status);
        return nullptr;
    }
    return etsRemoteObj;
}

void EtsCallerComplex::ReleaseCall(ani_env *env, ani_object aniObj)
{
    TAG_LOGI(AAFwkTag::UIABILITY, "ReleaseCall");
    auto ptr = GetComplexPtrFrom(env, aniObj);
    if (ptr == nullptr) {
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }
    ptr->ReleaseCallInner(env);

    auto etsRemoteObj = GetEtsRemoteObj(env, aniObj);
    ReleaseNativeRemote(env, etsRemoteObj);
    delete ptr;
}

void EtsCallerComplex::ReleaseCallInner(ani_env *env)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "ReleaseCallInner");
    if (callerCallback_ == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null CallBacker");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }

    if (!releaseCallFunc_) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null releaseFunc");
        EtsErrorUtil::ThrowError(env, AbilityErrorCode::ERROR_CODE_INNER);
        return;
    }

    callerCallback_->SetCallBack(nullptr);
    int32_t innerErrorCode = releaseCallFunc_(callerCallback_);
    if (innerErrorCode != ERR_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "ReleaseAbility failed %{public}d", static_cast<int>(innerErrorCode));
        EtsErrorUtil::ThrowError(env, innerErrorCode);
    }
}

ani_object EtsCallerComplex::CreateEtsCaller(ani_env *env, ReleaseCallFunc releaseCallFunc,
    sptr<IRemoteObject> callee, std::shared_ptr<CallerCallBack> callback)
{
    ani_class cls {};
    ani_status status = ANI_ERROR;
    ani_object callerObj = nullptr;
    ani_method method {};

    if ((status = env->FindClass(CALLER_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "l:", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    auto etsCaller = std::make_unique<EtsCallerComplex>(releaseCallFunc, callback, callee);
    if ((status = env->Object_New(cls, method, &callerObj, (ani_long)(etsCaller.get()))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->FindClass("L@ohos/rpc/rpc/RemoteProxy;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "FindClass RemoteProxy: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "l:", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "RemoteProxy ctor: %{public}d", status);
        return nullptr;
    }
    ani_object remoteObj = nullptr;
    if ((status = env->Object_New(cls, method, &remoteObj, (ani_long)(callee.GetRefPtr()))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "RemoteProxy create: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_SetFieldByName_Ref(callerObj, "callee", remoteObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    SetCallerCallback(callback, env, callerObj);
    etsCaller.release();
    return callerObj;
}

void EtsCallerComplex::SetCallerCallback(std::shared_ptr<CallerCallBack> callback, ani_env *env, ani_object callerObj)
{
    if (callback == nullptr || env == nullptr || callerObj == nullptr) {
        TAG_LOGI(AAFwkTag::UIABILITY, "SetCallerCallback fail");
        return;
    }

    callback->SetOnRelease([callbackObj = std::make_shared<CallbackWrap>(env, callerObj, "onReleaseCb")](
        const std::string &msg) {
            callbackObj->Invoke(msg);
        });
    callback->SetOnRemoteStateChanged([callbackObj = std::make_shared<CallbackWrap>(env,
        callerObj, "onRemoteChangeCb")](const std::string &msg) {
            callbackObj->Invoke(msg);
        });
}

ani_object EtsCallerComplex::NativeTransferStatic(ani_env *env, ani_object, ani_object input)
{
    TAG_LOGI(AAFwkTag::UIABILITY, "transfer static caller");
    std::lock_guard lock(staticTransferRecordMutex_);
    ani_object output = nullptr;
    uintptr_t srcPtr = 0;
    do {
        void *unwrapResult = nullptr;
        bool success = arkts_esvalue_unwrap(env, input, &unwrapResult);
        if (!success) {
            TAG_LOGE(AAFwkTag::UIABILITY, "failed to unwrap");
            break;
        }
        if (unwrapResult == nullptr) {
            TAG_LOGE(AAFwkTag::UIABILITY, "null unwrapResult");
            break;
        }
        srcPtr = reinterpret_cast<uintptr_t>(unwrapResult);
        auto recordItr = staticTransferRecords_.find(srcPtr);
        if (recordItr != staticTransferRecords_.end()) {
            return reinterpret_cast<ani_object>(recordItr->second->objectRef);
        }
        auto remoteObj = GetJsCallerRemoteObj(srcPtr);
        if (remoteObj == nullptr) {
            TAG_LOGE(AAFwkTag::UIABILITY, "null remoteObj");
        }

        output = CreateEtsCaller(env, [](std::shared_ptr<CallerCallBack> callback) {
            if (callback != nullptr) {
                callback->InvokeOnRelease("release");
            }
            return ERR_OK;
            }, remoteObj, std::make_shared<CallerCallBack>());
    } while (false);

    if (output == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "failed to create");
        EtsErrorUtil::ThrowEtsTransferClassError(env);
    } else {
        staticTransferRecords_.emplace(srcPtr, std::make_shared<EtsRefWrap>(env, output));
    }
    return output;
}

ani_object EtsCallerComplex::NativeTransferDynamic(ani_env *env, ani_object, ani_object input)
{
    TAG_LOGI(AAFwkTag::UIABILITY, "transfer dynamic caller");
    ani_object result = nullptr;
    do {
        if (!IsInstanceOf(env, input)) {
            TAG_LOGE(AAFwkTag::UIABILITY, "not caller");
            break;
        }

        auto nativePtr = GetComplexPtrFrom(env, input);
        if (nativePtr == nullptr) {
            TAG_LOGE(AAFwkTag::UIABILITY, "null nativePtr");
            break;
        }
        auto remoteObj = nativePtr->remoteObj_.promote();
        result = CreateDynamicCaller(env, remoteObj);
    } while (false);
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "failed to transfer");
        EtsErrorUtil::ThrowEtsTransferClassError(env);
    }
    return result;
}

bool EtsCallerComplex::IsInstanceOf(ani_env *env, ani_object aniObj)
{
    ani_class cls {};
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return false;
    }
    if ((status = env->FindClass(CALLER_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return false;
    }
    ani_boolean isInstanceOf = false;
    if ((status = env->Object_InstanceOf(aniObj, cls, &isInstanceOf)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status: %{public}d", status);
        return false;
    }
    return isInstanceOf;
}

ani_object EtsCallerComplex::CreateDynamicCaller(ani_env *env, sptr<IRemoteObject> remoteObj)
{
    if (remoteObj == nullptr || env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null remoteObj or env");
        return nullptr;
    }
    napi_env napiEnv = {};
    if (!arkts_napi_scope_open(env, &napiEnv)) {
        TAG_LOGE(AAFwkTag::UIABILITY, "arkts_napi_scope_open failed");
        return nullptr;
    }

    auto baseObj = CreateJsCallerComplex(napiEnv, [](std::shared_ptr<CallerCallBack> callback) {
        if (callback != nullptr) {
            callback->InvokeOnRelease("release");
        }
        return ERR_OK;
        }, remoteObj, std::make_shared<CallerCallBack>());
    ani_object result = nullptr;
    do {
        auto napiRef = JsRuntime::LoadSystemModuleByEngine(napiEnv, "application.Caller", &baseObj, 1);
        if (napiRef == nullptr) {
            TAG_LOGE(AAFwkTag::UIABILITY, "create napi caller failed");
            break;
        }
        auto jsObj = napiRef->Get();
        hybridgref ref = nullptr;
        bool success = hybridgref_create_from_napi(napiEnv, jsObj, &ref);
        if (!success) {
            TAG_LOGE(AAFwkTag::UIABILITY, "hybridgref_create_from_napi failed");
            break;
        }

        success = hybridgref_get_esvalue(env, ref, &result);
        if (!success) {
            TAG_LOGE(AAFwkTag::UIABILITY, "hybridgref_get_esvalue failed");
        }
        hybridgref_delete_from_napi(napiEnv, ref);
    } while (false);

    arkts_napi_scope_close_n(napiEnv, 0, nullptr, nullptr);
    return result;
}

void EtsCallerComplex::TransferFinalizeCallback(uintptr_t jsPtr)
{
    std::lock_guard lock(staticTransferRecordMutex_);
    staticTransferRecords_.erase(jsPtr);
}

EtsRefWrap::EtsRefWrap(ani_env *env, ani_object srcObj)
{
    if (env->GetVM(&aniVM) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "get aniVM failed");
        return;
    }

    ani_status status = ANI_ERROR;
    if ((status = env->GlobalReference_Create(srcObj, &objectRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "create ref: %{public}d", status);
    }
}

EtsRefWrap::~EtsRefWrap()
{
    if (objectRef == nullptr) {
        return;
    }
    ani_status status = ANI_ERROR;
    ani_env *aniEnv = nullptr;
    if ((status = aniVM->GetEnv(ANI_VERSION_1, &aniEnv)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "GetEnv failed, status : %{public}d", status);
        return;
    }
    aniEnv->GlobalReference_Delete(objectRef);
    objectRef = nullptr;
}

CallbackWrap::CallbackWrap(ani_env *env, ani_object callerObj, const std::string &callbackName)
    : EtsRefWrap(env, callerObj), name(callbackName) {}

void CallbackWrap::Invoke(const std::string &msg) const
{
    if (objectRef == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "objectRef null");
        return;
    }
    ani_string aniMsg = nullptr;
    ani_status status = ANI_ERROR;
    ani_env *aniEnv = nullptr;
    if ((status = aniVM->GetEnv(ANI_VERSION_1, &aniEnv)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "GetEnv failed, status : %{public}d", status);
        return;
    }
    if ((status = aniEnv->String_NewUTF8(msg.c_str(), msg.size(), &aniMsg)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "String_NewUTF8 failed %{public}d", status);
        return;
    }
    status = aniEnv->Object_CallMethodByName_Void(reinterpret_cast<ani_object>(objectRef), name.c_str(),
        "Lstd/core/String;:V", aniMsg);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "%{public}s failed %{public}d", name.c_str(), status);
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm *vm, uint32_t *result)
{
    TAG_LOGI(AAFwkTag::UIABILITY, "load ets_caller_complex");
    if (vm == nullptr || result == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null vm or result");
        return ANI_ERROR;
    }

    ani_env *env = nullptr;
    ani_status status = ANI_OK;
    if ((status = vm->GetEnv(ANI_VERSION_1, &env)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "GetEnv failed status: %{public}d", status);
        return ANI_NOT_FOUND;
    }
    ani_class cls {};
    if ((status = env->FindClass(CALLER_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "find class status : %{public}d", status);
        return ANI_NOT_FOUND;
    }
    std::array functions = {
        ani_native_function { "nativeReleaseSync", nullptr,
            reinterpret_cast<void*>(EtsCallerComplex::ReleaseCall) },
        ani_native_function { "nativeTransferStatic", "Lstd/interop/ESValue;:Lstd/core/Object;",
            reinterpret_cast<void*>(EtsCallerComplex::NativeTransferStatic) },
        ani_native_function { "nativeTransferDynamic", "Lstd/core/Object;:Lstd/interop/ESValue;",
            reinterpret_cast<void*>(EtsCallerComplex::NativeTransferDynamic) },
    };
    status = env->Class_BindNativeMethods(cls, functions.data(), functions.size());
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "bind methods status: %{public}d", status);
        return status;
    }

    SetFinalizeCallback(EtsCallerComplex::TransferFinalizeCallback);

    *result = ANI_VERSION_1;
    return ANI_OK;
}
}
} // namespace AbilityRuntime
} // namespace OHOS