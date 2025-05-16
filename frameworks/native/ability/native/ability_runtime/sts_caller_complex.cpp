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

#include "sts_caller_complex.h"

#include <mutex>

#include "ability_business_error.h"
#include "ani_remote_object.h"
#include "hilog_tag_wrapper.h"
#include "sts_error_utils.h"

namespace { // nameless
using namespace OHOS;
using namespace OHOS::AbilityRuntime;
class EtsCallerComplex;

static std::once_flag g_bindNativeMethodsFlag;

EtsCallerComplex *GetComplexPtrFrom(ani_env *env, ani_object aniObj)
{
    ani_long nativeCaller;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "null env");
        return nullptr;
    }
    if ((status = env->Object_GetFieldByName_Long(aniObj, "nativeCaller", &nativeCaller)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "status : %{public}d", status);
        return nullptr;
    }
    return reinterpret_cast<EtsCallerComplex*>(nativeCaller);
}

ani_ref GetEtsRemoteObj(ani_env *env, ani_object aniObj)
{
    ani_ref etsRemoteObj = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "null env");
        return nullptr;
    }
    if ((status = env->Object_GetFieldByName_Ref(aniObj, "callee", &etsRemoteObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "status : %{public}d", status);
        return nullptr;
    }
    return etsRemoteObj;
}

void ReleaseNativeRemote(ani_env *env, ani_ref aniObj)
{
    TAG_LOGI(AAFwkTag::ABILITY, "ReleaseNativeRemote");
}

ani_object AniCreateRemoteObj(ani_env *env, sptr<IRemoteObject> callee)
{
    TAG_LOGI(AAFwkTag::ABILITY, "AniCreateRemoteObj");
    ani_object etsRemoteObj = ANI_ohos_rpc_CreateJsRemoteObject(env, callee);
    return etsRemoteObj;
}

class EtsCallerComplex {
public:
    explicit EtsCallerComplex(ReleaseCallFunc releaseCallFunc, std::shared_ptr<CallerCallBack> callerCallBack)
        : releaseCallFunc_(releaseCallFunc), callerCallBack_(callerCallBack) {}
    ~EtsCallerComplex() = default;

    static void ReleaseCall(ani_env *env, ani_object aniObj)
    {
        TAG_LOGI(AAFwkTag::ABILITY, "ReleaseCall");
        auto ptr = GetComplexPtrFrom(env, aniObj);
        if (ptr == nullptr) {
            ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
            return;
        }
        ptr->ReleaseCallInner(env);

        auto etsRemoteObj = GetEtsRemoteObj(env, aniObj);
        ReleaseNativeRemote(env, etsRemoteObj);
    }

    static void SetOnRelease(ani_env *env, ani_object aniObj, ani_object callback)
    {
        TAG_LOGI(AAFwkTag::ABILITY, "SetOnRelease");
        auto ptr = GetComplexPtrFrom(env, aniObj);
        if (ptr == nullptr || ptr->callerCallBack_ == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITY, "SetOnRelease null");
            return;
        }
        ani_vm *aniVM = nullptr;
        if (env->GetVM(&aniVM) != ANI_OK) {
            TAG_LOGE(AAFwkTag::ABILITY, "get aniVM failed");
            return;
        }
        ani_ref callbackRef = nullptr;
        ani_status status = ANI_ERROR;
        if ((status = env->GlobalReference_Create(callback, &callbackRef)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::ABILITY, "callbackRef: %{public}d", status);
            return;
        }
        ptr->callerCallBack_->SetOnRelease([aniVM, callbackRef](const std::string &msg) {
            ani_string aniMsg = nullptr;
            ani_status status = ANI_ERROR;
            ani_env *aniEnv = nullptr;
            if ((status = aniVM->GetEnv(ANI_VERSION_1, &aniEnv)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::ABILITY, "GetEnv failed, status : %{public}d", status);
                return;
            }
            if ((status = aniEnv->String_NewUTF8(msg.c_str(), msg.size(), &aniMsg)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::ABILITY, "String_NewUTF8 failed %{public}d", status);
                return;
            }
            status = aniEnv->Object_CallMethodByName_Void(reinterpret_cast<ani_object>(callbackRef), "invoke",
                "Lstd/core/String;:V", aniMsg);
            if (status != ANI_OK) {
                TAG_LOGE(AAFwkTag::ABILITY, "OnRelease call failed %{public}d", status);
            }
            aniEnv->GlobalReference_Delete(callbackRef);
            });
    }

    static void SetOnRemoteStateChange(ani_env *env, ani_object aniObj, ani_object callback)
    {
        TAG_LOGI(AAFwkTag::ABILITY, "SetOnRemoteStateChange");
    }

private:
    void ReleaseCallInner(ani_env *env)
    {
        TAG_LOGD(AAFwkTag::ABILITY, "called");
        if (callerCallBack_ == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITY, "null CallBacker");
            ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
            return;
        }

        if (!releaseCallFunc_) {
            TAG_LOGE(AAFwkTag::ABILITY, "null releaseFunc");
            ThrowStsError(env, AbilityErrorCode::ERROR_CODE_INNER);
            return;
        }

        callerCallBack_->SetCallBack(nullptr);
        int32_t innerErrorCode = releaseCallFunc_(callerCallBack_);
        if (innerErrorCode != ERR_OK) {
            TAG_LOGE(AAFwkTag::ABILITY, "ReleaseAbility failed %{public}d", static_cast<int>(innerErrorCode));
            ThrowStsError(env, innerErrorCode);
        }
    }

private:
    ReleaseCallFunc releaseCallFunc_;
    std::shared_ptr<CallerCallBack> callerCallBack_;
};

bool BindNativeMethods(ani_env *env, ani_class &cls)
{
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "cls null");
        return false;
    }
    ani_status status = ANI_OK;
    std::call_once(g_bindNativeMethodsFlag, [&status, env, cls]() {
        std::array functions = {
            ani_native_function { "nativeReleaseSync", nullptr,
                reinterpret_cast<void*>(EtsCallerComplex::ReleaseCall) },
            ani_native_function { "nativeOnReleaseSync", "Lcaller/Caller/ReleaseCallback;:V",
                reinterpret_cast<void*>(EtsCallerComplex::SetOnRelease) },
            ani_native_function { "nativeOnRemoteStateChangeSync", "Lstd/core/Function1;:V",
                reinterpret_cast<void*>(EtsCallerComplex::SetOnRemoteStateChange) },
        };

        status = env->Class_BindNativeMethods(cls, functions.data(), functions.size());
    });
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "status: %{public}d", status);
        return false;
    }
    return true;
}
} // nameless

namespace OHOS {
namespace AbilityRuntime {
ani_object CreateEtsCaller(ani_env *env, ReleaseCallFunc releaseCallFunc,
    sptr<IRemoteObject> callee, std::shared_ptr<CallerCallBack> callback)
{
    ani_class cls {};
    ani_status status = ANI_ERROR;
    ani_object callerObj = nullptr;
    ani_method method {};

    if ((status = env->FindClass("Lcaller/Caller/CallerImpl;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if (!BindNativeMethods(env, cls)) {
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &callerObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "status : %{public}d", status);
        return nullptr;
    }
    auto etsCaller = new (std::nothrow) EtsCallerComplex(releaseCallFunc, callback);
    if (etsCaller == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "etsCaller is null");
        return nullptr;
    }
    ani_long nativeCaller = (ani_long)(etsCaller);
    if ((status = env->Object_SetFieldByName_Long(callerObj, "nativeCaller", nativeCaller)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "status : %{public}d", status);
        delete etsCaller;
        return nullptr;
    }
    auto remoteObj = AniCreateRemoteObj(env, callee);
    if ((status = env->Object_SetFieldByName_Ref(callerObj, "callee", remoteObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "status : %{public}d", status);
        delete etsCaller;
        return nullptr;
    }
    return callerObj;
}

ani_object CreateEtsCallee(ani_env *env)
{
    ani_class cls {};
    ani_status status = ANI_ERROR;
    ani_object calleeObj = nullptr;
    ani_method method {};

    if ((status = env->FindClass("Lcallee/Callee/CalleeImpl;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "CalleeImpl: %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "callee ctor : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Object_New(cls, method, &calleeObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "create callee: %{public}d", status);
        return nullptr;
    }
    return calleeObj;
}
} // namespace AbilityRuntime
} // namespace OHOS