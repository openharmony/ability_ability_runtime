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
#include "ability_business_error.h"
#include "ani_common_ability_result.h"
#include "ani_common_configuration.h"
#include "ani_common_start_options.h"
#include "ani_common_want.h"
#include "common_fun_ani.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "sts_free_install_observer.h"

namespace OHOS {
namespace AbilityRuntime {
StsFreeInstallObserver::StsFreeInstallObserver(ani_vm *etsVm) : etsVm_(etsVm) {}

StsFreeInstallObserver::~StsFreeInstallObserver() = default;

void StsFreeInstallObserver::OnInstallFinished(
    const std::string &bundleName, const std::string &abilityName, const std::string &startTime, const int &resultCode)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "call");
    HandleOnInstallFinished(bundleName, abilityName, startTime, resultCode);
}
void StsFreeInstallObserver::HandleOnInstallFinished(
    const std::string &bundleName, const std::string &abilityName, const std::string &startTime, const int &resultCode)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "call");
    std::vector<ani_object> callbacks;
    {
        std::unique_lock<std::mutex> lock(stsObserverObjectListLock_);
        for (auto it = stsObserverObjectList_.begin(); it != stsObserverObjectList_.end();) {
            if ((it->bundleName != bundleName) || (it->abilityName != abilityName) || (it->startTime != startTime)) {
                it++;
                continue;
            }
            if (it->callBack == nullptr) {
                it++;
                continue;
            }
            callbacks.emplace_back(it->callBack);
            it = stsObserverObjectList_.erase(it);
        }
    }

    for (auto callback : callbacks) {
        CallCallback(callback, resultCode);
        FinishAsyncTrace(HITRACE_TAG_ABILITY_MANAGER, "StartFreeInstall", atoi(startTime.c_str()));
    }
}
void StsFreeInstallObserver::CallCallback(ani_object callback, int32_t resultCode)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "call");
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "callback is nullptr.");
        return;
    }
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "etsVm_ is nullptr.");
        return;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    ani_option interopEnabled { "--interop=disable", nullptr };
    ani_options aniArgs { 1, &interopEnabled };
    if ((etsVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::STSRUNTIME, "status : %{public}d", status);
    }
    AsyncCallback(env, callback, WrapBusinessError(env, resultCode), nullptr);
}

bool StsFreeInstallObserver::AsyncCallback(ani_env *env, ani_object call, ani_object error, ani_object result)
{
    ani_status status = ANI_ERROR;
    ani_class clsCall {};

    if ((status = env->FindClass("Lapplication/UIAbilityContext/AsyncCallbackWrapper;", &clsCall)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return false;
    }
    ani_method method {};
    if ((status = env->Class_FindMethod(clsCall, "invoke", "L@ohos/base/BusinessError;Lstd/core/Object;:V", &method)) !=
        ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return false;
    }
    if (result == nullptr) {
        ani_ref nullRef = nullptr;
        env->GetNull(&nullRef);
        result = reinterpret_cast<ani_object>(nullRef);
    }
    if ((status = env->Object_CallMethod_Void(call, method, error, result)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return false;
    }
    return true;
}

ani_object StsFreeInstallObserver::WrapError(ani_env *env, const std::string &msg)
{
    ani_class cls {};
    ani_method method {};
    ani_object obj = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return nullptr;
    }
    ani_string aniMsg = AppExecFwk::GetAniString(env, msg);

    ani_ref undefRef;
    env->GetUndefined(&undefRef);

    if ((status = env->FindClass("Lescompat/Error;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "Lstd/core/String;Lescompat/ErrorOptions;:V", &method)) !=
        ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }

    if ((status = env->Object_New(cls, method, &obj, aniMsg, undefRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    return obj;
}

std::string StsFreeInstallObserver::GetErrMsg(int32_t err, const std::string &permission)
{
    auto errCode = GetJsErrorCodeByNativeError(err);
    auto errMsg = (errCode == AbilityErrorCode::ERROR_CODE_PERMISSION_DENIED && !permission.empty())
                      ? GetNoPermissionErrorMsg(permission)
                      : GetErrorMsg(errCode);
    return errMsg;
}

ani_object StsFreeInstallObserver::WrapBusinessError(ani_env *env, int32_t resultCode)
{
    ani_class cls {};
    ani_method method {};
    ani_object obj = nullptr;
    ani_status status = ANI_ERROR;
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "null env");
        return nullptr;
    }
    if ((status = env->FindClass("L@ohos/base/BusinessError;", &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    if ((status = env->Class_FindMethod(cls, "<ctor>", "DLescompat/Error;:V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    ani_object error = WrapError(env, GetErrMsg(resultCode));
    if (error == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "error nulll");
        return nullptr;
    }
    ani_double dCode(resultCode);
    if ((status = env->Object_New(cls, method, &obj, dCode, error)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return nullptr;
    }
    return obj;
}

void StsFreeInstallObserver::AddStsObserverObject(ani_env *env, const std::string &bundleName,
    const std::string &abilityName, const std::string &startTime, ani_object callBack)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "call");
    {
        std::unique_lock<std::mutex> lock(stsObserverObjectListLock_);
        for (auto it = stsObserverObjectList_.begin(); it != stsObserverObjectList_.end(); ++it) {
            if (it->bundleName == bundleName && it->abilityName == abilityName && it->startTime == startTime) {
                TAG_LOGW(AAFwkTag::FREE_INSTALL, "The StsFreeInstallObserverObject has been added");
                return;
            }
        }
    }
    StartAsyncTrace(HITRACE_TAG_ABILITY_MANAGER, "StartFreeInstall", atoi(startTime.c_str()));
    StsFreeInstallObserverObject object;
    object.bundleName = bundleName;
    object.abilityName = abilityName;
    object.startTime = startTime;
    AddStsObserverCommon(env, object, callBack);
}
void StsFreeInstallObserver::AddStsObserverCommon(
    ani_env *env, StsFreeInstallObserverObject &object, ani_object callBack)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "call");
    std::unique_lock<std::mutex> lock(stsObserverObjectListLock_);
    ani_ref global = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GlobalReference_Create(callBack, &global)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status : %{public}d", status);
        return;
    }
    object.callBack = reinterpret_cast<ani_object>(global);
    stsObserverObjectList_.emplace_back(object);
}
} // namespace AbilityRuntime
} // namespace OHOS