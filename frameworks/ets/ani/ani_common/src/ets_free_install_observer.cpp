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

#include "ets_free_install_observer.h"

#include "ability_business_error.h"
#include "ani_common_ability_result.h"
#include "ani_common_util.h"
#include "ani_common_want.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"

namespace OHOS {
namespace AbilityRuntime {
EtsFreeInstallObserver::EtsFreeInstallObserver(ani_vm *etsVm) : etsVm_(etsVm) {}

EtsFreeInstallObserver::~EtsFreeInstallObserver()
{
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    ani_option interopEnabled { "--interop=disable", nullptr };
    ani_options aniArgs { 1, &interopEnabled };
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "null etsVm_");
        return;
    }
    if ((etsVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "status: %{public}d", status);
        return;
    }
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "null env");
        return;
    }
    for (auto it = etsObserverObjectList_.begin(); it != etsObserverObjectList_.end();) {
        env->GlobalReference_Delete(it->callback);
        it++;
    }
    if ((status = etsVm_->DetachCurrentThread()) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "status: %{public}d", status);
    }
}

void EtsFreeInstallObserver::OnInstallFinished(
    const std::string &bundleName, const std::string &abilityName, const std::string &startTime, int32_t resultCode)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "OnInstallFinished");
    HandleOnInstallFinished(bundleName, abilityName, startTime, resultCode);
}

void EtsFreeInstallObserver::OnInstallFinished(const std::string &bundleName, const std::string &abilityName,
    const std::string &startTime, ani_object abilityResult)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "OnInstallFinished");
    std::vector<ani_object> callbacks;
    {
        std::unique_lock<std::mutex> lock(etsObserverObjectListLock_);
        for (auto it = etsObserverObjectList_.begin(); it != etsObserverObjectList_.end();) {
            if ((it->bundleName != bundleName) || (it->abilityName != abilityName) || (it->startTime != startTime)
                || (it->callback == nullptr) || (!it->isAbilityResult)) {
                it++;
                continue;
            }
            callbacks.emplace_back(it->callback);
            it = etsObserverObjectList_.erase(it);
            TAG_LOGD(AAFwkTag::FREE_INSTALL, "etsObserverObjectList_ size:%{public}zu", etsObserverObjectList_.size());
        }
    }

    for (auto& callback : callbacks) {
        CallCallback(callback, abilityResult);
        FinishAsyncTrace(HITRACE_TAG_ABILITY_MANAGER, "StartFreeInstall", atoi(startTime.c_str()));
    }
}

void EtsFreeInstallObserver::OnInstallFinishedByUrl(
    const std::string &startTime, const std::string &url, int32_t resultCode)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "OnInstallFinishedByUrl");
    HandleOnInstallFinishedByUrl(startTime, url, resultCode);
}

void EtsFreeInstallObserver::HandleOnInstallFinished(
    const std::string &bundleName, const std::string &abilityName, const std::string &startTime, int32_t resultCode)
{
    std::vector<ani_object> callbacks;
    {
        std::unique_lock<std::mutex> lock(etsObserverObjectListLock_);
        for (auto it = etsObserverObjectList_.begin(); it != etsObserverObjectList_.end();) {
            if ((it->bundleName != bundleName) || (it->abilityName != abilityName) || (it->startTime != startTime) ||
                (it->callback == nullptr) || (it->isAbilityResult && resultCode == ERR_OK)) {
                it++;
                continue;
            }
            callbacks.emplace_back(it->callback);
            it = etsObserverObjectList_.erase(it);
        }
    }

    for (auto& callback : callbacks) {
        CallCallback(callback, resultCode);
        FinishAsyncTrace(HITRACE_TAG_ABILITY_MANAGER, "StartFreeInstall", atoi(startTime.c_str()));
    }
}

void EtsFreeInstallObserver::HandleOnInstallFinishedByUrl(
    const std::string &startTime, const std::string &url, int32_t resultCode)
{
    std::vector<ani_object> callbacks;
    {
        std::unique_lock<std::mutex> lock(etsObserverObjectListLock_);
        for (auto it = etsObserverObjectList_.begin(); it != etsObserverObjectList_.end();) {
            if ((it->startTime != startTime) || (it->url != url) || (it->callback == nullptr)) {
                it++;
                continue;
            }
            callbacks.emplace_back(it->callback);
            it = etsObserverObjectList_.erase(it);
        }
    }

    for (auto& callback : callbacks) {
        CallCallback(callback, resultCode);
        FinishAsyncTrace(HITRACE_TAG_ABILITY_MANAGER, "StartFreeInstall", atoi(startTime.c_str()));
    }
}

void EtsFreeInstallObserver::CallCallback(ani_object callback, int32_t resultCode)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "CallCallback");
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "null callback");
        return;
    }
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "null etsVm");
        return;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    ani_option interopEnabled { "--interop=disable", nullptr };
    ani_options aniArgs { 1, &interopEnabled };
    bool attachFlag = true;
    if ((status = etsVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env)) != ANI_OK || env == nullptr) {
        attachFlag = false;
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "Failed to getEnv, status: %{public}d", status);
        if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) != ANI_OK || env == nullptr) {
            TAG_LOGE(AAFwkTag::FREE_INSTALL, "Failed to getEnv, status: %{public}d", status);
            return;
        }
    }
    ani_object aniObject = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    if (resultCode != ERR_OK) {
        aniObject = EtsErrorUtil::CreateErrorByNativeErr(env, resultCode);
    }
    AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
    env->GlobalReference_Delete(callback);
    if (attachFlag && (status = etsVm_->DetachCurrentThread()) != ANI_OK) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "status: %{public}d", status);
    }
}

void EtsFreeInstallObserver::CallCallback(ani_object callback, ani_object abilityResult)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "CallCallback");
    if (abilityResult == nullptr) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "null abilityResult");
        return;
    }
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "null callback");
        return;
    }
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "null etsVm");
        return;
    }
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) != ANI_OK || env == nullptr) {
        TAG_LOGE(AAFwkTag::FREE_INSTALL, "Failed to getEnv, status: %{public}d", status);
    }
    ani_object aniObject = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    AppExecFwk::AsyncCallback(env, callback, aniObject, abilityResult);
    env->GlobalReference_Delete(callback);
}

void EtsFreeInstallObserver::AddEtsObserverObject(ani_env *env, const std::string &bundleName,
    const std::string &abilityName, const std::string &startTime, ani_object callback, bool isAbilityResult)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "AddEtsObserverObject");
    {
        std::unique_lock<std::mutex> lock(etsObserverObjectListLock_);
        for (auto it = etsObserverObjectList_.begin(); it != etsObserverObjectList_.end(); ++it) {
            if (it->bundleName == bundleName && it->abilityName == abilityName && it->startTime == startTime) {
                TAG_LOGW(AAFwkTag::FREE_INSTALL, "The EtsFreeInstallObserverObject has been added");
                return;
            }
        }
    }
    StartAsyncTrace(HITRACE_TAG_ABILITY_MANAGER, "StartFreeInstall", atoi(startTime.c_str()));
    EtsFreeInstallObserverObject object;
    object.bundleName = bundleName;
    object.abilityName = abilityName;
    object.startTime = startTime;
    object.isAbilityResult = isAbilityResult;
    AddEtsObserverCommon(env, object, callback);
}

void EtsFreeInstallObserver::AddEtsObserverObject(
    ani_env *env, const std::string &startTime, const std::string &url, ani_object callback, bool isAbilityResult)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "AddEtsObserverObject");
    {
        std::unique_lock<std::mutex> lock(etsObserverObjectListLock_);
        for (auto it = etsObserverObjectList_.begin(); it != etsObserverObjectList_.end(); ++it) {
            if (it->startTime == startTime && it->url == url) {
                TAG_LOGW(AAFwkTag::FREE_INSTALL, "add etsObject");
                return;
            }
        }
    }
    StartAsyncTrace(HITRACE_TAG_ABILITY_MANAGER, "StartFreeInstall", atoi(startTime.c_str()));
    EtsFreeInstallObserverObject object;
    object.url = url;
    object.startTime = startTime;
    object.isAbilityResult = isAbilityResult;
    AddEtsObserverCommon(env, object, callback);
}

void EtsFreeInstallObserver::AddEtsObserverCommon(
    ani_env *env, EtsFreeInstallObserverObject &object, ani_object callback)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "AddEtsObserverCommon");
    std::unique_lock<std::mutex> lock(etsObserverObjectListLock_);
    ani_ref global = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GlobalReference_Create(callback, &global)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "status: %{public}d", status);
        return;
    }
    object.callback = reinterpret_cast<ani_object>(global);
    etsObserverObjectList_.emplace_back(object);
}
} // namespace AbilityRuntime
} // namespace OHOS