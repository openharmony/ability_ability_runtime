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

#include "sts_free_install_observer.h"

#include "ability_business_error.h"
#include "ani_common_ability_result.h"
#include "ani_common_configuration.h"
#include "ani_common_start_options.h"
#include "ani_common_want.h"
#include "ani_common_util.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"

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

void StsFreeInstallObserver::OnInstallFinishedByUrl(const std::string &startTime, const std::string& url,
    const int &resultCode)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "call");
    HandleOnInstallFinishedByUrl(startTime, url, resultCode);
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

void StsFreeInstallObserver::HandleOnInstallFinishedByUrl(const std::string &startTime, const std::string& url,
    const int &resultCode)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "call");
    std::vector<ani_object> callbacks;
    {
        std::unique_lock<std::mutex> lock(stsObserverObjectListLock_);
        for (auto it = stsObserverObjectList_.begin(); it != stsObserverObjectList_.end();) {
            if ((it->startTime != startTime) || (it->url != url)) {
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
    ani_object aniObject = CreateStsError(env, AbilityErrorCode::ERROR_OK);
    if (resultCode != ERR_OK) {
        aniObject = CreateStsErrorByNativeErr(env, resultCode);
    }
    AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
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

void StsFreeInstallObserver::AddStsObserverObject(ani_env *env, const std::string &startTime,
    const std::string &url, ani_object callBack)
{
    TAG_LOGD(AAFwkTag::FREE_INSTALL, "call");
    {
        std::unique_lock<std::mutex> lock(stsObserverObjectListLock_);
        for (auto it = stsObserverObjectList_.begin(); it != stsObserverObjectList_.end(); ++it) {
            if (it->startTime == startTime && it->url == url) {
                TAG_LOGW(AAFwkTag::FREE_INSTALL, "add stsObject");
                return;
            }
        }
    }
    StartAsyncTrace(HITRACE_TAG_ABILITY_MANAGER, "StartFreeInstall", atoi(startTime.c_str()));
    StsFreeInstallObserverObject object;
    object.url = url;
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