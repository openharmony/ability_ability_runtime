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

#include "ets_start_abilities_observer.h"

#include "ani_common_util.h"
#include "errors.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
EtsStartAbilitiesObserver& EtsStartAbilitiesObserver::GetInstance()
{
    static EtsStartAbilitiesObserver instance;
    return instance;
}

EtsStartAbilitiesObserver::~EtsStartAbilitiesObserver()
{
    ani_env *env = nullptr;
    if (etsVm_ == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "null etsVm_");
        return;
    }

    bool isAttachThread = false;
    env = AppExecFwk::AttachAniEnv(etsVm_, isAttachThread);
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "null env");
        return;
    }

    {
        std::lock_guard lock(etsObserverObjectListLock_);
        for (auto it = etsObserverObjectList_.begin(); it != etsObserverObjectList_.end(); it++) {
            env->GlobalReference_Delete(it->second);
        }
    }

    AppExecFwk::DetachAniEnv(etsVm_, isAttachThread);
}

void EtsStartAbilitiesObserver::AddObserver(ani_env *env, const std::string &requestKey, ani_object callback)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "null env");
        return;
    }

    {
        std::lock_guard lock(etsVmLock_);
        if (etsVm_ == nullptr) {
            ani_status status = ANI_ERROR;
            if ((status = env->GetVM(&etsVm_)) != ANI_OK || etsVm_ == nullptr) {
                TAG_LOGE(AAFwkTag::ABILITY, "status: %{public}d", status);
                return;
            }
        }
    }

    ani_ref global = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->GlobalReference_Create(callback, &global)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::ABILITY, "status: %{public}d", status);
        return;
    }
    std::lock_guard lock(etsObserverObjectListLock_);
    etsObserverObjectList_.emplace(requestKey, global);
}

void EtsStartAbilitiesObserver::HandleFinished(const std::string &requestKey, int32_t resultCode)
{
    EtsStartAbilitiesObserver::GetInstance().HandleFinishedInner(requestKey, resultCode);
}

void EtsStartAbilitiesObserver::HandleFinishedInner(const std::string &requestKey, int32_t resultCode)
{
    ani_ref callbackRef = nullptr;
    {
        std::lock_guard lock(etsObserverObjectListLock_);
        auto it = etsObserverObjectList_.find(requestKey);
        if (it != etsObserverObjectList_.end()) {
            callbackRef = std::move(it->second);
            etsObserverObjectList_.erase(it);
        }
    }
    if (callbackRef) {
        CallCallback(static_cast<ani_object>(callbackRef), resultCode);
        return;
    }
    TAG_LOGE(AAFwkTag::ABILITY, "null callback");
}

void EtsStartAbilitiesObserver::CallCallback(ani_object callback, int32_t resultCode)
{
    TAG_LOGD(AAFwkTag::ABILITY, "CallCallback");
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "null callback");
        return;
    }

    ani_env *env = nullptr;
    {
        std::lock_guard lock(etsVmLock_);
        if (etsVm_ == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITY, "null etsVm");
            return;
        }
        ani_status status = ANI_ERROR;
        if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) != ANI_OK || env == nullptr) {
            TAG_LOGE(AAFwkTag::ABILITY, "Failed to getEnv, status: %{public}d", status);
            return;
        }
    }
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITY, "null env");
        return;
    }

    ani_object aniObject = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    if (resultCode != ERR_OK) {
        aniObject = EtsErrorUtil::CreateErrorByNativeErr(env, resultCode);
    }
    AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
    env->GlobalReference_Delete(callback);
}

__attribute__((visibility("default"))) extern "C" void OHOS_ETS_START_ABILITIES_OBSERVER_HANDLE_FINISH(
    const std::string &requestKey, int32_t resultCode)
{
    OHOS::AbilityRuntime::EtsStartAbilitiesObserver::HandleFinished(requestKey, resultCode);
}

} // namespace AbilityRuntime
} // namespace OHOS