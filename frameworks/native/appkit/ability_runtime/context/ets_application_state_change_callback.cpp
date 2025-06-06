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

#include "ets_application_state_change_callback.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char* APPLICATION_STATE_CHANGE_CALLBACK =
    "L@ohos/app/ability/ApplicationStateChangeCallback/ApplicationStateChangeCallbackInner;";
}
EtsApplicationStateChangeCallback::EtsApplicationStateChangeCallback(ani_env *env)
    : env_(env)
{
}

void EtsApplicationStateChangeCallback::CallEtsMethod(const std::string &methodName)
{
    TAG_LOGD(AAFwkTag::APPKIT, "MethodName = %{public}s", methodName.c_str());
    if (env_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return;
    }
    ani_class cls {};
    ani_status status = env_->FindClass(APPLICATION_STATE_CHANGE_CALLBACK, &cls);
    if (status != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "FindClass status: %{public}d", status);
        return;
    }
    ani_method method {};
    if ((status = env_->Class_FindMethod(cls, methodName.c_str(), nullptr, &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "Class_FindMethod status: %{public}d", status);
        return;
    }
    std::lock_guard lock(mutex_);
    for (auto &callback : callbacks_) {
        if ((status = env_->Object_CallMethod_Void(reinterpret_cast<ani_object>(callback), method)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::APPKIT, "Object_CallMethod_Void status: %{public}d", status);
        }
    }
}

void EtsApplicationStateChangeCallback::NotifyApplicationForeground()
{
    CallEtsMethod("onApplicationForeground");
}

void EtsApplicationStateChangeCallback::NotifyApplicationBackground()
{
    CallEtsMethod("onApplicationBackground");
}

void EtsApplicationStateChangeCallback::Register(ani_object aniCallback)
{
    if (env_ == nullptr || aniCallback == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env or aniCallback");
        return;
    }
    ani_ref aniCallbackRef = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env_->GlobalReference_Create(aniCallback, &aniCallbackRef)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Create status : %{public}d", status);
        return;
    }
    std::lock_guard lock(mutex_);
    callbacks_.emplace(aniCallbackRef);
}

bool EtsApplicationStateChangeCallback::UnRegister(ani_object aniCallback)
{
    ani_status status = ANI_ERROR;
    std::lock_guard lock(mutex_);
    if (env_ == nullptr) {
        TAG_LOGE(AAFwkTag::APPKIT, "null env");
        return false;
    }
    if (aniCallback == nullptr) {
        TAG_LOGI(AAFwkTag::APPKIT, "null aniCallback");
        for (auto &callback : callbacks_) {
            if (!callback) {
                TAG_LOGE(AAFwkTag::APPKIT, "Invalid aniCallback");
                continue;
            }
            if ((status = env_->GlobalReference_Delete(callback)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Delete status: %{public}d", status);
            }
        }
        callbacks_.clear();
        return true;
    }
    for (auto &callback : callbacks_) {
        if (!callback) {
            TAG_LOGE(AAFwkTag::APPKIT, "Invalid aniCallback");
            continue;
        }
        ani_boolean isEqual = false;
        env_->Reference_StrictEquals(aniCallback, callback, &isEqual);
        if (isEqual) {
            if ((status = env_->GlobalReference_Delete(callback)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::APPKIT, "GlobalReference_Delete status: %{public}d", status);
                return false;
            }
            return callbacks_.erase(callback) == 1;
        }
    }
    return false;
}

bool EtsApplicationStateChangeCallback::IsEmpty() const
{
    std::lock_guard lock(mutex_);
    return callbacks_.empty();
}
} // namespace AbilityRuntime
} // namespace OHOS
