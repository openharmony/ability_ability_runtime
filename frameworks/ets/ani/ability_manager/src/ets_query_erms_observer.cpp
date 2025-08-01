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

#include "ets_query_erms_observer.h"

#include "ets_ability_manager_utils.h"
#include "ets_error_utils.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"


namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *ATOMIC_SERVICE_STARTUP_RULE_IMPL_CLASS_NAME =
    "L@ohos/app/ability/abilityManager/AtomicServiceStartupRuleImpl;";
}
EtsQueryERMSObserver::EtsQueryERMSObserver(ani_vm *etsVm) : etsVm_(etsVm) {}

EtsQueryERMSObserver::~EtsQueryERMSObserver()
{
    ani_env *env = AttachCurrentThread();
    for (auto it = etsObserverObjectList_.begin(); it != etsObserverObjectList_.end();) {
        env->GlobalReference_Delete(it->callback);
        it++;
    }
    DetachCurrentThread();
}

void EtsQueryERMSObserver::OnQueryFinished(const std::string &appId, const std::string &startTime,
    const AtomicServiceStartupRule &rule, int32_t resultCode)
{
    TAG_LOGD(AAFwkTag::QUERY_ERMS, "OnQueryFinished");
    HandleOnQueryFinished(appId, startTime, rule, resultCode);
}

void EtsQueryERMSObserver::HandleOnQueryFinished(const std::string &appId, const std::string &startTime,
    const AtomicServiceStartupRule &rule, int32_t resultCode)
{
    TAG_LOGD(AAFwkTag::QUERY_ERMS, "HandleOnQueryFinished");
    std::vector<ani_object> callbacks;
    {
        std::unique_lock<std::mutex> lock(etsObserverObjectListLock_);
        for (auto it = etsObserverObjectList_.begin(); it != etsObserverObjectList_.end();) {
            if (it->appId != appId || it->startTime != startTime || it->callback == nullptr) {
                it++;
                continue;
            }
            callbacks.emplace_back(it->callback);
            it = etsObserverObjectList_.erase(it);
        }
    }
    for (const auto &callback : callbacks) {
        CallCallback(callback, rule, resultCode);
        FinishAsyncTrace(HITRACE_TAG_ABILITY_MANAGER, "StartQueryERMS", atoi(startTime.c_str()));
    }
}

void EtsQueryERMSObserver::CallCallback(ani_object callback, const AtomicServiceStartupRule &rule, int32_t resultCode)
{
    TAG_LOGD(AAFwkTag::QUERY_ERMS, "CallCallback");
    if (callback == nullptr) {
        TAG_LOGE(AAFwkTag::QUERY_ERMS, "null callback");
        return;
    }
    ani_env *env = AttachCurrentThread();
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::APPMGR, "GetEnv failed");
        return;
    }
    ani_object aniObject = nullptr;
    ani_object ruleObj = nullptr;
    if (resultCode == ERR_OK && WrapAtomicServiceStartupRule(env, rule, ruleObj)) {
        aniObject = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
        AppExecFwk::AsyncCallback(env, callback, aniObject, ruleObj);
        DetachCurrentThread();
        return;
    }
    if (resultCode == ERR_OK) {
        aniObject = EtsErrorUtil::CreateError(env, AbilityErrorCode::ERROR_OK);
    } else {
        aniObject = EtsErrorUtil::CreateErrorByNativeErr(env, resultCode);
    }
    AppExecFwk::AsyncCallback(env, callback, aniObject, nullptr);
    DetachCurrentThread();
}

void EtsQueryERMSObserver::AddEtsObserverObject(const std::string &appId, const std::string &startTime,
    ani_object callback)
{
    TAG_LOGD(AAFwkTag::QUERY_ERMS, "call");
    std::unique_lock<std::mutex> lock(etsObserverObjectListLock_);
    for (auto it = etsObserverObjectList_.begin(); it != etsObserverObjectList_.end(); ++it) {
        if (it->appId == appId && it->startTime == startTime) {
            TAG_LOGW(AAFwkTag::QUERY_ERMS, "The etsObject has been added");
            return;
        }
    }

    StartAsyncTrace(HITRACE_TAG_ABILITY_MANAGER, "StartQueryERMS", atoi(startTime.c_str()));
    EtsQueryERMSObserverObject object;
    object.appId = appId;
    object.startTime = startTime;
    object.callback = reinterpret_cast<ani_object>(callback);

    etsObserverObjectList_.emplace_back(object);
}

bool EtsQueryERMSObserver::WrapAtomicServiceStartupRule(ani_env *env,
    const AbilityRuntime::AtomicServiceStartupRule &rule, ani_object &ruleObj)
{
    TAG_LOGD(AAFwkTag::UIABILITY, "WrapAtomicServiceStartupRule");
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::QUERY_ERMS, "null env");
        return false;
    }
    ani_class cls = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = env->FindClass(ATOMIC_SERVICE_STARTUP_RULE_IMPL_CLASS_NAME, &cls)) != ANI_OK || cls == nullptr) {
        TAG_LOGE(AAFwkTag::QUERY_ERMS, "Find AtomicServiceStartupRuleImpl Class failed");
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK || method == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return false;
    }
    if ((status = env->Object_New(cls, method, &ruleObj)) != ANI_OK || ruleObj == nullptr) {
        TAG_LOGE(AAFwkTag::UIABILITY, "status : %{public}d", status);
        return false;
    }
    if (!env->Object_SetFieldByName_Boolean(ruleObj, "isOpenAllowed", rule.isOpenAllowed)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set isOpenAllowed failed");
        return false;
    }
    if (!env->Object_SetFieldByName_Boolean(ruleObj, "isEmbeddedAllowed", rule.isEmbeddedAllowed)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "set isEmbeddedAllowed failed");
        return false;
    }
    return true;
}

ani_env *EtsQueryERMSObserver::AttachCurrentThread()
{
    ani_env *env = nullptr;
    ani_status status = ANI_ERROR;
    if ((status = etsVm_->GetEnv(ANI_VERSION_1, &env)) == ANI_OK) {
        return env;
    }
    ani_option interopEnabled { "--interop=disable", nullptr };
    ani_options aniArgs { 1, &interopEnabled };
    if ((status = etsVm_->AttachCurrentThread(&aniArgs, ANI_VERSION_1, &env)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::APPMGR, "status: %{public}d", status);
        return nullptr;
    }
    isAttachThread_ = true;
    return env;
}

void EtsQueryERMSObserver::DetachCurrentThread()
{
    if (isAttachThread_) {
        etsVm_->DetachCurrentThread();
        isAttachThread_ = false;
    }
}
} // namespace AbilityRuntime
} // namespace OHOS
