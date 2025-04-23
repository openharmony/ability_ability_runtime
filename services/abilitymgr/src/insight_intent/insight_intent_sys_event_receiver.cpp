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

#include "insight_intent_sys_event_receiver.h"

#include "extract_insight_intent_profile.h"
#include "common_event_support.h"
#include "hilog_tag_wrapper.h"
#include "task_handler_wrap.h"
#include "os_account_manager_wrapper.h"
#include "in_process_call_wrapper.h"
#include "ability_util.h"
#include "bundle_mgr_helper.h"
#include "insight_intent_db_cache.h"

namespace OHOS {
namespace AbilityRuntime {
constexpr const char* INSIGHT_INTENT_SYS_EVENT_RECERVER = "InsightIntentSysEventReceiver";
const int32_t MAIN_USER_ID = 100;

InsightIntentSysEventReceiver::InsightIntentSysEventReceiver(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
    : EventFwk::CommonEventSubscriber(subscribeInfo)
{
    taskHandler_ = AAFwk::TaskHandlerWrap::CreateQueueHandler(INSIGHT_INTENT_SYS_EVENT_RECERVER);
}

void InsightIntentSysEventReceiver::SaveInsightIntentInfos(const std::string &bundleName, const std::string &moduleName,
    int32_t userId)
{
    TAG_LOGI(AAFwkTag::INTENT, "save insight intent infos, bundle:%{public}s module:%{public}s",
        bundleName.c_str(), moduleName.c_str());
    ErrCode ret;
    auto bundleMgrHelper = DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance();
    if (bundleMgrHelper == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null bundleMgrHelper");
        return;
    }

    // Get json profile firstly
    std::string profile;
    ret = IN_PROCESS_CALL(bundleMgrHelper->GetJsonProfile(AppExecFwk::INSIGHT_INTENT_PROFILE, bundleName,
        moduleName, profile, AppExecFwk::OsAccountManagerWrapper::GetCurrentActiveAccountId()));
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "GetJsonProfile failed, code: %{public}d", ret);
        return;
    }

    // Transform json string
    AbilityRuntime::ExtractInsightIntentProfileInfoVec infos = {};
    if (!AbilityRuntime::ExtractInsightIntentProfile::TransformTo(profile, infos)) {
        TAG_LOGE(AAFwkTag::INTENT, "transform profile failed, profile:%{public}s", profile.c_str());
        return;
    }

    // save database
    ret = DelayedSingleton<AbilityRuntime::InsightIntentDbCache>::GetInstance()->SaveInsightIntentTotalInfo(bundleName,
        moduleName, userId, infos);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "save intent info failed, bundleName: %{public}s, moduleName: %{public}s, "
            "userId: %{public}d", bundleName.c_str(), moduleName.c_str(), userId);
        return;
    }

    TAG_LOGI(AAFwkTag::INTENT, "save intent info success, bundleName: %{public}s, moduleName: %{public}s, "
        "userId: %{public}d", bundleName.c_str(), moduleName.c_str(), userId);
}

void InsightIntentSysEventReceiver::LoadInsightIntentInfos(int32_t userId)
{
    std::lock_guard<std::mutex> lock(userIdMutex_);
    if (userId == -1) {
        userId = AppExecFwk::OsAccountManagerWrapper::GetCurrentActiveAccountId();
        if (userId == 0) {
            TAG_LOGI(AAFwkTag::INTENT, "use MAIN_USER_ID(%{public}d) instead of current userId: (%{public}d)",
                     MAIN_USER_ID, userId);
            userId = MAIN_USER_ID;
        }
    }

    TAG_LOGI(AAFwkTag::INTENT, "init insight intent cache start, userId: %{public}d", userId);
    DelayedSingleton<AbilityRuntime::InsightIntentDbCache>::GetInstance()->InitInsightIntentCache(userId);
    TAG_LOGI(AAFwkTag::INTENT, "init insight intent cache end, userId: %{public}d", userId);

    auto bundleMgrHelper = DelayedSingleton<AppExecFwk::BundleMgrHelper>::GetInstance();
    if (bundleMgrHelper == nullptr) {
        TAG_LOGE(AAFwkTag::INTENT, "null bundleMgrHelper");
        return;
    }

    std::vector<AppExecFwk::BundleInfo> bundleInfos {};
    if (!IN_PROCESS_CALL(bundleMgrHelper->GetBundleInfos(AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfos,
        userId))) {
        TAG_LOGE(AAFwkTag::INTENT, "get bundle info failed");
        return;
    }

    TAG_LOGI(AAFwkTag::INTENT, "bundleInfos size: %{public}zu", bundleInfos.size());
    for (auto &bundleInfo : bundleInfos) {
        for (const auto &hapInfo : bundleInfo.hapModuleInfos) {
            if (!hapInfo.hasIntent) {
                continue;
            }
            SaveInsightIntentInfos(bundleInfo.name, hapInfo.moduleName, userId);
        }
    }
}

void InsightIntentSysEventReceiver::DeleteInsightIntentInfoByUserId(int32_t userId)
{
    int32_t ret = DelayedSingleton<AbilityRuntime::InsightIntentDbCache>::GetInstance()->DeleteInsightIntentByUserId(
        userId);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::INTENT, "delete insight intent by userId failed, userId: %{public}d, ret: %{public}d",
            userId, ret);
        return;
    }
}

void InsightIntentSysEventReceiver::HandleBundleScanFinished()
{
    CHECK_POINTER(taskHandler_);
    auto task = [self = shared_from_this()]() { self->LoadInsightIntentInfos(); };
    taskHandler_->SubmitTask(task);
}

void InsightIntentSysEventReceiver::HandleUserSwitched(const EventFwk::CommonEventData &data)
{
    int32_t userId = data.GetCode();
    if (userId < 0) {
        TAG_LOGE(AAFwkTag::INTENT, "invalid switched userId: %{public}d", userId);
    }

    std::lock_guard<std::mutex> lock(userIdMutex_);
    if (userId == lastUserId_) {
        TAG_LOGE(AAFwkTag::INTENT, "same userId: %{public}d", lastUserId_);
        return;
    }

    TAG_LOGI(AAFwkTag::INTENT, "userId: %{public}d switch to  current userId: %{public}d", lastUserId_, userId);
    lastUserId_ = userId;

    CHECK_POINTER(taskHandler_);
    auto task = [self = shared_from_this(), userId]() { self->LoadInsightIntentInfos(userId); };
    taskHandler_->SubmitTask(task);
}

void InsightIntentSysEventReceiver::HandleUserRemove(const EventFwk::CommonEventData &data)
{
    int32_t userId = data.GetCode();
    if (userId < 0) {
        TAG_LOGE(AAFwkTag::INTENT, "invalid switched userId: %{public}d", userId);
    }

    std::lock_guard<std::mutex> lock(userIdMutex_);
    if (userId == lastUserId_) {
        TAG_LOGW(AAFwkTag::INTENT, "not allow remove current userId: %{public}d", userId);
        return;
    }

    CHECK_POINTER(taskHandler_);
    auto task = [self = shared_from_this(), userId]() { self->DeleteInsightIntentInfoByUserId(userId); };
    taskHandler_->SubmitTask(task);
}

void InsightIntentSysEventReceiver::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    const AAFwk::Want &want = data.GetWant();
    std::string action = want.GetAction();
    TAG_LOGI(AAFwkTag::INTENT, "the action: %{public}s", action.c_str());

    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED) {
        HandleBundleScanFinished();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        HandleUserSwitched(data);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED) {
        HandleUserRemove(data);
    } else {
        TAG_LOGW(AAFwkTag::INTENT, "invalid action");
    }
}
} // namespace AbilityRuntime
} // namespace OHOS