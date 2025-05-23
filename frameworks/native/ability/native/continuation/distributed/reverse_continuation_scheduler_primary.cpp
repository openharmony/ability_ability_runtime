/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "reverse_continuation_scheduler_primary.h"
#include "continuation_handler.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
ReverseContinuationSchedulerPrimary::ReverseContinuationSchedulerPrimary(
    const std::weak_ptr<IReverseContinuationSchedulerPrimaryHandler> &continuationHandler,
    const std::shared_ptr<AbilityHandler> &mainHandler)
    : continuationHandler_(continuationHandler), mainHandler_(mainHandler)
{}

/**
 * @brief Replica call this method when it terminated.
 */
void ReverseContinuationSchedulerPrimary::NotifyReplicaTerminated()
{
    auto task = [reverseContinuationSchedulerPrimary = this]() {
        reverseContinuationSchedulerPrimary->HandlerNotifyReplicaTerminated();
    };

    if (mainHandler_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTINUATION, "null mainHandler_");
        return;
    }

    bool ret = mainHandler_->PostTask(task);
    if (!ret) {
        TAG_LOGE(AAFwkTag::CONTINUATION, "PostTask error");
        return;
    }
}

/**
 * @brief Replica call this method to notify primary go on.
 *
 * @param want Contains data to be restore.
 * @return True if success, otherwise false.
 */
bool ReverseContinuationSchedulerPrimary::ContinuationBack(const AAFwk::Want &want)
{
    auto task = [reverseContinuationSchedulerPrimary = this, want]() {
        reverseContinuationSchedulerPrimary->HandlerContinuationBack(want);
    };

    if (mainHandler_ == nullptr) {
        TAG_LOGE(AAFwkTag::CONTINUATION, "null mainHandler_");
        return false;
    }

    bool ret = mainHandler_->PostTask(task);
    if (!ret) {
        TAG_LOGE(AAFwkTag::CONTINUATION, "PostTask error");
        return false;
    }
    return true;
}

void ReverseContinuationSchedulerPrimary::HandlerNotifyReplicaTerminated()
{
    std::shared_ptr<IReverseContinuationSchedulerPrimaryHandler> continuationHandler = nullptr;
    continuationHandler = continuationHandler_.lock();
    if (continuationHandler == nullptr) {
        TAG_LOGE(AAFwkTag::CONTINUATION, "null continuationHandler");
        return;
    }
    continuationHandler->NotifyReplicaTerminated();
}

void ReverseContinuationSchedulerPrimary::HandlerContinuationBack(const AAFwk::Want &want)
{
    std::shared_ptr<IReverseContinuationSchedulerPrimaryHandler> continuationHandler = nullptr;
    continuationHandler = continuationHandler_.lock();
    if (continuationHandler == nullptr) {
        TAG_LOGE(AAFwkTag::CONTINUATION, "null continuationHandler");
        return;
    }
    continuationHandler->ContinuationBack(want);
}
}  // namespace AppExecFwk
}  // namespace OHOS
