/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "completed_dispatcher.h"

namespace OHOS::AbilityRuntime::WantAgent {
CompletedDispatcher::CompletedDispatcher()
{}

CompletedDispatcher::CompletedDispatcher(const std::shared_ptr<PendingWant> &pendingWant,
    const std::shared_ptr<CompletedCallback> &callback, const std::shared_ptr<AppExecFwk::EventHandler> &handler)
    : pendingWant_(pendingWant), callback_(callback), handler_(handler)
{}

void CompletedDispatcher::Send(const int32_t resultCode)
{}

CompletedDispatcher &CompletedDispatcher::operator=(const CompletedDispatcher &other)
{
    if (this != &other) {
        pendingWant_ = other.pendingWant_;
        want_ = other.want_;
        resultCode_ = other.resultCode_;
        resultData_ = other.resultData_;
        resultExtras_ = other.resultExtras_;
    }
    return *this;
}

void CompletedDispatcher::PerformReceive(const AAFwk::Want &want, int resultCode, const std::string &data,
    const AAFwk::WantParams &extras, bool serialized, bool sticky, int sendingUser)
{
    want_ = want;
    resultCode_ = resultCode;
    resultData_ = data;
    resultExtras_ = extras;
    if (handler_ == nullptr) {
        Run();
    }
}

void CompletedDispatcher::Run()
{
    if (callback_ != nullptr) {
        callback_->OnSendFinished(want_, resultCode_, resultData_, resultExtras_);
    }
}

int CompletedDispatcher::GetResultCode() const
{
    return resultCode_;
}

std::string CompletedDispatcher::GetResultData() const
{
    return resultData_;
}

AAFwk::Want CompletedDispatcher::GetWant() const
{
    return want_;
}

AAFwk::WantParams CompletedDispatcher::GetResultExtras() const
{
    return resultExtras_;
}

std::shared_ptr<PendingWant> CompletedDispatcher::GetPendingWant() const
{
    return pendingWant_;
}
}  // namespace OHOS::AbilityRuntime::WantAgent
