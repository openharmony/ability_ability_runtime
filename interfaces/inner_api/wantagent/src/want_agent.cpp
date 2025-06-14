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

#include "hilog_tag_wrapper.h"
#include "want_agent.h"

namespace OHOS::AbilityRuntime::WantAgent {
bool WantAgent::isMultithreadingSupported_ = false;

WantAgent::WantAgent(const std::shared_ptr<PendingWant> &pendingWant)
{
    pendingWant_ = pendingWant;
}

WantAgent::WantAgent(const std::shared_ptr<LocalPendingWant> &localPendingWant)
{
    localPendingWant_ = localPendingWant;
    isLocal_ = true;
}

std::shared_ptr<PendingWant> WantAgent::GetPendingWant()
{
    return pendingWant_;
}

std::shared_ptr<LocalPendingWant> WantAgent::GetLocalPendingWant()
{
    return localPendingWant_;
}

void WantAgent::SetPendingWant(const std::shared_ptr<PendingWant> &pendingWant)
{
    pendingWant_ = pendingWant;
}

bool WantAgent::Marshalling(Parcel &parcel) const
{
    if (!parcel.WriteBool(isLocal_)) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "parcel WriteBool isLocal failed");
        return false;
    }

    if (isLocal_) {
        if (!parcel.WriteParcelable(localPendingWant_.get())) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "parcel WritePracelable localPendingWant failed");
            return false;
        }
    } else {
        if (!parcel.WriteParcelable(pendingWant_.get())) {
            TAG_LOGE(AAFwkTag::WANTAGENT, "parcel WriteParcelable pendingWant failed");
            return false;
        }
    }
    return true;
}

WantAgent *WantAgent::Unmarshalling(Parcel &parcel)
{
    WantAgent *agent = nullptr;
    const auto isLocal = parcel.ReadBool();
    if (isLocal) {
        std::shared_ptr<LocalPendingWant> localPendingWant(parcel.ReadParcelable<LocalPendingWant>());
        agent = new (std::nothrow) WantAgent(localPendingWant);
    } else {
        std::shared_ptr<PendingWant> pendingWant(parcel.ReadParcelable<PendingWant>());
        agent = new (std::nothrow) WantAgent(pendingWant);
    }

    if (agent == nullptr) {
        TAG_LOGE(AAFwkTag::WANTAGENT, "read from parcel failed");
        return nullptr;
    }
    return agent;
}

bool WantAgent::GetIsMultithreadingSupported()
{
    return isMultithreadingSupported_;
}

void WantAgent::SetIsMultithreadingSupported(bool isMultithreadingSupported)
{
    isMultithreadingSupported_ = isMultithreadingSupported;
}

bool WantAgent::IsLocal()
{
    return isLocal_;
}
}  // namespace OHOS::AbilityRuntime::WantAgent
