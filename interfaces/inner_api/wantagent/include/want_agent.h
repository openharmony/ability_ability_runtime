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

#ifndef OHOS_ABILITY_RUNTIME_WANT_AGENT_H
#define OHOS_ABILITY_RUNTIME_WANT_AGENT_H

#include <string>
#include <memory>
#include "local_pending_want.h"
#include "parcel.h"
#include "pending_want.h"
#include "want.h"
#include "want_params.h"

namespace OHOS::AbilityRuntime::WantAgent {
class WantAgent final : public std::enable_shared_from_this<WantAgent>, public Parcelable {
public:
    WantAgent() {};
    virtual ~WantAgent() = default;
    /**
     * Constructor.
     *
     * @param obj The proxy object.
     */
    explicit WantAgent(const std::shared_ptr<PendingWant> &pendingWant);

    /**
     * Constructor.
     *
     * @param obj The proxy object.
     */
    explicit WantAgent(const std::shared_ptr<LocalPendingWant> &localPendingWant);

    /**
     * Gets proxy obj.
     *
     * @return Return obj.
     */
    std::shared_ptr<PendingWant> GetPendingWant();

    /**
     * Gets proxy obj.
     *
     * @return Return obj.
     */
    std::shared_ptr<LocalPendingWant> GetLocalPendingWant();

    /**
     * Sets proxy obj.
     *
     * @param obj The proxy object.
     */
    void SetPendingWant(const std::shared_ptr<PendingWant> &pendingWant);

    /**
     * @description: Marshals a Want into a Parcel.
     * Fields in the Want are marshalled separately. If any field fails to be marshalled, false is returned.
     * @param parcel Indicates the Parcel object for marshalling.
     * @return Returns true if the marshalling is successful; returns false otherwise.
     */
    virtual bool Marshalling(Parcel &parcel) const;

    /**
     * @description: Unmarshals a Want from a Parcel.
     * Fields in the Want are unmarshalled separately. If any field fails to be unmarshalled, false is returned.
     * @param parcel Indicates the Parcel object for unmarshalling.
     * @return Returns true if the unmarshalling is successful; returns false otherwise.
     */
    static WantAgent *Unmarshalling(Parcel &parcel);

    /**
     * Get isMultithreadingSupported_
     *
     * @return Return isMultithreadingSupported_
     */
    static bool GetIsMultithreadingSupported();

    /**
     * Set isMultithreadingSupported_
     *
     * @param isMultithreadingSupported Indicates the WantAgent support multithreading or not.
     */
    static void SetIsMultithreadingSupported(bool isMultithreadingSupported);

    bool IsLocal();

private:
    std::shared_ptr<LocalPendingWant> localPendingWant_;
    bool isLocal_ = false;
    std::shared_ptr<PendingWant> pendingWant_;
    static bool isMultithreadingSupported_;
};
}  // namespace OHOS::AbilityRuntime::WantAgent
#endif  // OHOS_ABILITY_RUNTIME_WANT_AGENT_H
