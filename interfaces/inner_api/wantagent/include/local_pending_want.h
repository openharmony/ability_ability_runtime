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

#ifndef OHOS_ABILITY_RUNTIME_LOCAL_PENDING_WANT_H
#define OHOS_ABILITY_RUNTIME_LOCAL_PENDING_WANT_H

#include <memory>
#include <string>
#include "completed_dispatcher.h"
#include "trigger_info.h"
#include "want.h"

namespace OHOS::AbilityRuntime::WantAgent {
class LocalPendingWant final : public std::enable_shared_from_this<LocalPendingWant>, public Parcelable {
public:
    LocalPendingWant(const std::string &bundleName, const std::shared_ptr<AAFwk::Want> &want,
        int32_t operType);

    std::string GetBundleName() const;

    void SetBundleName(const std::string &bundleName);

    int32_t GetUid() const;

    void SetUid(int32_t uid);

    int32_t GetType() const;

    void SetType(int32_t operType);

    std::shared_ptr<AAFwk::Want> GetWant() const;

    void SetWant(const std::shared_ptr<AAFwk::Want> &want);

    int32_t GetHashCode() const;

    void SetHashCode(int32_t hashCode);

    uint32_t GetTokenId() const;

    void SetTokenId(uint32_t tokenId);

    virtual bool Marshalling(Parcel &parcel) const;

    static LocalPendingWant *Unmarshalling(Parcel &parcel);

    ErrCode Send(const sptr<CompletedDispatcher> &callBack, const TriggerInfo &triggerInfo,
        sptr<IRemoteObject> callerToken);

    static ErrCode IsEquals(const std::shared_ptr<LocalPendingWant> &localPendingWant,
        const std::shared_ptr<LocalPendingWant> &otherLocalPendingWant);

private:
    std::string bundleName_;
    int32_t uid_ = -1;
    int32_t hashCode_ = -1;
    AAFwk::Want want_;
    int32_t operType_ = -1;
    uint32_t tokenId_ = 0;
};
}

#endif /* OHOS_ABILITY_RUNTIME_LOCAL_PENDING_WANT_H */