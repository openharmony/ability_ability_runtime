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

#include "data_ability_observer_stub.h"

#include "hilog_wrapper.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AAFwk {

const DataAbilityObserverStub::RequestFuncType DataAbilityObserverStub::HANDLES[TRANS_BUTT] = {
    &DataAbilityObserverStub::OnChangeInner,
    &DataAbilityObserverStub::OnChangeExtInner,
};

DataAbilityObserverStub::DataAbilityObserverStub() {}

DataAbilityObserverStub::~DataAbilityObserverStub() {}

int DataAbilityObserverStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    HILOG_DEBUG("cmd = %{public}d, flags= %{public}d,callingPid:%{public}u", code, option.GetFlags(),
        IPCSkeleton::GetCallingPid());
    std::u16string descriptor = DataAbilityObserverStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOG_ERROR("local descriptor is not equal to remote");
        return ERR_INVALID_STATE;
    }

    if (code < TRANS_HEAD || code >= TRANS_BUTT || HANDLES[code] == nullptr) {
        HILOG_ERROR("not support code:%u, BUTT:%d", code, TRANS_BUTT);
        return -1;
    }
    return (this->*HANDLES[code])(data, reply);
}

/**
 * @brief Called back to notify that the data being observed has changed.
 *
 * @return Returns 0 on success, others on failure.
 */
int32_t DataAbilityObserverStub::OnChangeInner(MessageParcel &data, MessageParcel &reply)
{
    OnChange();
    return ERR_NONE;
}

/**
 * @brief Called back to notify that the data being observed has changed.
 *
 * @return Returns 0 on success, others on failure.
 */
int32_t DataAbilityObserverStub::OnChangeExtInner(MessageParcel &data, MessageParcel &reply)
{
    std::list<Uri> uris;
    int32_t size = data.ReadInt32();
    if (size < 0) {
        HILOG_WARN("size = %{public}d", size);
        return IPC_STUB_INVALID_DATA_ERR;
    }

    Uri *uri = nullptr;
    for (int32_t i = 0; i < size; i++) {
        uri = data.ReadParcelable<Uri>();
        if (uri == nullptr) {
            HILOG_ERROR("uri is nullptr");
            return IPC_STUB_INVALID_DATA_ERR;
        }
        uris.emplace_back(*uri);
    }
    OnChangeExt(uris);
    return ERR_NONE;
}

void DataObsCallbackRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    HILOG_WARN("recv DataObsCallbackRecipient death notice");

    if (handler_) {
        handler_(remote);
    }
}

DataObsCallbackRecipient::DataObsCallbackRecipient(RemoteDiedHandler handler) : handler_(handler) {}

DataObsCallbackRecipient::~DataObsCallbackRecipient() {}
}  // namespace AAFwk
}  // namespace OHOS
