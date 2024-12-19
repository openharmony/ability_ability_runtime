/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "query_erms_observer_proxy.h"

#include "hilog_tag_wrapper.h"
#include "ipc_types.h"

namespace OHOS {
namespace AbilityRuntime {
QueryERMSObserverProxy::QueryERMSObserverProxy(
    const sptr<IRemoteObject> &impl) : IRemoteProxy<IQueryERMSObserver>(impl)
{}

bool QueryERMSObserverProxy::WriteInterfaceToken(MessageParcel &data)
{
    if (!data.WriteInterfaceToken(QueryERMSObserverProxy::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::QUERY_ERMS, "write interface token failed");
        return false;
    }
    return true;
}

void QueryERMSObserverProxy::OnQueryFinished(const std::string &appId, const std::string &startTime,
    const AtomicServiceStartupRule &rule, int32_t resultCode)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!WriteInterfaceToken(data)) {
        TAG_LOGE(AAFwkTag::QUERY_ERMS, "failed to write token");
        return;
    }

    if (!data.WriteString(appId) || !data.WriteString(startTime) || !data.WriteBool(rule.isOpenAllowed) ||
        !data.WriteBool(rule.isEmbeddedAllowed) || !data.WriteInt32(resultCode)) {
        TAG_LOGE(AAFwkTag::QUERY_ERMS, "params is wrong");
        return;
    }

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TAG_LOGE(AAFwkTag::QUERY_ERMS, "remote is null");
        return;
    }
    int32_t ret = remote->SendRequest(IQueryERMSObserver::ON_QUERY_FINISHED, data, reply, option);
    if (ret != NO_ERROR) {
        TAG_LOGE(AAFwkTag::QUERY_ERMS, "error code: %{public}d", ret);
    }
}
} // namespace AbilityRuntime
} // namespace OHOS