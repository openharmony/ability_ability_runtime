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

#include "sa_interceptor_stub.h"

#include "ability_manager_errors.h"
#include "hilog_tag_wrapper.h"
#include "ipc_types.h"
#include "iremote_object.h"

namespace OHOS {
namespace AbilityRuntime {
SAInterceptorStub::SAInterceptorStub() {}

SAInterceptorStub::~SAInterceptorStub() {}

int32_t SAInterceptorStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
    std::u16string descriptor = SAInterceptorStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "invalid descriptor");
        return AAFwk::ERR_SA_INTERCEPTOR_DESCRIPTOR_MISMATCH;
    }

    if (code == static_cast<uint32_t>(ISAInterceptor::SAInterceptorCmd::ON_DO_CHECK_STARTING)) {
        return HandleOnCheckStarting(data, reply);
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t SAInterceptorStub::HandleOnCheckStarting(MessageParcel &data, MessageParcel &reply)
{
    std::string params = data.ReadString();
    Rule rule;
    reply.WriteInt32(OnCheckStarting(params, rule));

    if (!reply.WriteParcelable(&rule)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "failed write rule.");
        return AAFwk::ERR_SA_INTERCEPTOR_WRITE_RULE_FAILED;
    }
    return NO_ERROR;
}
} // namespace AbilityRuntime
} // namespace OHOS