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

#include "foreground_app_connection_client_impl.h"
#include "foreground_app_connection_stub_impl.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
void ForegroundAppConnectionStubImpl::OnForegroundAppConnected(const ForegroundAppConnectionData &data)
{
    auto owner = owner_.lock();
    if (!owner) {
        TAG_LOGE(AAFwkTag::CONNECTION, "owner nullptr");
        return;
    }
    owner->HandleOnForegroundAppConnected(data);
}

void ForegroundAppConnectionStubImpl::OnForegroundAppDisconnected(const ForegroundAppConnectionData &data)
{
    auto owner = owner_.lock();
    if (!owner) {
        TAG_LOGE(AAFwkTag::CONNECTION, "owner nullptr");
        return;
    }
    owner->HandleOnForegroundAppDisconnected(data);
}

void ForegroundAppConnectionStubImpl::OnForegroundAppCallerStarted(int32_t callerPid, int32_t callerUid,
    const std::string &bundleName)
{
    auto owner = owner_.lock();
    if (!owner) {
        TAG_LOGE(AAFwkTag::CONNECTION, "owner nullptr");
        return;
    }
    owner->HandleOnForegroundAppCallerStarted(callerPid, callerUid, bundleName);
}
}  // namespace AbilityRuntime
}  // namespace OHOS
