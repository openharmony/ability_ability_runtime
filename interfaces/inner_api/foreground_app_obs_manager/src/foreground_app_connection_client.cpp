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

#include "foreground_app_connection_client.h"

#include "foreground_app_connection_client_impl.h"
#include "foreground_app_connection_errors.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
ForegroundAppConnectionClient::ForegroundAppConnectionClient()
{
    clientImpl_ = std::make_shared<ForegroundAppConnectionClientImpl>();
}

ForegroundAppConnectionClient& ForegroundAppConnectionClient::GetInstance()
{
    static ForegroundAppConnectionClient instance;
    return instance;
}

int32_t ForegroundAppConnectionClient::RegisterObserver(const std::shared_ptr<ForegroundAppConnection> &observer)
{
    if (!clientImpl_) {
        TAG_LOGE(AAFwkTag::CONNECTION, "null clientImpl_");
        return ERR_NO_CLIENT_IMPL;
    }

    return clientImpl_->RegisterObserver(observer);
}

int32_t ForegroundAppConnectionClient::UnregisterObserver(const std::shared_ptr<ForegroundAppConnection> &observer)
{
    if (!clientImpl_) {
        TAG_LOGE(AAFwkTag::CONNECTION, "null clientImpl_");
        return ERR_NO_CLIENT_IMPL;
    }

    return clientImpl_->UnregisterObserver(observer);
}
}
}
