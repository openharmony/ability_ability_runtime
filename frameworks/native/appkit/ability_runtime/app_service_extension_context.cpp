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

#include "app_service_extension_context.h"
#include "ability_connection.h"
#include "ability_manager_client.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"

namespace OHOS {
namespace AbilityRuntime {

ErrCode AppServiceExtensionContext::ConnectAbility(
    const AAFwk::Want &want, const sptr<AbilityConnectCallback> &connectCallback) const
{
    TAG_LOGI(AAFwkTag::APP_SERVICE_EXT, "ConnectAbility called, caller:%{public}s, target:%{public}s",
        GetAbilityInfo() == nullptr ? "" : GetAbilityInfo()->name.c_str(), want.GetElement().GetAbilityName().c_str());
    ErrCode ret =
        ConnectionManager::GetInstance().ConnectAbility(token_, want, connectCallback);
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "ConnectAbility ErrorCode = %{public}d", ret);
    return ret;
}

ErrCode AppServiceExtensionContext::DisconnectAbility(const AAFwk::Want &want,
    const sptr<AbilityConnectCallback> &connectCallback, int32_t accountId) const
{
    TAG_LOGI(AAFwkTag::APP_SERVICE_EXT, "DisconnectAbility called, caller:%{public}s, target:%{public}s",
        GetAbilityInfo() == nullptr ? "" : GetAbilityInfo()->name.c_str(), want.GetElement().GetAbilityName().c_str());
    ErrCode ret =
        ConnectionManager::GetInstance().DisconnectAbility(token_, want, connectCallback, accountId);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "ret=%{public}d", ret);
    }
    return ret;
}

ErrCode AppServiceExtensionContext::TerminateSelf()
{
    ErrCode err = AAFwk::AbilityManagerClient::GetInstance()->TerminateAbility(token_, -1, nullptr);
    if (err != ERR_OK) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "failed %{public}d", err);
    }
    return err;
}

}  // namespace AbilityRuntime
}  // namespace OHOS
