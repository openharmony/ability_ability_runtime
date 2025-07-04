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

#include "overlay_manager_client.h"

#include "app_log_wrapper.h"
#include "bundle_mgr_proxy.h"
#include "bundle_mgr_service_death_recipient.h"
#include "iservice_registry.h"
#include "overlay_manager_proxy.h"
#include "system_ability_definition.h"
#include "mock_my_status.h"

namespace OHOS {
namespace AppExecFwk {

OverlayManagerClient &OverlayManagerClient::GetInstance()
{
    static OverlayManagerClient instance;
    return instance;
}

ErrCode OverlayManagerClient::GetOverlayModuleInfoForTarget(const std::string &targetBundleName,
    const std::string &targetModuleName, std::vector<OverlayModuleInfo> &overlayModuleInfos, int32_t userId)
{
    AAFwk::MyStatus::GetInstance().getOverlayCall_++;
    return ERR_OK;
}

}
}