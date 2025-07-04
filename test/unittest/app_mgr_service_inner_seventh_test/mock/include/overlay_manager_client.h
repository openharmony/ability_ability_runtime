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
#ifndef MOCK_FOUNDATION_APPEXECFWK_INTERFACES_INNERAPI_APPEXECFWK_CORE_INCLUDE_OVERLAY_MANAGER_CLIENT_H
#define MOCK_FOUNDATION_APPEXECFWK_INTERFACES_INNERAPI_APPEXECFWK_CORE_INCLUDE_OVERLAY_MANAGER_CLIENT_H

#include <mutex>

#include "bundle_constants.h"
#include "ioverlay_manager.h"
#include "overlay_bundle_info.h"
#include "overlay_module_info.h"

namespace OHOS {
namespace AppExecFwk {
class OverlayManagerClient {
public:
    static OverlayManagerClient &GetInstance();
    ErrCode GetOverlayModuleInfoForTarget(const std::string &targetBundleName,
        const std::string &targetModuleName, std::vector<OverlayModuleInfo> &overlayModuleInfos,
        int32_t userId = Constants::UNSPECIFIED_USERID);
};
} // AppExecFwk
} // OHOS
#endif // MOCK_FOUNDATION_APPEXECFWK_INTERFACES_INNERAPI_APPEXECFWK_CORE_INCLUDE_OVERLAY_MANAGER_CLIENT_H