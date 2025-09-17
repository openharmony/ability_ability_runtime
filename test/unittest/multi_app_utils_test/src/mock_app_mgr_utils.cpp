/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "app_mgr_util.h"

#include "mock_app_mgr_service.h"

namespace OHOS {
namespace AAFwk {
sptr<OHOS::AppExecFwk::IAppMgr> g_appMgr = nullptr;

OHOS::sptr<AppExecFwk::IAppMgr> AppMgrUtil::GetAppMgr()
{
    if (g_appMgr) {
        return g_appMgr;
    }

    sptr<AppExecFwk::MockAppMgrService> mockAppMgr(new AppExecFwk::MockAppMgrService());
    g_appMgr = iface_cast<AppExecFwk::IAppMgr>(mockAppMgr);
    return g_appMgr;
}
}  // namespace AAFwk
}  // namespace OHOS
