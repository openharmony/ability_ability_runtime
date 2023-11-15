/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_APP_RUNNING_STATUS_PROXY_H
#define OHOS_ABILITY_RUNTIME_APP_RUNNING_STATUS_PROXY_H

#include "app_running_status_listener_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AbilityRuntime {
class AppRunningStatusProxy : public IRemoteProxy<AppRunningStatusListenerInterface> {
public:
    explicit AppRunningStatusProxy(const sptr<IRemoteObject> &impl);
    virtual ~AppRunningStatusProxy() = default;

    /**
     * Notify the app running status.
     *
     * @param bundle Bundle name in application record.
     * @param UID Uid of bundle.
     * @param runningStatus The app running status.
     * @return
     */
    void NotifyAppRunningStatus(const std::string &bundle, int32_t uid, RunningStatus runningStatus) override;

private:
    static inline BrokerDelegator<AppRunningStatusProxy> delegator_;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_APP_RUNNING_STATUS_PROXY_H