/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_WINDOW_MANAGER_SERVICE_HANDLER_PROXY_H
#define OHOS_ABILITY_RUNTIME_WINDOW_MANAGER_SERVICE_HANDLER_PROXY_H

#ifdef SUPPORT_SCREEN
#include "iremote_proxy.h"
#include "window_manager_service_handler.h"

namespace OHOS {
namespace AAFwk {
class WindowManagerServiceHandlerProxy : public IRemoteProxy<IWindowManagerServiceHandler> {
public:
    explicit WindowManagerServiceHandlerProxy(const sptr<IRemoteObject> &impl);
    virtual ~WindowManagerServiceHandlerProxy() = default;

    virtual void NotifyWindowTransition(sptr<AbilityTransitionInfo> fromInfo,
        sptr<AbilityTransitionInfo> toInfo, bool& animaEnabled) override;

    virtual int32_t GetFocusWindow(sptr<IRemoteObject>& abilityToken) override;

    virtual void StartingWindow(sptr<AbilityTransitionInfo> info, std::shared_ptr<Media::PixelMap> pixelMap,
        uint32_t bgColor) override;

    virtual void StartingWindow(sptr<AbilityTransitionInfo> info, std::shared_ptr<Media::PixelMap> pixelMap) override;

    virtual void CancelStartingWindow(sptr<IRemoteObject> abilityToken) override;

    virtual void NotifyAnimationAbilityDied(sptr<AbilityTransitionInfo> info) override;

    virtual int32_t MoveMissionsToForeground(const std::vector<int32_t>& missionIds, int32_t topMissionId) override;

    virtual int32_t MoveMissionsToBackground(const std::vector<int32_t>& missionIds,
        std::vector<int32_t>& result) override;

 private:
    static inline BrokerDelegator<WindowManagerServiceHandlerProxy> delegator_;
    int32_t SendTransactCmd(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option);
};
}  // namespace AAFwk
}  // namespace OHOS
#endif
#endif  // OHOS_ABILITY_RUNTIME_WINDOW_MANAGER_SERVICE_HANDLER_PROXY_H
