/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_WINDOW_MANAGER_SERVICE_HANDLER_H
#define OHOS_ABILITY_RUNTIME_WINDOW_MANAGER_SERVICE_HANDLER_H

#ifdef SUPPORT_SCREEN
#include "iremote_broker.h"
#include "window_info.h"

namespace OHOS {
namespace Media {
class PixelMap;
}
namespace AAFwk {
/**
 * @class IWindowManagerServiceHandler
 * Window Manager Service Handler, use to call methods of WMS
 */
class IWindowManagerServiceHandler : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.WindowManagerServiceHandler");

    virtual void NotifyWindowTransition(sptr<AbilityTransitionInfo> fromInfo, sptr<AbilityTransitionInfo> toInfo,
        bool& animaEnabled) = 0;

    virtual int32_t GetFocusWindow(sptr<IRemoteObject>& abilityToken) = 0;

    virtual void StartingWindow(sptr<AbilityTransitionInfo> info,
        std::shared_ptr<Media::PixelMap> pixelMap, uint32_t bgColor) = 0;

    virtual void StartingWindow(sptr<AbilityTransitionInfo> info, std::shared_ptr<Media::PixelMap> pixelMap) = 0;

    virtual void CancelStartingWindow(sptr<IRemoteObject> abilityToken) = 0;

    virtual void NotifyAnimationAbilityDied(sptr<AbilityTransitionInfo> info) = 0;

    virtual int32_t MoveMissionsToForeground(const std::vector<int32_t>& missionIds, int32_t topMissionId) = 0;

    virtual int32_t MoveMissionsToBackground(const std::vector<int32_t>& missionIds, std::vector<int32_t>& result) = 0;

    enum WMSCmd {
        // ipc id for NotifyWindowTransition
        ON_NOTIFY_WINDOW_TRANSITION,

        // ipc id for GetFocusWindow
        ON_GET_FOCUS_ABILITY,

        // ipc id for Cold StartingWindow
        ON_COLD_STARTING_WINDOW,

        // ipc id for Hot StartingWindow
        ON_HOT_STARTING_WINDOW,

        // ipc id for CancelStartingWindow
        ON_CANCEL_STARTING_WINDOW,

        // ipc id for NotifyAnimationAbilityDied
        ON_NOTIFY_ANIMATION_ABILITY_DIED,

        // ipc id for MoveMissionsToForeground
        ON_MOVE_MISSINONS_TO_FOREGROUND,

        // ipc id for MoveMissionsToBackground
        ON_MOVE_MISSIONS_TO_BACKGROUND,
    };
};
}  // namespace AAFwk
}  // namespace OHOS
#endif
#endif  // OHOS_ABILITY_RUNTIME_WINDOW_MANAGER_SERVICE_HANDLER_H
