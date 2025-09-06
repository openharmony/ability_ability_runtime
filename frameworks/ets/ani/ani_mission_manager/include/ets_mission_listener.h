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

#ifndef OHOS_ABILITY_RUNTIME_ETS_MISSION_LISTENER_H
#define OHOS_ABILITY_RUNTIME_ETS_MISSION_LISTENER_H

#include <map>
#include <mutex>

#include "ani_common_util.h"
#include "event_handler.h"
#include "mission_listener_stub.h"

namespace OHOS {
namespace AbilityRuntime {
class EtsMissionListener : public AAFwk::MissionListenerStub {
public:
    explicit EtsMissionListener(ani_vm *vm) : vm_(vm) {}
    ~EtsMissionListener() override;

    void OnMissionCreated(int32_t missionId) override;
    void OnMissionDestroyed(int32_t missionId) override;
    void OnMissionSnapshotChanged(int32_t missionId) override;
    void OnMissionMovedToFront(int32_t missionId) override;
    void OnMissionClosed(int32_t missionId) override;
    void OnMissionLabelUpdated(int32_t missionId) override;

    void AddEtsListenerObject(ani_env *env, int32_t listenerId, ani_object jsListenerObject, bool isSync = false);
    bool RemoveEtsListenerObject(int32_t listenerId, bool isSync = false);
    bool IsEmpty();

#ifdef SUPPORT_SCREEN
    void OnMissionIconUpdated(int32_t missionId, const std::shared_ptr<Media::PixelMap> &icon) override;
#endif

private:
    void CallEtsMethod(const std::string &methodName, int32_t missionId);
    ani_env *AttachCurrentThread();
    void DetachCurrentThread();
    ani_vm *vm_ = nullptr;
    bool isAttachThread_ = false;
    std::map<int32_t, ani_object> etsListenerObjectMap_;
    std::map<int32_t, ani_object> etsListenerObjectMapSync_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> mainHandler_;
    std::mutex listenerLock_;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif /* OHOS_ABILITY_RUNTIME_JS_MISSION_LISTENER_H */
