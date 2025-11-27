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
#ifndef OHOS_ANI_REMOTELISTENER_UTILS_H
#define OHOS_ANI_REMOTELISTENER_UTILS_H
#include <string>
#include <optional>

#include "taihe/runtime.hpp"
#include "ohos.distributedmissionmanager.proj.hpp"
#include "ohos.distributedmissionmanager.impl.hpp"
#include "event_handler.h"
#include "event_runner.h"
#include "mission_continue_stub.h"
#include "refbase.h"
#include "remote_mission_listener_stub.h"

namespace ani_remotelistenerutils {

using namespace OHOS;

class AniRemoteMissionListener : public AAFwk::RemoteMissionListenerStub {
public:
    AniRemoteMissionListener(const ::MissionCallbacks::MissionCallback &ref);
    virtual ~AniRemoteMissionListener();

    void SetCallbacks(const ::MissionCallbacks::MissionCallback &ref);
    void NotifyMissionsChanged(const std::string &deviceId) override;
    void NotifySnapshot(const std::string &deviceId, int32_t missionId) override;
    void NotifyNetDisconnect(const std::string &deviceId, int32_t state) override;

    void NotifyMissionsChangedInMainThread(const std::string &deviceId);
    void NotifySnapshotInMainThread(const std::string &deviceId, int32_t missionId);
    void NotifyNetDisconnectInMainThread(const std::string &deviceId, int32_t state);

    bool SendEventToMainThread(const std::function<void()> func);
    void Release();

private:
    ::MissionCallbacks::MissionCallback callbacks_;
    std::recursive_mutex mutex_;
    bool released_ = false;
};

class AniMissionContinue : public AAFwk::MissionContinueStub {
public:
    explicit AniMissionContinue(::taihe::callback<void(uintptr_t err)> const& callback);
    explicit AniMissionContinue(::ContinueCallback::ContinueCallback const& callback);
    explicit AniMissionContinue(ani_env *env, ani_resolver deferred);
    ~AniMissionContinue();
    bool SendEventToMainThread(const std::function<void()> func);
    void OnContinueDone(int32_t result) override;
    void OnContinueDoneInMainThread(int32_t result);
    void PromiseResult(ani_env* currentEnv, int32_t result);

private:
    ani_vm *vm_ = nullptr;
    std::optional<::taihe::callback<void(uintptr_t err)>> callbackByMissionInfo_;
    std::optional<::ContinueCallback::ContinueCallback> callbackByDeviceInfo_;
    ani_resolver deferred_ = nullptr;
};

}  // namespace ani_observerutils
#endif  // OHOS_ANI_REMOTELISTENER_UTILS_H
