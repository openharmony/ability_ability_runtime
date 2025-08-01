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

#include "unregistermissionlistener_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "ability_manager_client.h"
#include "mission_listener_interface.h"
#include "remote_mission_listener_interface.h"
#include "securec.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t U32_AT_SIZE = 4;
}
class MissionListenerFuzz : public IMissionListener {
public:
    explicit MissionListenerFuzz() {};
    virtual ~MissionListenerFuzz() {};
    void OnMissionCreated(int32_t missionId) override {};
    void OnMissionDestroyed(int32_t missionId) override {};
    void OnMissionSnapshotChanged(int32_t missionId) override {};
    void OnMissionMovedToFront(int32_t missionId) override {};
    void OnMissionMovedToBackground(int32_t missionId) override {};
    void OnMissionClosed(int32_t missionId) override {};
    void OnMissionLabelUpdated(int32_t missionId) override {};
#ifdef SUPPORT_GRAPHICS
    void OnMissionIconUpdated(int32_t missionId, const std::shared_ptr<Media::PixelMap>& icon) override;
#endif
};
class RemoteMissionListenerFuzz : public IRemoteMissionListener {
public:
    explicit RemoteMissionListenerFuzz() {};
    virtual ~RemoteMissionListenerFuzz() {};
    void NotifyMissionsChanged(const std::string& deviceId) override {};
    void NotifySnapshot(const std::string& deviceId, int32_t missionId) override {};
    void NotifyNetDisconnect(const std::string& deviceId, int32_t state) override {};
};
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    auto abilitymgr = AbilityManagerClient::GetInstance();
    if (!abilitymgr) {
        return false;
    }

    sptr<MissionListenerFuzz> listener;
    if (listener) {
        abilitymgr->UnRegisterMissionListener(listener);
    }

    std::string deviceId(data, size);
    sptr<RemoteMissionListenerFuzz> remoteListener;
    if (!deviceId.empty() && remoteListener) {
        abilitymgr->UnRegisterMissionListener(deviceId, remoteListener);
    }

    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        std::cout << "invalid data" << std::endl;
        return 0;
    }

    /* Validate the length of size */
    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        std::cout << "copy failed." << std::endl;
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}