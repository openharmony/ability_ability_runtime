/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "missionlistenercontroller_fuzzer.h"

#include <cstddef>
#include <cstdint>

#define private public
#include "mission_listener_controller.h"
#include "mission_listener_stub.h"
#undef private

#include "securec.h"
#include "parcel.h"
#include "ability_record.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint8_t ENABLE = 2;
constexpr int INPUT_ZERO = 0;
constexpr int INPUT_ONE = 1;
constexpr int INPUT_TWO = 2;
constexpr int INPUT_THREE = 3;
constexpr size_t OFFSET_ZERO = 24;
constexpr size_t OFFSET_ONE = 16;
constexpr size_t OFFSET_TWO = 8;
std::shared_ptr<MissionListenerController> Infot_ = nullptr;
class MyMissionListenerFuszzer : public MissionListenerStub {
public:
    MyMissionListenerFuszzer() = default;
    ~MyMissionListenerFuszzer() = default;

    void OnMissionCreated(int32_t missionId) override
    {
        isMissionCreated_ = true;
    }

    void OnMissionDestroyed(int32_t missionId) override
    {
        isMissionDestroyed_ = true;
    }

    void OnMissionSnapshotChanged(int32_t missionId) override
    {
        isMissionSnapshotChanged_ = true;
    }

    void OnMissionMovedToFront(int32_t missionId) override
    {
        isMissionMovedToFront_ = true;
    }

    void OnMissionIconUpdated(int32_t missionId, const std::shared_ptr<OHOS::Media::PixelMap>& icon) override
    {
        isMissionIconUpdated_ = true;
    }

    void OnMissionClosed(int32_t missionId) override
    {
        isMissionClosed_ = true;
    }

    void OnMissionLabelUpdated(int32_t missionId) override
    {
        isMissionLabelUpdated_ = true;
    }

    bool IsMissionCreated() const
    {
        return isMissionCreated_;
    }

    bool IsMissionDestroyed() const
    {
        return isMissionDestroyed_;
    }

    bool IsMissionSnapshotChanged() const
    {
        return isMissionSnapshotChanged_;
    }

    bool IsMissionMovedToFront() const
    {
        return isMissionMovedToFront_;
    }

    bool IsMissionIconUpdated() const
    {
        return isMissionIconUpdated_;
    }

    bool IsMissionClosed() const
    {
        return isMissionClosed_;
    }

    bool IsMissionLabelUpdated() const
    {
        return isMissionLabelUpdated_;
    }

private:
    bool isMissionCreated_ = false;
    bool isMissionDestroyed_ = false;
    bool isMissionSnapshotChanged_ = false;
    bool isMissionMovedToFront_ = false;
    bool isMissionIconUpdated_ = false;
    bool isMissionClosed_ = false;
    bool isMissionLabelUpdated_ = false;
};

class MyAbilityConnection : public IAbilityConnection {
public:
    MyAbilityConnection() = default;
    virtual ~MyAbilityConnection() = default;
    void OnAbilityConnectDone(
        const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int resultCode) override
    {}
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode) override
    {}
    sptr<IRemoteObject> AsObject() override
    {
        return {};
    }
};
}

uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[INPUT_ZERO] << OFFSET_ZERO) | (ptr[INPUT_ONE] << OFFSET_ONE) | (ptr[INPUT_TWO] << OFFSET_TWO) |
        ptr[INPUT_THREE];
}

std::shared_ptr<AbilityRecord> GetFuzzAbilityRecord()
{
    sptr<Token> token = nullptr;
    AbilityRequest abilityRequest;
    abilityRequest.appInfo.bundleName = "com.example.fuzzTest";
    abilityRequest.abilityInfo.name = "MainAbility";
    abilityRequest.abilityInfo.type = AbilityType::DATA;
    std::shared_ptr<AbilityRecord> abilityRecord = AbilityRecord::CreateAbilityRecord(abilityRequest);
    if (!abilityRecord) {
        return nullptr;
    }
    return abilityRecord;
}

sptr<Token> GetFuzzAbilityToken()
{
    sptr<Token> token = nullptr;
    std::shared_ptr<AbilityRecord> abilityRecord = GetFuzzAbilityRecord();
    if (abilityRecord) {
        token = abilityRecord->GetToken();
    }
    return token;
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    std::shared_ptr<MissionListenerController> Info = std::make_shared<MissionListenerController>();
    if (!Info) {
        return false;
    }
    Info->handler_ = nullptr;
    Info->Init();
    std::shared_ptr<MissionListenerController> Infos = std::make_shared<MissionListenerController>();
    Infos->Init();
    sptr<IMissionListener> listener = nullptr;
    Infos->AddMissionListener(listener);
    Infos->DelMissionListener(listener);
    listener = new MyMissionListenerFuszzer();
    Infos->AddMissionListener(listener);
    Infos->DelMissionListener(listener);
    Infos->missionListeners_.push_back(listener);
    Infos->AddMissionListener(listener);
    Infos->DelMissionListener(listener);
    std::list<int32_t> missions;
    Infos->HandleUnInstallApp(missions);
    wptr<IRemoteObject> remote;
    Infos->OnListenerDied(remote);
    if (!Infot_) {
        Infot_ = std::make_shared<MissionListenerController>();
    }
    int32_t missionIds = static_cast<int32_t>(GetU32Data(data));
    Infot_->NotifyMissionCreated(missionIds);
    Infot_->NotifyMissionDestroyed(missionIds);
    Infot_->NotifyMissionSnapshotChanged(missionIds);
    Infot_->NotifyMissionMovedToFront(missionIds);
    Infot_->NotifyMissionFocused(missionIds);
    Infot_->NotifyMissionUnfocused(missionIds);
    std::shared_ptr<OHOS::Media::PixelMap> icon;
    #ifdef SUPPORT_SCREEN
    Infot_->NotifyMissionIconChanged(missionIds, icon);
    #endif
    Infot_->NotifyMissionClosed(missionIds);
    Infot_->NotifyMissionLabelUpdated(missionIds);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    /* Validate the length of size */
    if (size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = (char*)malloc(size + 1);
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
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