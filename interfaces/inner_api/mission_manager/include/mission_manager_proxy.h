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

#ifndef OHOS_ABILITY_RUNTIME_MISSION_MANAGER_PROXY_H
#define OHOS_ABILITY_RUNTIME_MISSION_MANAGER_PROXY_H

#include "iremote_proxy.h"
#include "mission_manager_interface.h"

namespace OHOS {
class MessageParcel;
namespace AAFwk {
enum class AbilityManagerInterfaceCode;
/**
 * @class MissionManagerProxy
 * MissionManagerProxy.
 */
class MissionManagerProxy : public IRemoteProxy<IMissionManager> {
public:
    explicit MissionManagerProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IMissionManager>(impl) {}
    virtual ~MissionManagerProxy() = default;

    virtual int ContinueMission(const std::string &srcDeviceId, const std::string &dstDeviceId,
        int32_t missionId, const sptr<IRemoteObject> &callBack, AAFwk::WantParams &wantParams) override;

    virtual int ContinueMission(AAFwk::ContinueMissionInfo continueMissionInfo,
        const sptr<IRemoteObject> &callback) override;

    virtual int LockMissionForCleanup(int32_t missionId) override;

    virtual int UnlockMissionForCleanup(int32_t missionId) override;

    /**
     * @brief Register mission listener to ability mgr.
     * @param listener The handler of listener.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int RegisterMissionListener(const sptr<IMissionListener> &listener) override;

    /**
     * @brief UnRegister mission listener from ability mgr.
     * @param listener The handler of listener.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int UnRegisterMissionListener(const sptr<IMissionListener> &listener) override;

    /**
     * @brief Register mission listener to ability manager service.
     * @param deviceId The remote device Id.
     * @param listener The handler of listener.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int RegisterMissionListener(const std::string &deviceId,
        const sptr<IRemoteMissionListener> &listener) override;
    
    virtual int UnRegisterMissionListener(const std::string &deviceId,
        const sptr<IRemoteMissionListener> &listener) override;

    /**
     * @brief Get mission infos from ability mgr.
     * @param deviceId local or remote deviceId.
     * @param numMax max number of missions.
     * @param missionInfos mission info result.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int GetMissionInfos(const std::string& deviceId, int32_t numMax,
        std::vector<MissionInfo> &missionInfos) override;

    /**
     * @brief Get mission info by id.
     * @param deviceId local or remote deviceId.
     * @param missionId Id of target mission.
     * @param missionInfo mission info of target mission.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int GetMissionInfo(const std::string& deviceId, int32_t missionId,
        MissionInfo &missionInfos) override;

    /**
     * @brief Get the Mission Snapshot Info object
     * @param deviceId local or remote deviceId.
     * @param missionId Id of target mission.
     * @param snapshot snapshot of target mission.
     * @param isLowResolution get low resolution snapshot.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int GetMissionSnapshot(const std::string& deviceId, int32_t missionId,
        MissionSnapshot& snapshot, bool isLowResolution) override;

    /**
     * @brief Clean mission by id.
     * @param missionId Id of target mission.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int CleanMission(int32_t missionId) override;

    /**
     * @brief Clean all missions in system.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int CleanAllMissions() override;

    virtual int MoveMissionToFront(int32_t missionId) override;

    /**
     * @brief Move a mission to front.
     * @param missionId Id of target mission.
     * @param startOptions Special startOptions for target mission.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int MoveMissionToFront(int32_t missionId, const StartOptions &startOptions) override;

    /**
     * Move missions to front
     * @param missionIds Ids of target missions
     * @param topMissionId Indicate which mission will be moved to top, if set to -1, missions' order won't change
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int MoveMissionsToForeground(const std::vector<int32_t>& missionIds, int32_t topMissionId) override;

    /**
     * Move missions to background
     * @param missionIds Ids of target missions
     * @param result The result of move missions to background, and the array is sorted by zOrder
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int MoveMissionsToBackground(const std::vector<int32_t>& missionIds,
        std::vector<int32_t>& result) override;

    /**
     * Get mission id by ability token.
     *
     * @param token The token of ability.
     * @return Returns -1 if do not find mission, otherwise return mission id.
     */
    virtual int32_t GetMissionIdByToken(const sptr<IRemoteObject> &token) override;

    virtual int StartSyncRemoteMissions(const std::string& devId, bool fixConflict, int64_t tag) override;

    virtual int StopSyncRemoteMissions(const std::string& devId) override;

    virtual int SetMissionContinueState(const sptr<IRemoteObject> &token, const AAFwk::ContinueState &state) override;

#ifdef SUPPORT_SCREEN
    virtual int SetMissionLabel(const sptr<IRemoteObject> &abilityToken, const std::string &label) override;

    virtual int SetMissionIcon(const sptr<IRemoteObject> &token,
        const std::shared_ptr<OHOS::Media::PixelMap> &icon) override;

    virtual void UpdateMissionSnapShot(const sptr<IRemoteObject> &token,
        const std::shared_ptr<Media::PixelMap> &pixelMap) override;
#endif

    /**
     * Called to verify that the MissionId is valid.
     * @param missionIds Query mission list.
     * @param results Output parameters, return results up to 20 query results.
     * @return Returns ERR_OK on success, others on failure.
     */
    int32_t IsValidMissionIds(
        const std::vector<int32_t> &missionIds, std::vector<MissionValidResult> &results) override;

    /**
     * Open atomic service window prior to finishing free install.
     *
     * @param bundleName, the bundle name of the atomic service.
     * @param moduleName, the module name of the atomic service.
     * @param abilityName, the ability name of the atomic service.
     * @param startTime, the starting time of the free install task.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t PreStartMission(const std::string& bundleName, const std::string& moduleName,
        const std::string& abilityName, const std::string& startTime) override;

    /**
     * Terminate the mission.
     *
     * @param missionId, The mission id of the UIAbility need to be terminated.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t TerminateMission(int32_t missionId) override;
private:
    bool WriteInterfaceToken(MessageParcel &data);
    ErrCode SendRequest(AbilityManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply,
        MessageOption& option);
        
    template <typename T>
    int GetParcelableInfos(MessageParcel &reply, std::vector<T> &parcelableInfos);

private:
    static inline BrokerDelegator<MissionManagerProxy> delegator_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_MISSION_MANAGER_PROXY_H
