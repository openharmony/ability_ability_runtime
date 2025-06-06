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

#ifndef OHOS_ABILITY_RUNTIME_MISSION_MANAGER_INTERFACE_H
#define OHOS_ABILITY_RUNTIME_MISSION_MANAGER_INTERFACE_H

#include <iremote_broker.h>
#include <vector>

#include "dms_continueInfo.h"
#include "mission_listener_interface.h"
#include "mission_info.h"
#include "mission_snapshot.h"
#include "remote_mission_listener_interface.h"
#include "session_manager_lite.h"
#include "start_options.h"
#include "want.h"
#include "want_receiver_interface.h"
#include "want_sender_info.h"
#include "want_sender_interface.h"

namespace OHOS {
namespace AppExecFwk {
enum class ExtensionAbilityType;
}
namespace AAFwk {
namespace {
constexpr int DEFAULT_INVALID_USER_ID = -1;
constexpr int CYCLE_LIMIT = 1000;
}
class Want;
/**
 * @class IMissionManager
 * IMissionManager interface is used to access ability manager services.
 */
class IMissionManager : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.aafwk.MissionManager")
    
    virtual int ContinueMission(const std::string &srcDeviceId, const std::string &dstDeviceId, int32_t missionId,
        const sptr<IRemoteObject> &callBack, AAFwk::WantParams &wantParams) = 0;

    virtual int ContinueMission(AAFwk::ContinueMissionInfo continueMissionInfo, const sptr<IRemoteObject> &callback)
    {
        return 0;
    }
    
    virtual int LockMissionForCleanup(int32_t missionId) = 0;

    virtual int UnlockMissionForCleanup(int32_t missionId) = 0;

    /**
     * @brief Register mission listener to ability mgr.
     * @param listener The handler of listener.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int RegisterMissionListener(const sptr<IMissionListener> &listener) = 0;

    /**
     * @brief UnRegister mission listener from ability mgr.
     * @param listener The handler of listener.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int UnRegisterMissionListener(const sptr<IMissionListener> &listener) = 0;

    /**
     * @brief Register mission listener to ability manager service.
     * @param deviceId The remote device Id.
     * @param listener The handler of listener.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int RegisterMissionListener(const std::string &deviceId, const sptr<IRemoteMissionListener> &listener) = 0;

    virtual int UnRegisterMissionListener(const std::string &deviceId,
        const sptr<IRemoteMissionListener> &listener) = 0;

    /**
     * @brief Get mission infos from ability mgr.
     * @param deviceId local or remote deviceId.
     * @param numMax max number of missions.
     * @param missionInfos mission info result.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int GetMissionInfos(
        const std::string &deviceId, int32_t numMax, std::vector<MissionInfo> &missionInfos) = 0;

    /**
     * @brief Get mission info by id.
     * @param deviceId local or remote deviceId.
     * @param missionId Id of target mission.
     * @param missionInfo mission info of target mission.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int GetMissionInfo(const std::string &deviceId, int32_t missionId, MissionInfo &missionInfo) = 0;

    /**
     * @brief Get the Mission Snapshot Info object
     * @param deviceId local or remote deviceId.
     * @param missionId Id of target mission.
     * @param snapshot snapshot of target mission.
     * @param isLowResolution get low resolution snapshot.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int GetMissionSnapshot(const std::string &deviceId, int32_t missionId,
        MissionSnapshot &snapshot, bool isLowResolution) = 0;

    /**
     * @brief Clean mission by id.
     * @param missionId Id of target mission.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int CleanMission(int32_t missionId) = 0;

    /**
     * @brief Clean all missions in system.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int CleanAllMissions() = 0;

    /**
     * @brief Move a mission to front.
     * @param missionId Id of target mission.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int MoveMissionToFront(int32_t missionId) = 0;

    /**
     * @brief Move a mission to front.
     * @param missionId Id of target mission.
     * @param startOptions Special startOptions for target mission.
     *
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int MoveMissionToFront(int32_t missionId, const StartOptions &startOptions) = 0;

    /**
     * Move missions to front
     * @param missionIds Ids of target missions
     * @param topMissionId Indicate which mission will be moved to top, if set to -1, missions' order won't change
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int MoveMissionsToForeground(const std::vector<int32_t> &missionIds, int32_t topMissionId)
    {
        return 0;
    }

    /**
     * Move missions to background
     * @param missionIds Ids of target missions
     * @param result The result of move missions to background, and the array is sorted by zOrder
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int MoveMissionsToBackground(const std::vector<int32_t> &missionIds, std::vector<int32_t> &result)
    {
        return 0;
    }

    /**
     * Get mission id by ability token.
     *
     * @param token The token of ability.
     * @return Returns -1 if do not find mission, otherwise return mission id.
     */
    virtual int32_t GetMissionIdByToken(const sptr<IRemoteObject> &token) = 0;

    /**
     * Start synchronizing remote device mission
     * @param devId, deviceId.
     * @param fixConflict, resolve synchronizing conflicts flag.
     * @param tag, call tag.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int StartSyncRemoteMissions(const std::string &devId, bool fixConflict, int64_t tag) = 0;

    /**
     * Stop synchronizing remote device mission
     * @param devId, deviceId.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int StopSyncRemoteMissions(const std::string &devId) = 0;

    virtual int SetMissionContinueState(const sptr<IRemoteObject> &token, const AAFwk::ContinueState &state)
    {
        return 0;
    };

#ifdef SUPPORT_SCREEN
    virtual int SetMissionLabel(const sptr<IRemoteObject> &abilityToken, const std::string &label) = 0;

    virtual int SetMissionIcon(const sptr<IRemoteObject> &token,
        const std::shared_ptr<OHOS::Media::PixelMap> &icon) = 0;

    /**
     * Called to update mission snapshot.
     * @param token The target ability.
     * @param pixelMap The snapshot.
     */
    virtual void UpdateMissionSnapShot(const sptr<IRemoteObject> &token,
        const std::shared_ptr<OHOS::Media::PixelMap> &pixelMap) {};
#endif

    /**
     * Called to verify that the MissionId is valid.
     * @param missionIds Query mission list.
     * @param results Output parameters, return results up to 20 query results.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t IsValidMissionIds(
        const std::vector<int32_t> &missionIds, std::vector<MissionValidResult> &results) = 0;

    /**
     * Open atomic service window prior to finishing free install.
     *
     * @param bundleName, the bundle name of the atomic service.
     * @param moduleName, the module name of the atomic service.
     * @param abilityName, the ability name of the atomic service.
     * @param startTime, the starting time of the free install task.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t PreStartMission(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const std::string &startTime)
    {
        return 0;
    }

    /**
     * Terminate the mission.
     *
     * @param missionId, The mission id of the UIAbility need to be terminated.
     * @return Returns ERR_OK on success, others on failure.
     */
    virtual int32_t TerminateMission(int32_t missionId)
    {
        return 0;
    }
};
}  // namespace AAFwk
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_MISSION_MANAGER_INTERFACE_H
