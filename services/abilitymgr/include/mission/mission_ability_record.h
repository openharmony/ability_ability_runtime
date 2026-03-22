/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_MISSION_ABILITY_RECORD_H
#define OHOS_ABILITY_RUNTIME_MISSION_ABILITY_RECORD_H

#include "ability_record.h"

namespace OHOS {
namespace AAFwk {
class MissionAbilityRecord;
using MissionAbilityRecordPtr = std::shared_ptr<MissionAbilityRecord>;
class MissionAbilityRecord : public AbilityRecord {
public:
    /**
     * @brief Constructor
     * @param want The Want object containing ability launch information
     * @param abilityInfo The AbilityInfo containing ability metadata
     * @param applicationInfo The ApplicationInfo containing application metadata
     * @param requestCode The request code for ability launch
     */
    MissionAbilityRecord(const Want &want, const AppExecFwk::AbilityInfo &abilityInfo,
        const AppExecFwk::ApplicationInfo &applicationInfo, int requestCode);
    
    /**
     * @brief Create a MissionAbilityRecord from an AbilityRequest
     * @param abilityRequest The ability request containing launch information
     * @return Shared pointer to the created MissionAbilityRecord
     */
    static MissionAbilityRecordPtr CreateAbilityRecord(const AbilityRequest &abilityRequest);

    /**
     * @brief Convert a base AbilityRecord to MissionAbilityRecord
     * @param abilityRecord Shared pointer to the base AbilityRecord
     * @return Shared pointer to the converted MissionAbilityRecord
     */
    static MissionAbilityRecordPtr FromBaseRecord(std::shared_ptr<AbilityRecord> abilityRecord);

    /**
     * @brief Get the ability record type
     * @return The AbilityRecordType enum value
     */
    AbilityRecordType GetAbilityRecordType() override;

    /**
     * @brief Dump ability record information for debugging
     * @param info Vector to receive the dumped information strings
     */
    void Dump(std::vector<std::string> &info) override;

    /**
     * @brief Set the ability foregrounding flag
     */
    void SetAbilityForegroundingFlag();

    /**
     * @brief Check if need to back to other mission stack
     * @return Returns true if need to back to other mission stack, otherwise false
     */
    bool IsNeedBackToOtherMissionStack() const
    {
        return isNeedBackToOtherMissionStack_;
    }

    /**
     * @brief Set whether need to back to other mission stack
     * @param isNeedBackToOtherMissionStack Flag indicating whether to back to other mission stack
     */
    void SetNeedBackToOtherMissionStack(bool isNeedBackToOtherMissionStack)
    {
        isNeedBackToOtherMissionStack_ = isNeedBackToOtherMissionStack;
    }

    /**
     * @brief Get the ability record in other mission stack
     * @return Shared pointer to the other mission stack ability record
     */
    MissionAbilityRecordPtr GetOtherMissionStackAbilityRecord() const
    {
        return otherMissionStackAbilityRecord_.lock();
    }

    /**
     * @brief Set the ability record in other mission stack
     * @param abilityRecord Shared pointer to the ability record
     */
    void SetOtherMissionStackAbilityRecord(MissionAbilityRecordPtr abilityRecord)
    {
        otherMissionStackAbilityRecord_ = abilityRecord;
    }

    /**
     * @brief Set the previous ability record in the mission
     * @param abilityRecord Shared pointer to the previous ability record
     */
    void SetPreAbilityRecord(MissionAbilityRecordPtr abilityRecord)
    {
        preAbilityRecord_ = abilityRecord;
    }

    /**
     * @brief Get the previous ability record in the mission
     * @return Shared pointer to the previous ability record
     */
    MissionAbilityRecordPtr GetPreAbilityRecord() const
    {
        return preAbilityRecord_.lock();
    }

    /**
     * @brief Set the next ability record in the mission
     * @param abilityRecord Shared pointer to the next ability record
     */
    void SetNextAbilityRecord(MissionAbilityRecordPtr abilityRecord)
    {
        nextAbilityRecord_ = abilityRecord;
    }

    /**
     * @brief Get the next ability record in the mission
     * @return Shared pointer to the next ability record
     */
    MissionAbilityRecordPtr GetNextAbilityRecord() const
    {
        return nextAbilityRecord_.lock();
    }

    /**
     * @brief Get the label of the ability
     * @return The label string
     */
    std::string GetLabel();
#ifdef SUPPORT_SCREEN
    void NotifyAnimationFromMinimizeAbility(bool& animaEnabled);
    /**
     * @brief Process request of foregrounding the ability
     * @param isRecent Flag indicating if launched from recent tasks
     * @param abilityRequest The ability request containing launch information
     * @param startOptions Shared pointer to start options
     * @param callerAbility Shared pointer to the caller ability record
     * @param sceneFlag The scene flag for ability transition
     */
    void ProcessForegroundAbility(bool isRecent, const AbilityRequest &abilityRequest,
        std::shared_ptr<StartOptions> &startOptions, const std::shared_ptr<AbilityRecord> &callerAbility,
        uint32_t sceneFlag = 0);

    /**
     * @brief Process request of foregrounding the ability
     * @param callerAbility Shared pointer to the caller ability record
     * @param needExit Flag indicating whether to exit current ability
     * @param sceneFlag The scene flag for ability transition
     */
    void ProcessForegroundAbility(const std::shared_ptr<AbilityRecord> &callerAbility, bool needExit = true,
        uint32_t sceneFlag = 0);
    void PostCancelStartingWindowHotTask();

    /**
     * @brief Notify animation from terminating ability
     */
    void NotifyAnimationFromTerminatingAbility() const;

    /**
     * @brief Notify animation from terminating ability
     * @param callerAbility Shared pointer to the caller ability record
     * @param needExit Flag indicating whether to exit current ability
     * @param flag Additional flag for animation control
     */
    void NotifyAnimationFromTerminatingAbility(const std::shared_ptr<AbilityRecord> &callerAbility, bool needExit,
        bool flag);
    void AnimationTask(bool isRecent, const AbilityRequest &abilityRequest,
        const std::shared_ptr<StartOptions> &startOptions, const std::shared_ptr<AbilityRecord> &callerAbility);

    /**
     * @brief Notify animation from starting ability
     * @param callerAbility Shared pointer to the caller ability record
     * @param abilityRequest The ability request containing launch information
     */
    void NotifyAnimationFromStartingAbility(const std::shared_ptr<AbilityRecord> &callerAbility,
        const AbilityRequest &abilityRequest) const;

    /**
     * @brief Notify animation from recent task
     * @param startOptions Shared pointer to start options
     * @param want Shared pointer to the Want object
     */
    void NotifyAnimationFromRecentTask(const std::shared_ptr<StartOptions> &startOptions,
        const std::shared_ptr<Want> &want) const;
    void StartingWindowTask(bool isRecent, bool isCold, const AbilityRequest &abilityRequest,
        std::shared_ptr<StartOptions> &startOptions);
    void PostCancelStartingWindowColdTask();

    void StartingWindowHot(const std::shared_ptr<StartOptions> &startOptions, const std::shared_ptr<Want> &want,
        const AbilityRequest &abilityRequest);
    void StartingWindowHot();
    void StartingWindowCold(const std::shared_ptr<StartOptions> &startOptions, const std::shared_ptr<Want> &want,
        const AbilityRequest &abilityRequest);

    std::shared_ptr<Global::Resource::ResourceManager> CreateResourceManager() const;
    std::shared_ptr<Media::PixelMap> GetPixelMap(const uint32_t windowIconId,
        std::shared_ptr<Global::Resource::ResourceManager> resourceMgr) const;

    void InitColdStartingWindowResource(const std::shared_ptr<Global::Resource::ResourceManager> &resourceMgr);
    void GetColdStartingWindowResource(std::shared_ptr<Media::PixelMap> &bg, uint32_t &bgColor);
#endif
private:
    std::string DumpPreAbility() const;
    std::string DumpNextAbility() const;
private:
    bool isNeedBackToOtherMissionStack_ = false;
    std::weak_ptr<MissionAbilityRecord> otherMissionStackAbilityRecord_;
    std::weak_ptr<MissionAbilityRecord> preAbilityRecord_ = {};
    std::weak_ptr<MissionAbilityRecord> nextAbilityRecord_ = {};
#ifdef SUPPORT_SCREEN
    uint32_t bgColor_ = 0;
    std::shared_ptr<Media::PixelMap> startingWindowBg_ = nullptr;
#endif
};
}  // namespace AAFwk
}  // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_MISSION_ABILITY_RECORD_H
