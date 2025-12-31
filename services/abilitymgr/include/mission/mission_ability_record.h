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

#ifndef OHOS_ABILITY_RUNTIME_MISSION_ABILITY_RECORD_H
#define OHOS_ABILITY_RUNTIME_MISSION_ABILITY_RECORD_H

#include "ability_record.h"

namespace OHOS {
namespace AAFwk {
class MissionAbilityRecord;
using MissionAbilityRecordPtr = std::shared_ptr<MissionAbilityRecord>;
class MissionAbilityRecord : public AbilityRecord {
public:
    MissionAbilityRecord(const Want &want, const AppExecFwk::AbilityInfo &abilityInfo,
        const AppExecFwk::ApplicationInfo &applicationInfo, int requestCode);
    
    static MissionAbilityRecordPtr CreateAbilityRecord(const AbilityRequest &abilityRequest);
    static MissionAbilityRecordPtr FromBaseRecord(std::shared_ptr<AbilityRecord> abilityRecord);

    AbilityRecordType GetAbilityRecordType() override;
    void Dump(std::vector<std::string> &info) override;
    void SetAbilityForegroundingFlag();
    bool IsNeedBackToOtherMissionStack() const
    {
        return isNeedBackToOtherMissionStack_;
    }
    void SetNeedBackToOtherMissionStack(bool isNeedBackToOtherMissionStack)
    {
        isNeedBackToOtherMissionStack_ = isNeedBackToOtherMissionStack;
    }

    MissionAbilityRecordPtr GetOtherMissionStackAbilityRecord() const
    {
        return otherMissionStackAbilityRecord_.lock();
    }
    void SetOtherMissionStackAbilityRecord(MissionAbilityRecordPtr abilityRecord)
    {
        otherMissionStackAbilityRecord_ = abilityRecord;
    }

    void SetPreAbilityRecord(MissionAbilityRecordPtr abilityRecord)
    {
        preAbilityRecord_ = abilityRecord;
    }
    MissionAbilityRecordPtr GetPreAbilityRecord() const
    {
        return preAbilityRecord_.lock();
    }

    void SetNextAbilityRecord(MissionAbilityRecordPtr abilityRecord)
    {
        nextAbilityRecord_ = abilityRecord;
    }
    MissionAbilityRecordPtr GetNextAbilityRecord() const
    {
        return nextAbilityRecord_.lock();
    }

    std::string GetLabel();
#ifdef SUPPORT_SCREEN
    void NotifyAnimationFromMinimizeAbility(bool& animaEnabled);
    /**
     * process request of foregrounding the ability.
     *
     */
    void ProcessForegroundAbility(bool isRecent, const AbilityRequest &abilityRequest,
        std::shared_ptr<StartOptions> &startOptions, const std::shared_ptr<AbilityRecord> &callerAbility,
        uint32_t sceneFlag = 0);
    void ProcessForegroundAbility(const std::shared_ptr<AbilityRecord> &callerAbility, bool needExit = true,
        uint32_t sceneFlag = 0);
    void PostCancelStartingWindowHotTask();
    void NotifyAnimationFromTerminatingAbility() const;
    void NotifyAnimationFromTerminatingAbility(const std::shared_ptr<AbilityRecord> &callerAbility, bool needExit,
        bool flag);
    void AnimationTask(bool isRecent, const AbilityRequest &abilityRequest,
        const std::shared_ptr<StartOptions> &startOptions, const std::shared_ptr<AbilityRecord> &callerAbility);
    void NotifyAnimationFromStartingAbility(const std::shared_ptr<AbilityRecord> &callerAbility,
        const AbilityRequest &abilityRequest) const;
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