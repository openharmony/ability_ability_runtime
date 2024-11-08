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

#include "ui_extension_record_factory.h"

#include "hilog_tag_wrapper.h"
#include "multi_instance_utils.h"
#include "ui_extension_record.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
const std::string UIEXTENSION_ABILITY_ID = "ability.want.params.uiExtensionAbilityId";
}

UIExtensionRecordFactory::UIExtensionRecordFactory() = default;

UIExtensionRecordFactory::~UIExtensionRecordFactory() = default;

bool UIExtensionRecordFactory::NeedReuse(const AAFwk::AbilityRequest &abilityRequest, int32_t &extensionRecordId)
{
    int32_t uiExtensionAbilityId = abilityRequest.sessionInfo->want.GetIntParam(UIEXTENSION_ABILITY_ID,
        INVALID_EXTENSION_RECORD_ID);
    if (uiExtensionAbilityId == INVALID_EXTENSION_RECORD_ID) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "UIEXTENSION_ABILITY_ID is not config, no reuse");
        return false;
    }
    TAG_LOGI(AAFwkTag::ABILITYMGR, "UIExtensionAbility id: %{public}d.", uiExtensionAbilityId);
    extensionRecordId = uiExtensionAbilityId;
    return true;
}

int32_t UIExtensionRecordFactory::PreCheck(
    const AAFwk::AbilityRequest &abilityRequest, const std::string &hostBundleName)
{
    return ExtensionRecordFactory::PreCheck(abilityRequest, hostBundleName);
}

int32_t UIExtensionRecordFactory::CreateRecord(
    const AAFwk::AbilityRequest &abilityRequest, std::shared_ptr<ExtensionRecord> &extensionRecord)
{
    auto abilityRecord = AAFwk::AbilityRecord::CreateAbilityRecord(abilityRequest);
    if (abilityRecord == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "create record failed");
        return ERR_NULL_OBJECT;
    }
    if (AAFwk::MultiInstanceUtils::IsMultiInstanceApp(abilityRequest.appInfo)) {
        abilityRecord->SetInstanceKey(AAFwk::MultiInstanceUtils::GetValidExtensionInstanceKey(abilityRequest));
    }
    CreateDebugRecord(abilityRequest, abilityRecord);
    extensionRecord = std::make_shared<UIExtensionRecord>(abilityRecord);
    extensionRecord->processMode_ = GetExtensionProcessMode(abilityRequest, extensionRecord->isHostSpecified_);
    return ERR_OK;
}

void UIExtensionRecordFactory::CreateDebugRecord(
    const AAFwk::AbilityRequest &abilityRequest, std::shared_ptr<AAFwk::AbilityRecord> abilityRecord)
{
    auto callerRecord = AAFwk::Token::GetAbilityRecordByToken(abilityRequest.callerToken);
    if (!callerRecord) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "No caller record");
        return;
    }
    if (!callerRecord->IsDebug() ||
        callerRecord->GetApplicationInfo().appProvisionType !=
        AppExecFwk::Constants::APP_PROVISION_TYPE_DEBUG) {
            TAG_LOGE(AAFwkTag::ABILITYMGR, "Invalid to debug UIExtension");
            return;
    }
    auto callerBundleName = callerRecord->GetAbilityInfo().bundleName;
    auto isSameApp = callerBundleName == abilityRequest.abilityInfo.bundleName;
    auto isCallerUIAbility = callerRecord->GetAbilityInfo().type == AppExecFwk::AbilityType::PAGE;
    if (isSameApp && isCallerUIAbility) {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "Setting up debug UIExtension");
        abilityRecord->SetDebugUIExtension();
    }
}
} // namespace AbilityRuntime
} // namespace OHOS
