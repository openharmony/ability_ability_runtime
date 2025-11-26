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

#include "ability_record/ability_record_utils.h"

#include "ability_config.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {
Token::Token(std::weak_ptr<AbilityRecord> abilityRecord) : abilityRecord_(abilityRecord)
{}

Token::~Token()
{}

std::shared_ptr<AbilityRecord> Token::GetAbilityRecordByToken(sptr<IRemoteObject> token)
{
    if (token == nullptr) {
        return nullptr;
    }

    std::string descriptor = Str16ToStr8(token->GetObjectDescriptor());
    if (descriptor != "ohos.aafwk.AbilityToken") {
        TAG_LOGD(AAFwkTag::ABILITYMGR, "descriptor:%{public}s", descriptor.c_str());
        return nullptr;
    }

    // Double check if token is valid
    sptr<IAbilityToken> theToken = iface_cast<IAbilityToken>(token);
    if (!theToken) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "input err");
        return nullptr;
    }
    std::u16string castDescriptor = theToken->GetDescriptor();
    if (castDescriptor != u"ohos.aafwk.AbilityToken") {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "Input token iface_cast error:%{public}s.", Str16ToStr8(castDescriptor).c_str());
        return nullptr;
    }

    return (static_cast<Token *>(token.GetRefPtr()))->GetAbilityRecord();
}

std::shared_ptr<AbilityRecord> Token::GetAbilityRecord() const
{
    return abilityRecord_.lock();
}

void LaunchDebugInfo::Update(const OHOS::AAFwk::Want &want)
{
    isDebugAppSet = want.HasParameter(AbilityConfig::DEBUG_APP);
    if (isDebugAppSet) {
        debugApp = want.GetBoolParam(AbilityConfig::DEBUG_APP, false);
    }
    isNativeDebugSet = want.HasParameter(AbilityConfig::NATIVE_DEBUG);
    if (isNativeDebugSet) {
        nativeDebug = want.GetBoolParam(AbilityConfig::NATIVE_DEBUG, false);
    }
    isPerfCmdSet = want.HasParameter(AbilityConfig::PERF_CMD);
    if (isPerfCmdSet) {
        perfCmd = want.GetStringParam(AbilityConfig::PERF_CMD);
    }
}
}  // namespace AAFwk
}  // namespace OHOS