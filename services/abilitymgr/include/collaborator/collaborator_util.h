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

#ifndef OHOS_ABILITY_RUNTIME_COLLABORATOR_UTIL_H
#define OHOS_ABILITY_RUNTIME_COLLABORATOR_UTIL_H

#include <string>

#include "start_ability_utils.h"

namespace OHOS {
namespace AAFwk {
namespace CollaboratorUtil {
constexpr const char* PARAM_ANCO_APP_IDENTIFIER = "persist.hmos_fusion_mgr.anco_identifier";

static void UpdateCallerIfNeed(const sptr<IAbilityManagerCollaborator> &collaborator, Want &want)
{
    if (collaborator == nullptr) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "collaborator is nullptr");
        return;
    }
    int32_t ret = collaborator->UpdateCallerIfNeed(want);
    TAG_LOGI(AAFwkTag::ABILITYMGR, "UpdateCallerIfNeed end,ret:%{public}d", ret);
}

static void RemoveCallerIfNeed(const sptr<IAbilityManagerCollaborator> &collaborator, Want &want)
{
    if (collaborator == nullptr) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "collaborator is nullptr");
        return;
    }
    if (AppUtils::GetInstance().InAppTransferList(want.GetBundle())) {
        int32_t ret = collaborator->RemoveCallerIfNeed(want);
        TAG_LOGI(AAFwkTag::ABILITYMGR, "RemoveCallerIfNeed end,ret:%{public}d", ret);
    }
}

static void HandleCallerIfNeed(const sptr<IRemoteObject> &callerToken,
    const sptr<IAbilityManagerCollaborator> &collaborator, Want &want, const std::string &callerBundleName)
{
    want.SetParam("CollaboratorRemoveCallerName", callerBundleName);
    if (StartAbilityUtils::IsCallFromAncoShellOrBroker(callerToken)) {
        UpdateCallerIfNeed(collaborator, want);
    } else {
        RemoveCallerIfNeed(collaborator, want);
    }
    want.RemoveParam("CollaboratorRemoveCallerName");
}

static void UpdateTargetIfNeed(const sptr<IAbilityManagerCollaborator> &collaborator, const Want &want,
    const std::string &callerBundleName)
{
    if (collaborator == nullptr) {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "collaborator is nullptr");
        return;
    }
    std::string identifier = system::GetParameter(PARAM_ANCO_APP_IDENTIFIER, "");
    std::string targetBundleName = want.GetBundle();
    bool callCollaborator = !identifier.empty() &&
        !targetBundleName.empty() && identifier.find(targetBundleName) != std::string::npos;
    if (callCollaborator || AppUtils::GetInstance().InAppTransferList(callerBundleName)) {
        Want tempWant = want;
        int32_t ret = collaborator->UpdateTargetIfNeed(tempWant);
        TAG_LOGI(AAFwkTag::ABILITYMGR, "UpdateTargetIfNeed end,ret:%{public}d", ret);
        (const_cast<Want &>(want)).SetElement(tempWant.GetElement());
    }
}
}  // namespace CollaboratorUtil
}  // namespace AAFwk
}  // namespace OHOS

#endif  // OHOS_ABILITY_RUNTIME_COLLABORATOR_UTIL_H