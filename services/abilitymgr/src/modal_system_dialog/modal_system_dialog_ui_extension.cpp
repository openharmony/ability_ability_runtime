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

#include "modal_system_dialog/modal_system_dialog_ui_extension.h"

#include "ability_manager_client.h"
#include "hilog_tag_wrapper.h"
#include "in_process_call_wrapper.h"
#include "scene_board_judgement.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr int32_t INVALID_USERID = -1;
constexpr int32_t MESSAGE_PARCEL_KEY_SIZE = 1;
constexpr const char* SYSTEM_SCENEBOARD_BUNDLE_NAME = "com.ohos.sceneboard";
constexpr const char* SYSTEM_SCENEBOARD_ABILITY_NAME = "com.ohos.sceneboard.systemdialog";
}

bool ModalSystemDialogUIExtension::CreateModalUIExtension(const std::string &commandStr)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
    sptr<DialogConnection> connectionCallback(new (std::nothrow) DialogConnection(commandStr));
    if (connectionCallback == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null callback");
        return false;
    }
    auto abilityManagerClient = AAFwk::AbilityManagerClient::GetInstance();
    if (abilityManagerClient == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null abilityManagerClient");
        return false;
    }
    AAFwk::Want systemUIWant;
    systemUIWant.SetElementName(SYSTEM_SCENEBOARD_BUNDLE_NAME, SYSTEM_SCENEBOARD_ABILITY_NAME);

    auto result =
        IN_PROCESS_CALL(abilityManagerClient->ConnectAbility(systemUIWant, connectionCallback, INVALID_USERID));
    if (result != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "connect ability failed, result: %{public}d", result);
        return false;
    }
    return true;
}

void ModalSystemDialogUIExtension::DialogConnection::OnAbilityConnectDone(
    const AppExecFwk::ElementName &element, const sptr<IRemoteObject> &remote, int resultCode)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
    if (remote == nullptr) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "null remote");
        return;
    }

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInt32(MESSAGE_PARCEL_KEY_SIZE)) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write MESSAGE_PARCEL_KEY_SIZE fail");
        return;
    }
    if (!data.WriteString16(u"parameters")) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write parameters fail");
        return;
    }
    if (!data.WriteString16(Str8ToStr16(commandStr_))) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "write commandStr_ fail");
        return;
    }
    auto ret = remote->SendRequest(AAFwk::IAbilityConnection::ON_CONNECT_SYSTEM_COMMON_DIALOG, data, reply, option);
    if (ret != ERR_OK) {
        TAG_LOGE(AAFwkTag::ABILITYMGR, "show dialog failed");
    } else {
        TAG_LOGI(AAFwkTag::ABILITYMGR, "show system dialog successed");
    }
}

void ModalSystemDialogUIExtension::DialogConnection::OnAbilityDisconnectDone(
    const AppExecFwk::ElementName &element, int resultCode)
{
    TAG_LOGD(AAFwkTag::ABILITYMGR, "called");
}
} // namespace AbilityRuntime
} // namespace OHOS