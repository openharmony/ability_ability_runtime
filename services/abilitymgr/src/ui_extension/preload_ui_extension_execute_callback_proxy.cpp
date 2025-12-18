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

#include "preload_ui_extension_execute_callback_proxy.h"

#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AAFwk {
void PreloadUIExtensionExecuteCallbackProxy::OnLoadedDone(int32_t extensionAbilityId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IPreloadUIExtensionExecuteCallback::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::UI_EXT, "interface token write failed");
        return;
    }
    if (!data.WriteInt32(extensionAbilityId)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "extensionAbilityId Int32 write failed");
        return;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null remote");
        return;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int error = remote->SendRequest(ON_PRELOAD_UI_EXTENSION_ABILITY_LOADED_DONE, data, reply, option);
    if (error != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "error: %{public}d", error);
    }
}

void PreloadUIExtensionExecuteCallbackProxy::OnDestroyDone(int32_t extensionAbilityId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IPreloadUIExtensionExecuteCallback::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::UI_EXT, "interface token write failed");
        return;
    }
    if (!data.WriteInt32(extensionAbilityId)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "extensionAbilityId Int32 write failed");
        return;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null remote");
        return;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int error = remote->SendRequest(ON_PRELOAD_UI_EXTENSION_ABILITY_DESTROY_DONE, data, reply, option);
    if (error != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "error: %{public}d", error);
    }
}

void PreloadUIExtensionExecuteCallbackProxy::OnPreloadSuccess(
    int32_t requestCode, int32_t extensionAbilityId, int32_t innerErrCode)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(IPreloadUIExtensionExecuteCallback::GetDescriptor())) {
        TAG_LOGE(AAFwkTag::UI_EXT, "interface token write failed");
        return;
    }
    if (!data.WriteInt32(requestCode)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "requestCode Int32 write failed");
        return;
    }
    if (!data.WriteInt32(extensionAbilityId)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "extensionAbilityId Int32 write failed");
        return;
    }
    if (!data.WriteInt32(innerErrCode)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "innerErrCode Int32 write failed");
        return;
    }
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null remote");
        return;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    int error = remote->SendRequest(ON_PRELOAD_UI_EXTENSION_ABILITY_SUCCESS, data, reply, option);
    if (error != ERR_OK) {
        TAG_LOGE(AAFwkTag::UI_EXT, "error: %{public}d", error);
    }
}
} // namespace AAFwk
} // namespace OHOS
