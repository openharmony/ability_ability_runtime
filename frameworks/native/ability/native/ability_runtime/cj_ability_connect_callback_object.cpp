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

#include "cj_ability_connect_callback_object.h"

#include "cj_remote_object_ffi.h"
#include "cj_macro.h"
#include "hilog_tag_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
struct CJUIExtensionConnectionKey {
    AAFwk::Want want;
    int64_t id;
};

struct KeyCompare {
    bool operator()(const CJUIExtensionConnectionKey &key1, const CJUIExtensionConnectionKey &key2) const
    {
        if (key1.id < key2.id) {
            return true;
        }
        return false;
    }
};

namespace {
static CJAbilityConnectCallbackFuncs* g_cjAbilityConnectCallbackFuncs = nullptr;
static std::map<CJUIExtensionConnectionKey, sptr<CJAbilityConnectCallback>, KeyCompare> g_connects;
static int64_t g_serialNumber = 0;
static std::mutex g_connectMtx;
}

void RegisterCJAbilityConnectCallbackFuncs(void (*registerFunc)(CJAbilityConnectCallbackFuncs* result))
{
    TAG_LOGD(AAFwkTag::CONTEXT, "start");
    if (g_cjAbilityConnectCallbackFuncs != nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "not null cangjie callback");
        return;
    }

    g_cjAbilityConnectCallbackFuncs = new CJAbilityConnectCallbackFuncs();
    registerFunc(g_cjAbilityConnectCallbackFuncs);
}

sptr<CJAbilityConnectCallback> CJAbilityConnectCallback::Create(int64_t id, AAFwk::Want& want)
{
    auto connection = sptr<CJAbilityConnectCallback>::MakeSptr(id);

    CJUIExtensionConnectionKey key;
    {
        std::unique_lock<std::mutex> lock(g_connectMtx);

        key.id = g_serialNumber;
        key.want = want;
        g_serialNumber = (g_serialNumber + 1) % INT32_MAX;
        g_connects.emplace(key, connection);
    }
    connection->SetConnectionId(key.id);

    return connection;
}

void CJAbilityConnectCallback::Remove(int64_t connectId)
{
    std::unique_lock<std::mutex> lock(g_connectMtx);

    auto item = std::find_if(g_connects.begin(), g_connects.end(), [&connectId](const auto &obj) {
            return connectId == obj.first.id;
        });
    if (item != g_connects.end()) {
        TAG_LOGD(AAFwkTag::UI_EXT, "conn ability exists");
        g_connects.erase(item);
    } else {
        TAG_LOGD(AAFwkTag::UI_EXT, "conn ability not exists");
    }
}

void CJAbilityConnectCallback::FindConnection(AAFwk::Want& want, sptr<CJAbilityConnectCallback>& connection,
    int64_t connectId)
{
    std::unique_lock<std::mutex> lock(g_connectMtx);

    TAG_LOGD(AAFwkTag::UI_EXT, "Disconnect ability enter, connection:%{public}" PRId64, connectId);
    auto item = std::find_if(g_connects.begin(), g_connects.end(), [connectId](const auto &obj) {
            return connectId == obj.first.id;
        });
    if (item != g_connects.end()) {
        // match id
        want = item->first.want;
        connection = item->second;
        TAG_LOGD(AAFwkTag::UI_EXT, "find conn ability exist");
    }
}

CJAbilityConnectCallback::~CJAbilityConnectCallback()
{
    if (g_cjAbilityConnectCallbackFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null cangjie callback");
        return;
    }
    g_cjAbilityConnectCallbackFuncs->release(callbackId_);
}

void CJAbilityConnectCallback::OnAbilityConnectDone(
    const AppExecFwk::ElementName& element, const sptr<IRemoteObject>& remoteObject, int resultCode)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called, resultCode:%{public}d", resultCode);
    if (g_cjAbilityConnectCallbackFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null g_cjAbilityConnectCallbackFuncs");
        return;
    }

    ElementNameHandle elementNameHandle = const_cast<AppExecFwk::ElementName*>(&element);
    // The cj side is responsible for the release.
    auto cjRemoteObj = FFI::FFIData::Create<AppExecFwk::CJRemoteObject>(remoteObject);
    if (cjRemoteObj == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null cjRemoteObj");
        return;
    }
    g_cjAbilityConnectCallbackFuncs->onConnect(callbackId_, elementNameHandle, cjRemoteObj->GetID(), resultCode);
}

void CJAbilityConnectCallback::OnAbilityDisconnectDone(const AppExecFwk::ElementName& element, int resultCode)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called, resultCode:%{public}d", resultCode);
    if (g_cjAbilityConnectCallbackFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null cangjie callback");
        return;
    }

    ElementNameHandle elementNameHandle = const_cast<AppExecFwk::ElementName*>(&element);
    g_cjAbilityConnectCallbackFuncs->onDisconnect(callbackId_, elementNameHandle, resultCode);
    Remove(connectId_);
}

void CJAbilityConnectCallback::OnFailed(int32_t resultCode)
{
    TAG_LOGD(AAFwkTag::CONTEXT, "called, resultCode:%{public}d", resultCode);
    if (g_cjAbilityConnectCallbackFuncs == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null cangjie callback");
        return;
    }

    g_cjAbilityConnectCallbackFuncs->onFailed(callbackId_, resultCode);
}
} // AbilityRuntime
} // OHOS
