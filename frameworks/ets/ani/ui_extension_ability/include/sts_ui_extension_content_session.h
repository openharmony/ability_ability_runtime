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

#ifndef OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CONTENT_SESSION_H
#define OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CONTENT_SESSION_H

#include "session_info.h"
#include "start_options.h"
#include "window.h"
#include "sts_runtime.h"

namespace OHOS {
namespace AbilityRuntime {
[[maybe_unused]] static void NativeSendData(ani_env* env, ani_object obj, ani_object data);
[[maybe_unused]] static void NativeLoadContent(ani_env* env, ani_object obj, ani_string path, ani_object storage);
[[maybe_unused]] static void NativeTerminateSelf(ani_env* env, ani_object obj, [[maybe_unused]] ani_object callback);
[[maybe_unused]] static void NativeSetWindowBackgroundColor(ani_env* env, ani_object obj, ani_string color);
[[maybe_unused]] static int NativeTerminateSelfWithResult(ani_env* env, ani_object obj,
    [[maybe_unused]] ani_object abilityResult, [[maybe_unused]] ani_object callback);
[[maybe_unused]] static ani_object NativeSetReceiveDataCallback(ani_env* env, ani_object obj);

using RuntimeTask = std::function<void(int, const AAFwk::Want&, bool)>;

class StsAbilityResultListener {
public:
    StsAbilityResultListener() = default;
    virtual ~StsAbilityResultListener() = default;
    virtual void OnAbilityResult(int requestCode, int resultCode, const AAFwk::Want &resultData) = 0;
    virtual bool IsMatch(int requestCode) = 0;
};

class StsAbilityResultListeners {
public:
    StsAbilityResultListeners() = default;
    virtual ~StsAbilityResultListeners() = default;
    void AddListener(const uint64_t &uiExtensionComponentId, std::shared_ptr<StsAbilityResultListener> listener) {}
    void RemoveListener(const uint64_t &uiExtensionComponentId) {}
    void OnAbilityResult(int requestCode, int resultCode, const AAFwk::Want &resultData) {}
private:
    std::map<uint64_t, std::shared_ptr<StsAbilityResultListener>> listeners_;
};

class StsUISessionAbilityResultListener : public StsAbilityResultListener {
public:
    StsUISessionAbilityResultListener() = default;
    virtual ~StsUISessionAbilityResultListener() = default;
    virtual void OnAbilityResult(int requestCode, int resultCode, const AAFwk::Want &resultData) {}
    virtual bool IsMatch(int requestCode) {return true;}
    void OnAbilityResultInner(int requestCode, int resultCode, const AAFwk::Want &resultData) {}
    void SaveResultCallbacks(int requestCode, RuntimeTask&& task) {}
private:
    std::map<int, RuntimeTask> resultCallbacks_;
};

class StsUIExtensionContentSession {
private:
    class CallbackWrapper;
public:
    StsUIExtensionContentSession(sptr<AAFwk::SessionInfo> sessionInfo,
        sptr<Rosen::Window> uiWindow, std::weak_ptr<AbilityRuntime::Context>& context,
        std::shared_ptr<StsAbilityResultListeners>& abilityResultListeners);
    StsUIExtensionContentSession(sptr<AAFwk::SessionInfo> sessionInfo,
        sptr<Rosen::Window> uiWindow);
    virtual ~StsUIExtensionContentSession() = default;
    static ani_object CreateStsUIExtensionContentSession(ani_env* env,
        sptr<AAFwk::SessionInfo> sessionInfo, sptr<Rosen::Window> uiWindow,
        std::weak_ptr<AbilityRuntime::Context> context,
        std::shared_ptr<StsAbilityResultListeners>& abilityResultListeners,
        std::shared_ptr<StsUIExtensionContentSession> contentSessionPtr);
    void SendData(ani_env* env, ani_object object, ani_object data);
    void LoadContent(ani_env* env, ani_object object, ani_string path, ani_object storage);
    void TerminateSelf();
    int32_t TerminateSelfWithResult();
    void SetWindowBackgroundColor(ani_env* env, ani_string color);
    ani_object GetUIExtensionHostWindowProxy(ani_env* env, ani_object object);
    ani_object SetReceiveDataCallback(ani_env* env, ani_object object);

private:
    sptr<AAFwk::SessionInfo> sessionInfo_;
    sptr<Rosen::Window> uiWindow_;
    std::weak_ptr<AbilityRuntime::Context> context_;
    std::shared_ptr<CallbackWrapper> receiveDataCallback_;
    bool isRegistered = false;
    std::shared_ptr<CallbackWrapper> receiveDataForResultCallback_;
    bool isSyncRegistered = false;
    std::shared_ptr<StsUISessionAbilityResultListener> listener_;
    bool isFirstTriggerBindModal_ = true;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_CONTENT_SESSION_H
