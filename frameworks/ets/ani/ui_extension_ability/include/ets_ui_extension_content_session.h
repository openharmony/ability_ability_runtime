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

#ifndef OHOS_ABILITY_RUNTIME_ETS_UI_EXTENSION_CONTENT_SESSION_H
#define OHOS_ABILITY_RUNTIME_ETS_UI_EXTENSION_CONTENT_SESSION_H

#include "ani.h"
#include "ets_runtime.h"
#include "session_info.h"
#include "start_options.h"
#include "ui_extension_context.h"
#include "window.h"

namespace OHOS {
namespace AbilityRuntime {
using RuntimeTask = std::function<void(int, const AAFwk::Want&, bool)>;
class EtsAbilityResultListener {
public:
    EtsAbilityResultListener() = default;
    virtual ~EtsAbilityResultListener() = default;
    virtual void OnAbilityResult(int requestCode, int resultCode, const AAFwk::Want &resultData) = 0;
    virtual bool IsMatch(int requestCode) = 0;
};

class EtsAbilityResultListeners {
public:
    EtsAbilityResultListeners() = default;
    virtual ~EtsAbilityResultListeners() = default;
    void AddListener(const uint64_t &uiExtensionComponentId, std::shared_ptr<EtsAbilityResultListener> listener) {}
    void RemoveListener(const uint64_t &uiExtensionComponentId) {}
    void OnAbilityResult(int requestCode, int resultCode, const AAFwk::Want &resultData) {}
private:
    std::map<uint64_t, std::shared_ptr<EtsAbilityResultListener>> listeners_;
};

class EtsUISessionAbilityResultListener : public EtsAbilityResultListener {
public:
    EtsUISessionAbilityResultListener() = default;
    virtual ~EtsUISessionAbilityResultListener() = default;
    virtual void OnAbilityResult(int requestCode, int resultCode, const AAFwk::Want &resultData) {}
    virtual bool IsMatch(int requestCode) {return true;}
    void OnAbilityResultInner(int requestCode, int resultCode, const AAFwk::Want &resultData) {}
    void SaveResultCallbacks(int requestCode, RuntimeTask &&task) {}
private:
    std::map<int, RuntimeTask> resultCallbacks_;
};

class EtsUIExtensionContentSession {
private:
    class CallbackWrapper;
public:
    EtsUIExtensionContentSession(sptr<AAFwk::SessionInfo> sessionInfo,
        sptr<Rosen::Window> uiWindow, std::weak_ptr<AbilityRuntime::Context> &context,
        std::shared_ptr<EtsAbilityResultListeners> &abilityResultListeners);
    EtsUIExtensionContentSession(sptr<AAFwk::SessionInfo> sessionInfo,
        sptr<Rosen::Window> uiWindow);
    virtual ~EtsUIExtensionContentSession() = default;
    static EtsUIExtensionContentSession* GetEtsContentSession(ani_env *env, ani_object obj);
    static ani_object CreateEtsUIExtensionContentSession(ani_env *env,
        sptr<AAFwk::SessionInfo> sessionInfo, sptr<Rosen::Window> uiWindow,
        std::weak_ptr<AbilityRuntime::Context> context,
        std::shared_ptr<EtsAbilityResultListeners> &abilityResultListeners,
        std::shared_ptr<EtsUIExtensionContentSession> contentSessionPtr);

    static void NativeSendData(ani_env *env, ani_object obj, ani_object data);
    static void NativeLoadContent(ani_env *env, ani_object obj, ani_string path, ani_object storage);
    static void NativeLoadContentByName(ani_env *env, ani_object obj, ani_string path, ani_object storage);
    static void NativeTerminateSelf(ani_env *env, ani_object obj, ani_object callback);
    static void NativeSetWindowBackgroundColor(ani_env *env, ani_object obj, ani_string color);
    static int NativeTerminateSelfWithResult(
        ani_env *env, ani_object obj, ani_object abilityResult, ani_object callback);
    static void NativeSetReceiveDataCallback(ani_env *env, ani_object clsObj, ani_object funcObj);
    static void NativeSetReceiveDataForResultCallback(ani_env *env, ani_object clsObj, ani_object funcObj);
    static ani_object NativeGetUIExtensionHostWindowProxy(ani_env *env, ani_object obj);
    static ani_object NativeGetUIExtensionWindowProxy(ani_env *env, ani_object obj);
    static ani_object NativeStartAbilityByTypeSync(
        ani_env *env, ani_object obj, ani_string type, ani_ref wantParam, ani_object startCallback);
    static void NativeSetWindowPrivacyMode(
        ani_env *env, ani_object obj, ani_boolean isPrivacyMode, ani_object callbackObj);

    void SendData(ani_env *env, ani_object object, ani_object data);
    void LoadContent(ani_env *env, ani_object object, ani_string path, ani_object storage);
    void TerminateSelf();
    int32_t TerminateSelfWithResult();
    void SetWindowBackgroundColor(ani_env *env, ani_string color);
    void SetReceiveDataCallback(ani_env *env, ani_object functionObj);
    static void CallReceiveDataCallback(ani_vm *vm, ani_ref callbackRef, const AAFwk::WantParams &wantParams);
    void SetReceiveDataForResultCallback(ani_env *env, ani_object object);
    void SetWindowPrivacyMode(
        ani_env *env, ani_object obj, ani_boolean isPrivacyMode, ani_object callbackObj);
    static void CallReceiveDataCallbackForResult(
        ani_vm *vm, ani_ref callbackRef, const AAFwk::WantParams &wantParams, AAFwk::WantParams &retWantParams);
    std::shared_ptr<AbilityRuntime::Context> GetContext();
    sptr<Rosen::Window> GetUIWindow();
    static bool BindNativePtrCleaner(ani_env *env);
    static void Clean(ani_env *env, ani_object object);
private:
    void SetReceiveDataCallbackRegister(ani_env *env, ani_object functionObj);
    void SetReceiveDataForResultCallbackRegister(ani_env *env, ani_object funcObj);
    ani_object StartAbilityByTypeSync(ani_env *env, ani_string aniType, ani_ref aniWantParam, ani_object startCallback);
    bool CheckStartAbilityByTypeParam(
        ani_env *env, ani_string aniType, ani_ref aniWantParam, std::string &type, AAFwk::WantParams &wantParam);
    ani_object GetUIExtensionHostWindowProxy(ani_env *env, ani_object object);
    ani_object GetUIExtensionWindowProxy(ani_env *env, ani_object object);
    void SetWindowPrivacyModeInner(ani_env *env, ani_boolean isPrivacyMode, ani_object callbackObj,
        ani_vm *etsVm, ani_ref callbackRef);
    void LoadContentByName(ani_env *env, ani_object object, ani_string path, ani_object storage);
    static ani_status BindNativeMethod(ani_env *env, ani_class cls);

    sptr<AAFwk::SessionInfo> sessionInfo_;
    sptr<Rosen::Window> uiWindow_;
    std::weak_ptr<AbilityRuntime::Context> context_;
    ani_ref receiveDataCallback_ = nullptr;
    bool isRegistered_ = false;
    ani_ref receiveDataForResultCallback_ = nullptr;
    bool isSyncRegistered_ = false;
    std::shared_ptr<EtsUISessionAbilityResultListener> listener_;
    bool isFirstTriggerBindModal_ = true;
#ifdef SUPPORT_SCREEN
    void InitDisplayId(AAFwk::Want &want);
#endif
};

} // namespace AbilityRuntime
} // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ETS_UI_EXTENSION_CONTENT_SESSION_H
