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

#ifndef OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_H
#define OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_H

#include "ability_handler.h"
#include "configuration.h"
#ifdef SUPPORT_GRAPHICS
#include "display_manager.h"
#include "window_manager.h"
#endif // SUPPORT_GRAPHICS
#include "ui_extension.h"
#include "ui_extension_context.h"
#include <mutex>
#include <unordered_set>
#include "sts_runtime.h"
#include "sts_ui_extension_content_session.h"

class STSNativeReference;

namespace OHOS {
namespace AbilityRuntime {
class UIExtension;
class UIExtensionContext;
class JsRuntime;

/**
 * @brief Basic ui extension components.
 */
class StsUIExtension : public UIExtension {
public:
    explicit StsUIExtension(STSRuntime& stsRuntime);
    virtual ~StsUIExtension() override;

    /**
     * @brief Create StsUIExtension.
     *
     * @param runtime The runtime.
     * @return The StsUIExtension instance.
     */
    static StsUIExtension* Create(const std::unique_ptr<Runtime>& stsRuntime);

    /**
     * @brief Init the ui extension.
     *
     * @param record the ui extension record.
     * @param application the application info.
     * @param handler the ui extension handler.
     * @param token the remote token.
     */
    virtual void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
        const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
        std::shared_ptr<AppExecFwk::AbilityHandler> &handler,
        const sptr<IRemoteObject> &token) override;

    /**
     * @brief Called when this ui extension is started. You must override this function if you want to perform some
     *        initialization operations during ui extension startup.
     *
     * This function can be called only once in the entire lifecycle of an ui extension.
     *
     * @param Want Indicates the {@link Want} structure containing startup information about the ui extension.
     * @param sessionInfo The session info of the ability.
     */
    virtual void OnStart(const AAFwk::Want &want, sptr<AAFwk::SessionInfo> sessionInfo) override;

    /**
     * @brief Called when this ui extension is connected for the first time.
     *
     * You can override this function to implement your own processing logic.
     *
     * @param want Indicates the {@link Want} structure containing connection information about the ui extension.
     * @return Returns a pointer to the <b>sid</b> of the connected ui extension.
     */
    virtual sptr<IRemoteObject> OnConnect(const AAFwk::Want &want) override;

    /**
     * @brief Called when all abilities connected to this ui extension are disconnected.
     *
     * You can override this function to implement your own processing logic.
     *
     */
    virtual void OnDisconnect(const AAFwk::Want &want) override;

    /**
     * @brief Called back when ui extension is started.
     *
     * This method can be called only by ui extension. You can use the StartAbility(Want) method to start
     * ui extension. Then the system calls back the current method to use the transferred want parameter to
     * execute its own logic.
     *
     * @param want Indicates the want of ui extension to start.
     * @param restart Indicates the startup mode. The value true indicates that ui extension is restarted after being
     * destroyed, and the value false indicates a normal startup.
     * @param startId Indicates the number of times the ui extension has been started. The startId is incremented
     * by 1 every time the ui extension is started. For example, if the ui extension has been started for six times, the
     * value of startId is 6.
     */
    virtual void OnCommand(const AAFwk::Want &want, bool restart, int startId) override;

    virtual void OnCommandWindow(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo,
        AAFwk::WindowCommand winCmd) override;

    /**
     * @brief Called when this ui extension enters the <b>STATE_STOP</b> state.
     *
     * The ui extension in the <b>STATE_STOP</b> is being destroyed.
     * You can override this function to implement your own processing logic.
     */
    virtual void OnStop() override;
    virtual void OnStop(AppExecFwk::AbilityTransactionCallbackInfo<> *callbackInfo, bool &isAsyncCallback) override;
    /**
     * @brief The callback of OnStop.
     */
    virtual void OnStopCallBack() override;

    /**
     * @brief Called when the system configuration is updated.
     *
     * @param configuration Indicates the updated configuration information.
     */
    virtual void OnConfigurationUpdated(const AppExecFwk::Configuration& configuration) override;

    /**
     * @brief Called when this extension enters the <b>STATE_FOREGROUND</b> state.
     *
     *
     * The extension in the <b>STATE_FOREGROUND</b> state is visible.
     * You can override this function to implement your own processing logic.
     */
    virtual void OnForeground(const Want &want, sptr<AAFwk::SessionInfo> sessionInfo) override;

    /**
     * @brief Called when this extension enters the <b>STATE_BACKGROUND</b> state.
     *
     *
     * The extension in the <b>STATE_BACKGROUND</b> state is invisible.
     * You can override this function to implement your own processing logic.
     */
    virtual void OnBackground() override;

    /**
     * @brief Called when ui extension need dump info.
     *
     * @param params The params from ui extension.
     * @param info The dump info to show.
     */
    virtual void Dump(const std::vector<std::string> &params, std::vector<std::string> &info) override;

    /**
     * @brief Called when startAbilityForResult(ohos.aafwk.content.Want,int) is called to start an extension ability
     * and the result is returned.
     * @param requestCode Indicates the request code returned after the ability is started. You can define the request
     * code to identify the results returned by abilities. The value ranges from 0 to 65535.
     * @param resultCode Indicates the result code returned after the ability is started. You can define the result
     * code to identify an error.
     * @param resultData Indicates the data returned after the ability is started. You can define the data returned. The
     * value can be null.
     */
    void OnAbilityResult(int requestCode, int resultCode, const Want &resultData) override;

    /**
     * @brief Called when configuration changed, including system configuration and window configuration.
     */
    void ConfigurationUpdated();

    void ResetEnv(ani_env* env);

private:
    // virtual void BindContext(napi_env env, napi_value obj, std::shared_ptr<AAFwk::Want> want);
    virtual void BindContext(ani_env *env, std::shared_ptr<AAFwk::Want> want,
        const std::shared_ptr<OHOSApplication> &application);
    ani_object CreateSTSContext(ani_env *env, std::shared_ptr<UIExtensionContext> context,
        int32_t screenMode, const std::shared_ptr<OHOSApplication> &application);
    // napi_value CallObjectMethod(const char *name, napi_value const *argv = nullptr, size_t argc = 0,
    //     bool withResult = false);
    bool CallObjectMethod(bool withResult, const char* name, const char* signature, ...);
    // bool CheckPromise(napi_value result);
    // bool CallPromise(napi_value result, AppExecFwk::AbilityTransactionCallbackInfo<> *callbackInfo);

    // napi_value CallOnConnect(const AAFwk::Want &want);
    ani_status CallOnDisconnect(const AAFwk::Want &want, bool withResult = false);
    ani_object CreateStsLaunchParam(ani_env* env, const AAFwk::LaunchParam& param);
    std::shared_ptr<STSNativeReference> LoadModule(ani_env *env);

    void ForegroundWindow(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo);
    void BackgroundWindow(const sptr<AAFwk::SessionInfo> &sessionInfo);
    void DestroyWindow(const sptr<AAFwk::SessionInfo> &sessionInfo);

    void OnCommandWindowDone(const sptr<AAFwk::SessionInfo> &sessionInfo, AAFwk::WindowCommand winCmd) override;
    bool ForegroundWindowWithInsightIntent(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo,
        bool needForeground);
    bool HandleSessionCreate(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo);
    void OnInsightIntentExecuteDone(const sptr<AAFwk::SessionInfo> &sessionInfo,
        const AppExecFwk::InsightIntentExecuteResult &result) override;
    void PostInsightIntentExecuted(const sptr<AAFwk::SessionInfo> &sessionInfo,
        const AppExecFwk::InsightIntentExecuteResult &result, bool needForeground);
    std::unique_ptr<STSNativeReference> CreateAppWindowStage(sptr<Rosen::Window> uiWindow,
        sptr<AAFwk::SessionInfo> sessionInfo);
    sptr<Rosen::Window> CreateUIWindow(const std::shared_ptr<UIExtensionContext> context,
        const sptr<AAFwk::SessionInfo> &sessionInfo);

    STSRuntime& stsRuntime_;
    std::shared_ptr<STSNativeReference> stsObj_ = nullptr;
    std::shared_ptr<STSNativeReference> shellContextRef_ = nullptr;
    std::mutex uiWindowMutex_;
    std::map<uint64_t, sptr<Rosen::Window>> uiWindowMap_;
    std::set<uint64_t> foregroundWindows_;
    std::map<uint64_t, std::shared_ptr<NativeReference>> contentSessions_;
    int32_t screenMode_ = AAFwk::IDLE_SCREEN_MODE;
    std::shared_ptr<int32_t> screenModePtr_;
    sptr<IRemoteObject> token_ = nullptr;
    std::shared_ptr<AbilityHandler> handler_ = nullptr;
    std::shared_ptr<StsAbilityResultListeners> abilityResultListeners_ = nullptr;
    ani_ref contentSession_;
    std::shared_ptr<StsUIExtensionContentSession> stsUiExtContentSession_;

#ifdef SUPPORT_GRAPHICS
    class StsUIExtensionAbilityDisplayListener : public OHOS::Rosen::IDisplayInfoChangedListener {
    public:
        explicit StsUIExtensionAbilityDisplayListener(const std::weak_ptr<StsUIExtension> &StsUIExtension)
        {
            StsUIExtension_ = StsUIExtension;
        }

        void OnDisplayInfoChange(const sptr<IRemoteObject> &token, Rosen::DisplayId displayId, float density,
            Rosen::DisplayOrientation orientation) override
        {
            auto sptr = StsUIExtension_.lock();
            if (sptr != nullptr) {
                sptr->OnDisplayInfoChange(token, displayId, density, orientation);
            }
        }

    private:
        std::weak_ptr<StsUIExtension> StsUIExtension_;
    };

    void RegisterDisplayInfoChangedListener();
    void UnregisterDisplayInfoChangedListener();
    void OnDisplayInfoChange(const sptr<IRemoteObject> &token, Rosen::DisplayId displayId, float density,
        Rosen::DisplayOrientation orientation);

    sptr<StsUIExtensionAbilityDisplayListener> StsUIExtensionAbilityDisplayListener_ = nullptr;
#endif
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_STS_UI_EXTENSION_H
