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

#ifndef OHOS_ABILITY_RUNTIME_ETS_UI_SERVICE_EXTENSION_H
#define OHOS_ABILITY_RUNTIME_ETS_UI_SERVICE_EXTENSION_H

#include "ability_info.h"
#include "ani.h"
#include "configuration.h"
#include "ets_native_reference.h"
#include "ets_runtime.h"
#include "ui_service_extension.h"
#include "ui_service_extension_context.h"
#include "ui_service_stub.h"
#ifdef SUPPORT_GRAPHICS
#include "display_manager.h"
#include "js_window_stage.h"
#include "system_ability_status_change_stub.h"
#include "window_option.h"
#endif

namespace OHOS {
namespace AbilityRuntime {
class UIServiceExtension;
class Runtime;
class UIServiceExtensionContext;
class EtsUIServiceExtension;

class UIEtsServiceStubImpl : public AAFwk::UIServiceStub {
public:
    explicit UIEtsServiceStubImpl(std::weak_ptr<EtsUIServiceExtension> &ext);
    virtual ~UIEtsServiceStubImpl();
    virtual int32_t SendData(sptr<IRemoteObject> hostProxy, AAFwk::WantParams &data) override;

protected:
    std::weak_ptr<EtsUIServiceExtension> extension_;
};

/**
 * @brief Basic service components.
 */
class EtsUIServiceExtension : public UIServiceExtension {
public:
    explicit EtsUIServiceExtension(ETSRuntime &etsRuntime);
    virtual ~EtsUIServiceExtension() override;

    /**
     * @brief Create EtsServiceExtension.
     *
     * @param runtime The runtime.
     * @return The EtsServiceExtension instance.
     */
    static EtsUIServiceExtension* Create(const std::unique_ptr<Runtime> &runtime);

    /**
     * @brief Init the extension.
     *
     * @param record the extension record.
     * @param application the application info.
     * @param handler the extension handler.
     * @param token the remote token.
     */
    virtual void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
        const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
        std::shared_ptr<AppExecFwk::AbilityHandler> &handler,
        const sptr<IRemoteObject> &token) override;

     /**
     * @brief Called when this extension is started. You must override this function if you want to perform some
     *        initialization operations during extension startup.
     *
     * This function can be called only once in the entire lifecycle of an extension.
     * @param Want Indicates the {@link Want} structure containing startup information about the extension.
     */
    void OnStart(const AAFwk::Want &want) override;

     /**
     * @brief Called when this extension enters the <b>STATE_STOP</b> state.
     *
     * The extension in the <b>STATE_STOP</b> is being destroyed.
     * You can override this function to implement your own processing logic.
     */
    void OnStop() override;

    /**
     * @brief Called when this Service extension is connected for the first time.
     *
     * You can override this function to implement your own processing logic.
     *
     * @param want Indicates the {@link Want} structure containing connection information about the Service extension.
     * @param callbackInfo Indicates the lifecycle transaction callback information
     * @param isAsyncCallback Indicates whether it is an asynchronous lifecycle callback
     * @return Returns a pointer to the <b>sid</b> of the connected Service extension.
     */
    sptr<IRemoteObject> OnConnect(const AAFwk::Want &want,
        AppExecFwk::AbilityTransactionCallbackInfo<sptr<IRemoteObject>> *callbackInfo, bool &isAsyncCallback) override;

    /**
     * @brief Called when all abilities connected to this Service extension are disconnected.
     *
     * You can override this function to implement your own processing logic.
     * @param callbackInfo Indicates the lifecycle transaction callback information
     * @param isAsyncCallback Indicates whether it is an asynchronous lifecycle callback
     */
    void OnDisconnect(const AAFwk::Want &want, AppExecFwk::AbilityTransactionCallbackInfo<> *callbackInfo,
        bool &isAsyncCallback) override;

    /**
     * @brief Called back when Service is started.
     * This method can be called only by Service. You can use the StartAbility(ohos.aafwk.content.Want) method to start
     * Service. Then the system calls back the current method to use the transferred want parameter to execute its own
     * logic.
     *
     * @param want Indicates the want of Service to start.
     * @param restart Indicates the startup mode. The value true indicates that Service is restarted after being
     * destroyed, and the value false indicates a normal startup.
     * @param startId Indicates the number of times the Service extension has been started. The startId is incremented
     * by 1 every time the extension is started. For example, if the extension has been started for six times, the
     * value of startId is 6.
     */
    void OnCommand(const AAFwk::Want &want, bool restart, int startId) override;

    /**
     * @brief Called when the system configuration is updated.
     *
     * @param configuration Indicates the updated configuration information.
     */
    void OnConfigurationUpdated(const AppExecFwk::Configuration& configuration) override;

    /**
     * @brief Called when configuration changed, including system configuration and window configuration.
     *
     */
    void ConfigurationUpdated();

    /**
     * @brief Called when client send data to extension.
     *
     * @param hostProxy the proxy used to send data back to client
     * @param data The data to send.
     */
    int32_t OnSendData(sptr<IRemoteObject> hostProxy, OHOS::AAFwk::WantParams &data);

protected:
    bool showOnLockScreen_ = false;

private:
    bool CreateWindowIfNeeded();
    void AbilityWindowConfigTransition(sptr<Rosen::WindowOption>& option, uint32_t windowId);
    bool CallObjectMethod(bool withResult, const char* name, const char* signature, ...);
    void HandleSendData(sptr<IRemoteObject> hostProxy, const OHOS::AAFwk::WantParams &data);
    sptr<IRemoteObject> GetHostProxyFromWant(const AAFwk::Want &want);
    void BindContext(ani_env *env);
    void GetSrcPath(std::string& srcPath);
    void ListenWMS();

    ETSRuntime& etsRuntime_;
    std::unique_ptr<ETSNativeReference> etsObj_ = nullptr;
    std::shared_ptr<AbilityContext> aContext_ = nullptr;
    std::shared_ptr<ETSNativeReference> shellContextRef_ = nullptr;
    std::shared_ptr<AbilityHandler> handler_ = nullptr;
    int32_t hostWindowIdInStart_ = 0;
    sptr<UIEtsServiceStubImpl> extensionStub_;
    std::map<sptr<IRemoteObject>, ani_ref> hostProxyMap_;
    bool firstRequest_ = true;
    ani_vm *etsVm_ = nullptr;

#ifdef SUPPORT_GRAPHICS
    void InitDisplayId(AAFwk::Want &want, AAFwk::StartOptions &startOptions, napi_env &env, NapiCallbackInfo& info);
    void OnSceneWillCreated(std::shared_ptr<Rosen::ExtensionWindowConfig> extensionWindowConfig);
    void OnSceneDidCreated(sptr<Rosen::Window>& window);
protected:
    class EtsUIServiceExtensionDisplayListener : public Rosen::DisplayManager::IDisplayListener {
    public:
        explicit EtsUIServiceExtensionDisplayListener(const std::weak_ptr<EtsUIServiceExtension>& etsUIServiceExtension)
        {
            etsUIServiceExtension_ = etsUIServiceExtension;
        }

        void OnCreate(Rosen::DisplayId displayId) override
        {
            auto ptrEtsUIServiceExtension = etsUIServiceExtension_.lock();
            if (ptrEtsUIServiceExtension != nullptr) {
                ptrEtsUIServiceExtension->OnCreate(displayId);
            }
        }

        void OnDestroy(Rosen::DisplayId displayId) override
        {
            auto ptrEtsUIServiceExtension = etsUIServiceExtension_.lock();
            if (ptrEtsUIServiceExtension != nullptr) {
                ptrEtsUIServiceExtension->OnDestroy(displayId);
            }
        }

        void OnChange(Rosen::DisplayId displayId) override
        {
            auto ptrEtsUIServiceExtension = etsUIServiceExtension_.lock();
            if (ptrEtsUIServiceExtension != nullptr) {
                ptrEtsUIServiceExtension->OnChange(displayId);
            }
        }

    private:
        std::weak_ptr<EtsUIServiceExtension> etsUIServiceExtension_;
    };

    void OnCreate(Rosen::DisplayId displayId);
    void OnDestroy(Rosen::DisplayId displayId);
    void OnChange(Rosen::DisplayId displayId);

private:
    class SystemAbilityStatusChangeListener : public OHOS::SystemAbilityStatusChangeStub {
    public:
        SystemAbilityStatusChangeListener(sptr<EtsUIServiceExtensionDisplayListener> displayListener)
            : tmpDisplayListener_(displayListener) {};
        virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
        virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override {}

    private:
        sptr<EtsUIServiceExtensionDisplayListener> tmpDisplayListener_ = nullptr;
    };

    sptr<EtsUIServiceExtensionDisplayListener> displayListener_ = nullptr;
    sptr<SystemAbilityStatusChangeListener> saStatusChangeListener_ = nullptr;
#endif
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_ETS_UI_SERVICE_EXTENSION_H
