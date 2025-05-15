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

#ifndef OHOS_ABILITY_RUNTIME_JS_APP_SERVICE_EXTENSION_H
#define OHOS_ABILITY_RUNTIME_JS_APP_SERVICE_EXTENSION_H

#include "app_service_extension.h"
#include "configuration.h"

#ifdef SUPPORT_GRAPHICS
#include "display_manager.h"
#include "system_ability_status_change_stub.h"
#include "window_manager.h"
#endif

class NativeReference;

namespace OHOS {
namespace AbilityRuntime {
class ServiceExtension;
class JsRuntime;
/**
 * @brief Basic service components.
 */
class JsAppServiceExtension : public AppServiceExtension {
public:
    explicit JsAppServiceExtension(JsRuntime& jsRuntime);
    virtual ~JsAppServiceExtension() override;

    /**
     * @brief Create JsAppServiceExtension.
     *
     * @param runtime The runtime.
     * @return The JsAppServiceExtension instance.
     */
    static JsAppServiceExtension* Create(const std::unique_ptr<Runtime>& runtime);

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
    virtual void OnStart(const AAFwk::Want &want) override;

    /**
     * @brief Called when this Service extension is connected for the first time.
     *
     * You can override this function to implement your own processing logic.
     *
     * @param want Indicates the {@link Want} structure containing connection information about the Service extension.
     * @return Returns a pointer to the <b>sid</b> of the connected Service extension.
     */
    virtual sptr<IRemoteObject> OnConnect(const AAFwk::Want &want) override;

    /**
     * @brief Called when all abilities connected to this Service extension are disconnected.
     *
     * You can override this function to implement your own processing logic.
     *
     */
    virtual void OnDisconnect(const AAFwk::Want &want) override;

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
    virtual void OnCommand(const AAFwk::Want &want, bool restart, int startId) override;

    /**
     * @brief Called when this extension enters the <b>STATE_STOP</b> state.
     *
     * The extension in the <b>STATE_STOP</b> is being destroyed.
     * You can override this function to implement your own processing logic.
     */
    virtual void OnStop() override;

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

private:
    napi_value CallObjectMethod(const char* name, napi_value const *argv = nullptr, size_t argc = 0);

    void BindContext(napi_env env, napi_value obj);

    void GetSrcPath(std::string &srcPath);

    napi_value CallOnConnect(const AAFwk::Want &want);

    napi_value CallOnDisconnect(const AAFwk::Want &want, bool withResult = false);

    void ListenWMS();

    JsRuntime& jsRuntime_;
    std::unique_ptr<NativeReference> jsObj_;
    std::shared_ptr<NativeReference> shellContextRef_ = nullptr;
#ifdef SUPPORT_GRAPHICS
protected:
    class JsAppServiceExtensionDisplayListener : public Rosen::IDisplayInfoChangedListener {
    public:
        explicit JsAppServiceExtensionDisplayListener(const std::weak_ptr<JsAppServiceExtension>& jsAppServiceExtension)
        {
            jsAppServiceExtension_ = jsAppServiceExtension;
        }

        void OnDisplayInfoChange(const sptr<IRemoteObject>& token, Rosen::DisplayId displayId, float density,
            Rosen::DisplayOrientation orientation) override
            {
                auto sptr = jsAppServiceExtension_.lock();
                if (sptr != nullptr) {
                    sptr->OnDisplayInfoChange(token, displayId, density, orientation);
                }
            }

    private:
        std::weak_ptr<JsAppServiceExtension> jsAppServiceExtension_;
    };

    void OnCreate(Rosen::DisplayId displayId);
    void OnDestroy(Rosen::DisplayId displayId);
    void OnChange(Rosen::DisplayId displayId);
    void OnDisplayInfoChange(const sptr<IRemoteObject>& token, Rosen::DisplayId displayId, float density,
        Rosen::DisplayOrientation orientation);

private:
    class SystemAbilityStatusChangeListener : public OHOS::SystemAbilityStatusChangeStub {
    public:
        SystemAbilityStatusChangeListener(sptr<JsAppServiceExtensionDisplayListener> displayListener,
            const sptr<IRemoteObject> & token): tmpDisplayListener_(displayListener), token_(token) {};
        virtual void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
        virtual void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override {}

    private:
        sptr<JsAppServiceExtensionDisplayListener> tmpDisplayListener_ = nullptr;
        sptr<IRemoteObject> token_ = nullptr;
    };

    sptr<JsAppServiceExtensionDisplayListener> displayListener_ = nullptr;
    sptr<SystemAbilityStatusChangeListener> saStatusChangeListener_ = nullptr;
#endif
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_JS_APP_SERVICE_EXTENSION_H