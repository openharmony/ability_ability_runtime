/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_UI_EXTENSION_H
#define OHOS_ABILITY_RUNTIME_UI_EXTENSION_H

#include "extension_base.h"
#include <mutex>
namespace OHOS {
namespace AppExecFwk {
struct InsightIntentExecuteResult;
}
namespace AbilityRuntime {
class UIExtensionContext;
class Runtime;
/**
 * @brief Basic ui extension components.
 */
class UIExtension : public ExtensionBase<UIExtensionContext> {
public:
    UIExtension() = default;
    virtual ~UIExtension() = default;

    /**
     * @brief Create and init context.
     *
     * @param record the ui extension record.
     * @param application the application info.
     * @param handler the ui extension handler.
     * @param token the remote token.
     * @return The created context.
     */
    virtual std::shared_ptr<UIExtensionContext> CreateAndInitContext(
        const std::shared_ptr<AbilityLocalRecord> &record,
        const std::shared_ptr<OHOSApplication> &application,
        std::shared_ptr<AbilityHandler> &handler,
        const sptr<IRemoteObject> &token) override;

    /**
     * @brief Init the ui extension.
     *
     * @param record the ui extension record.
     * @param application the application info.
     * @param handler the ui extension handler.
     * @param token the remote token.
     */
    virtual void Init(const std::shared_ptr<AbilityLocalRecord> &record,
        const std::shared_ptr<OHOSApplication> &application,
        std::shared_ptr<AbilityHandler> &handler,
        const sptr<IRemoteObject> &token) override;

    /**
     * @brief Create ui extension.
     *
     * @param runtime The runtime.
     * @return The ui extension instance.
     */
    static UIExtension* Create(const std::unique_ptr<Runtime>& runtime);

    /**
     * @brief On command window.
     *
     * @param want The want.
     * @param sessionInfo The sessionInfo.
     * @param winCmd The window command.
     */
    void OnCommandWindow(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo,
        AAFwk::WindowCommand winCmd) override;

    /**
     * @brief On command window done.
     *
     * @param sessionInfo The sessionInfo.
     * @param winCmd The window command.
     */
    void OnCommandWindowDone(const sptr<AAFwk::SessionInfo> &sessionInfo, AAFwk::WindowCommand winCmd) override;

    /**
     * @brief On insight intent execute done.
     *
     * @param sessionInfo The sessionInfo.
     * @param result The execute result.
     */
    void OnInsightIntentExecuteDone(const sptr<AAFwk::SessionInfo> &sessionInfo,
        const AppExecFwk::InsightIntentExecuteResult &result) override;

    /**
     * @brief Excute foreground window.
     *
     * @param want The want.
     * @param sessionInfo The sessionInfo.
     */
    virtual void ForegroundWindow(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo) {};

    /**
     * @brief Excute background window.
     *
     * @param sessionInfo The sessionInfo.
     */
    virtual void BackgroundWindow(const sptr<AAFwk::SessionInfo> &sessionInfo) {};

    /**
     * @brief Excute destroy window.
     *
     * @param sessionInfo The sessionInfo.
     */
    virtual void DestroyWindow(const sptr<AAFwk::SessionInfo> &sessionInfo) {};

    /**
     * @brief Excute foreground window with insight intent.
     *
     * @param want The want.
     * @param sessionInfo The sessionInfo.
     * @param needForeground If need foreground.
     */
    virtual bool ForegroundWindowWithInsightIntent(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo,
        bool needForeground) { return false; };

protected:
    std::mutex uiWindowMutex_;
    std::map<uint64_t, sptr<Rosen::Window>> uiWindowMap_;
    std::set<uint64_t> foregroundWindows_;
};
}  // namespace AbilityRuntime
}  // namespace OHOS
#endif  // OHOS_ABILITY_RUNTIME_UI_EXTENSION_H
