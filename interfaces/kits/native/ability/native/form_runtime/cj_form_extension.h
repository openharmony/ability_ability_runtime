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

#ifndef OHOS_ABILITY_RUNTIME_CJ_FORM_EXTENSION_H
#define OHOS_ABILITY_RUNTIME_CJ_FORM_EXTENSION_H

#include "cj_form_extension_context.h"
#include "cj_form_extension_object.h"
#include "configuration.h"
#include "form_extension.h"

namespace OHOS {
namespace AbilityRuntime {
class FormExtension;
/**
 * @brief cj form extension components.
 */
class CJFormExtension : public FormExtension {
public:
    explicit CJFormExtension();
    virtual ~CJFormExtension() override;

    static CJFormExtension* Create(const std::unique_ptr<Runtime>& runtime);

    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord>& record,
        const std::shared_ptr<AppExecFwk::OHOSApplication>& application,
        std::shared_ptr<AppExecFwk::AbilityHandler>& handler, const sptr<IRemoteObject>& token) override;

    OHOS::AppExecFwk::FormProviderInfo OnCreate(const OHOS::AAFwk::Want& want) override;

    void OnDestroy(const int64_t formId) override;

    void OnEvent(const int64_t formId, const std::string& message) override;

    void OnUpdate(const int64_t formId, const AAFwk::WantParams& wantParams) override;

    void OnCastToNormal(const int64_t formId) override;

    void OnVisibilityChange(const std::map<int64_t, int32_t>& formEventsMap) override;

    sptr<IRemoteObject> OnConnect(const OHOS::AAFwk::Want& want) override;

    void OnConfigurationUpdated(const AppExecFwk::Configuration& configuration) override;

    FormState OnAcquireFormState(const Want& want) override;

    bool OnShare(int64_t formId, AAFwk::WantParams& wantParams) override;

    bool OnAcquireData(int64_t formId, AAFwk::WantParams& wantParams) override;

    void OnStop() override;

    void SetCjContext(sptr<CJFormExtensionContext> cjContext)
    {
        cjContext_ = cjContext;
    }

private:
    bool ConvertFromDataProxies(CArrProxyData cArrProxyData, std::vector<FormDataProxy>& formDataProxies);

    bool ConvertFormDataProxy(CProxyData cProxyData, FormDataProxy& formDataProxy);

    CJFormExtensionObject cjObj_;
    sptr<IRemoteObject> providerRemoteObject_ = nullptr;
    sptr<CJFormExtensionContext> cjContext_ = nullptr;
};
} // namespace AbilityRuntime
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_CJ_FORM_EXTENSION_H
