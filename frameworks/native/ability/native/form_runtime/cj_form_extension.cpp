/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "form_runtime/cj_form_extension.h"

#include "ability_info.h"
#include "connection_manager.h"
#include "form_provider_data.h"
#include "form_runtime/form_extension_provider_client.h"
#include "form_runtime/cj_form_extension_object.h"

#include "hilog_tag_wrapper.h"

#include <type_traits>
#include <vector>

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;

extern "C" __attribute__((visibility("default"))) FormExtension* OHOS_ABILITY_CJFormExtension()
{
    return new (std::nothrow) CJFormExtension();
}

CJFormExtension* CJFormExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "call");
    return new CJFormExtension();
}

CJFormExtension::CJFormExtension() {}
CJFormExtension::~CJFormExtension()
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "destructor");
    // auto context = GetContext();
    // if (context) {
    //     context->Unbind();
    // }
}

void CJFormExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application,
    std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "call");
    FormExtension::Init(record, application, handler, token);
    int32_t ret = cjObj_.Init(abilityInfo_->name);
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "cjFormExtension Init failed");
        return;
    }
}

OHOS::AppExecFwk::FormProviderInfo CJFormExtension::OnCreate(const OHOS::AAFwk::Want& want)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "call");

    cjObj_.OnAddForm(want);
    OHOS::AppExecFwk::FormProviderInfo formProviderInfo;
    // if (!CheckTypeForNapiValue(env, nativeResult, napi_object)) {
    //     TAG_LOGE(AAFwkTag::FORM_EXT, "null nativeResult");
    //     return formProviderInfo;
    // }

    // napi_value nativeDataValue = nullptr;
    // napi_get_named_property(env, nativeResult, "data", &nativeDataValue);
    // if (nativeDataValue == nullptr) {
    //     TAG_LOGE(AAFwkTag::FORM_EXT, "null nativeResult");
    //     return formProviderInfo;
    // }
    // std::string formDataStr;
    // if (!ConvertFromJsValue(env, nativeDataValue, formDataStr)) {
    //     TAG_LOGE(AAFwkTag::FORM_EXT, "Convert formDataStr failed");
    //     return formProviderInfo;
    // }
    // AppExecFwk::FormProviderData formData = AppExecFwk::FormProviderData(formDataStr);
    // formProviderInfo.SetFormData(formData);

    // napi_value nativeProxies = nullptr;
    // napi_get_named_property(env, nativeResult, "proxies", &nativeProxies);
    // std::vector<FormDataProxy> formDataProxies;
    // if (nativeProxies != nullptr && !ConvertFromDataProxies(env, nativeProxies, formDataProxies)) {
    //     TAG_LOGW(AAFwkTag::FORM_EXT, "Convert formDataProxies failed");
    //     return formProviderInfo;
    // }
    // formProviderInfo.SetFormDataProxies(formDataProxies);
    TAG_LOGI(AAFwkTag::FORM_EXT, "ok");
    return formProviderInfo;
}

void CJFormExtension::OnDestroy(const int64_t formId)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "formId: %{public}" PRId64, formId);
    FormExtension::OnDestroy(formId);

    // 
    return;
}

void CJFormExtension::OnStop()
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "call");
    cjObj_.OnStop();
    bool ret = ConnectionManager::GetInstance().DisconnectCaller(GetContext()->GetToken());
    if (ret) {
        ConnectionManager::GetInstance().ReportConnectionLeakEvent(getpid(), gettid());
        TAG_LOGI(AAFwkTag::FORM_EXT, "disconnected failed");
    }
    return;
}

void CJFormExtension::OnEvent(const int64_t formId, const std::string& message)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "formId: %{public}" PRId64, formId);
    FormExtension::OnEvent(formId, message);

    return;
}

void CJFormExtension::OnUpdate(const int64_t formId, const AAFwk::WantParams &wantParams)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "formId: %{public}" PRId64, formId);
    FormExtension::OnUpdate(formId, wantParams);

    return;
}

void CJFormExtension::OnCastToNormal(const int64_t formId)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "formId: %{public}" PRId64, formId);
    FormExtension::OnCastToNormal(formId);

    return;
}

void CJFormExtension::OnVisibilityChange(const std::map<int64_t, int32_t>& formEventsMap)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "call");
    FormExtension::OnVisibilityChange(formEventsMap);
    return;
}

sptr<IRemoteObject> CJFormExtension::OnConnect(const OHOS::AAFwk::Want& want)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "call");
    Extension::OnConnect(want);
    // if (providerRemoteObject_ == nullptr) {
    //     TAG_LOGD(AAFwkTag::FORM_EXT, "null providerRemoteObject");
    //     sptr<FormExtensionProviderClient> providerClient = new (std::nothrow) FormExtensionProviderClient();
    //     if (providerClient == nullptr) {
    //         TAG_LOGE(AAFwkTag::FORM_EXT, "providerClient null");
    //         return nullptr;
    //     }
    //     std::shared_ptr<CJFormExtension> formExtension = std::static_pointer_cast<CJFormExtension>(shared_from_this());
    //     providerClient->SetOwner(formExtension);
    //     providerRemoteObject_ = providerClient->AsObject();
    // }
    // return providerRemoteObject_;
    return nullptr;
}


void CJFormExtension::OnConfigurationUpdated(const AppExecFwk::Configuration& configuration)
{
    FormExtension::OnConfigurationUpdated(configuration);
    TAG_LOGI(AAFwkTag::FORM_EXT, "call");

    // HandleScope handleScope(cjRuntime_);
    // napi_env env = cjRuntime_.GetNapiEnv();

    // // Notify extension context
    // auto fullConfig = GetContext()->GetConfiguration();
    // if (!fullConfig) {
    //     TAG_LOGE(AAFwkTag::FORM_EXT, "null fullConfig");
    //     return;
    // }
    // JsExtensionContext::ConfigurationUpdated(env, shellContextRef_, fullConfig);

    // napi_value napiConfiguration = OHOS::AppExecFwk::WrapConfiguration(env, *fullConfig);
    // CallObjectMethod("onConfigurationUpdate", "onConfigurationUpdated", &napiConfiguration, 1);
    return;
}

FormState CJFormExtension::OnAcquireFormState(const Want &want)
{
    TAG_LOGI(AAFwkTag::FORM_EXT, "call");
    auto state = static_cast<int32_t>(FormState::DEFAULT);
    
    TAG_LOGI(AAFwkTag::FORM_EXT, "state: %{public}d", state);
    if (state <= static_cast<int32_t>(AppExecFwk::FormState::UNKNOWN) ||
        state > static_cast<int32_t>(AppExecFwk::FormState::READY)) {
        return AppExecFwk::FormState::UNKNOWN;
    } else {
        return static_cast<AppExecFwk::FormState>(state);
    }
}

bool CJFormExtension::OnShare(int64_t formId, AAFwk::WantParams &wantParams)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "formId: %{public}" PRId64, formId);
    return true;
}

bool CJFormExtension::OnAcquireData(int64_t formId, AAFwk::WantParams &wantParams)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "formId: %{public}" PRId64, formId);
    return true;
}


} // namespace AbilityRuntime
} // namespace OHOS
