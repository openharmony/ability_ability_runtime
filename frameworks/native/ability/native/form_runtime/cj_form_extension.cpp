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
    return new CJFormExtension();
}

CJFormExtension* CJFormExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "call");
    return new CJFormExtension();
}

CJFormExtension::CJFormExtension() {}
CJFormExtension::~CJFormExtension()
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "destructor");
    auto context = GetContext();
    if (context) {
        context->Unbind();
    }
    cjObj_.Destroy();
}

void CJFormExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application,
    std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "call");
    FormExtension::Init(record, application, handler, token);
    // init and bindContext
    int32_t ret = cjObj_.Init(abilityInfo_->name, this);
    if (ret != 0) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "cjFormExtension Init failed");
    }
}

OHOS::AppExecFwk::FormProviderInfo CJFormExtension::OnCreate(const OHOS::AAFwk::Want& want)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "call");

    CFormBindingData nativeResult = cjObj_.OnAddForm(want);
    OHOS::AppExecFwk::FormProviderInfo formProviderInfo;

    if (nativeResult.data == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "null nativeResult");
        cjObj_.FreeCFormBindingData(nativeResult);
        return formProviderInfo;
    }
    std::string formDataStr = std::string(nativeResult.data);
    AppExecFwk::FormProviderData formData = AppExecFwk::FormProviderData(formDataStr);
    formProviderInfo.SetFormData(formData);
    std::vector<FormDataProxy> formDataProxies;
    if (!ConvertFromDataProxies(nativeResult.cArrProxyData, formDataProxies)) {
        TAG_LOGW(AAFwkTag::FORM_EXT, "Convert formDataProxies failed");
        cjObj_.FreeCFormBindingData(nativeResult);
        return formProviderInfo;
    }
    formProviderInfo.SetFormDataProxies(formDataProxies);
    cjObj_.FreeCFormBindingData(nativeResult);
    TAG_LOGD(AAFwkTag::FORM_EXT, "ok");
    return formProviderInfo;
}

void CJFormExtension::OnDestroy(const int64_t formId)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "formId: %{public}" PRId64, formId);
    FormExtension::OnDestroy(formId);
    cjObj_.OnRemoveForm(std::to_string(formId).c_str());
}

void CJFormExtension::OnStop()
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "call");
    cjObj_.OnStop();
    bool ret = ConnectionManager::GetInstance().DisconnectCaller(GetContext()->GetToken());
    if (ret) {
        ConnectionManager::GetInstance().ReportConnectionLeakEvent(getpid(), gettid());
        TAG_LOGD(AAFwkTag::FORM_EXT, "disconnected failed");
    }
}

void CJFormExtension::OnEvent(const int64_t formId, const std::string& message)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "formId: %{public}" PRId64, formId);
    FormExtension::OnEvent(formId, message);
    cjObj_.OnFormEvent(std::to_string(formId).c_str(), message.c_str());
}

void CJFormExtension::OnUpdate(const int64_t formId, const AAFwk::WantParams &wantParams)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "formId: %{public}" PRId64, formId);
    FormExtension::OnUpdate(formId, wantParams);
    auto params = OHOS::AAFwk::WantParamWrapper(wantParams).ToString();
    cjObj_.OnUpdateForm(std::to_string(formId).c_str(), params.c_str());
}

void CJFormExtension::OnCastToNormal(const int64_t formId)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "formId: %{public}" PRId64, formId);
    FormExtension::OnCastToNormal(formId);
    cjObj_.OnCastToNormalForm(std::to_string(formId).c_str());
}

void CJFormExtension::OnVisibilityChange(const std::map<int64_t, int32_t>& formEventsMap)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "call");
    FormExtension::OnVisibilityChange(formEventsMap);
    cjObj_.OnChangeFormVisibility(formEventsMap);
}

sptr<IRemoteObject> CJFormExtension::OnConnect(const OHOS::AAFwk::Want& want)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "call");
    Extension::OnConnect(want);
    if (providerRemoteObject_ == nullptr) {
        TAG_LOGD(AAFwkTag::FORM_EXT, "null providerRemoteObject");
        sptr<FormExtensionProviderClient> providerClient = new FormExtensionProviderClient();
        std::shared_ptr<CJFormExtension> formExtension = std::static_pointer_cast<CJFormExtension>(shared_from_this());
        providerClient->SetOwner(formExtension);
        providerRemoteObject_ = providerClient->AsObject();
    }
    return providerRemoteObject_;
}


void CJFormExtension::OnConfigurationUpdated(const AppExecFwk::Configuration& configuration)
{
    FormExtension::OnConfigurationUpdated(configuration);
    TAG_LOGD(AAFwkTag::FORM_EXT, "call");

    auto fullConfig = GetContext()->GetConfiguration();
    cjObj_.OnConfigurationUpdate(fullConfig);
}

FormState CJFormExtension::OnAcquireFormState(const Want &want)
{
    TAG_LOGD(AAFwkTag::FORM_EXT, "call");
    auto state = cjObj_.OnAcquireFormState(want);
    TAG_LOGD(AAFwkTag::FORM_EXT, "state: %{public}d", state);
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

bool CJFormExtension::ConvertFromDataProxies(CArrProxyData cArrProxyData,
    std::vector<FormDataProxy> &formDataProxies)
{
    uint32_t len = cArrProxyData.size;
    if (cArrProxyData.head == nullptr) {
        TAG_LOGE(AAFwkTag::FORM_EXT, "null head");
        return false;
    }
    for (uint32_t i = 0; i < len; i++) {
        FormDataProxy formDataProxy("", "");
        CProxyData element = cArrProxyData.head[i];
        if (!ConvertFormDataProxy(element, formDataProxy)) {
            TAG_LOGE(AAFwkTag::FORM_EXT, "GetElement [%{public}u] error", i);
            continue;
        }
        formDataProxies.push_back(formDataProxy);
    }
    return true;
}

bool CJFormExtension::ConvertFormDataProxy(CProxyData cProxyData, FormDataProxy &formDataProxy)
{
    if (cProxyData.key == nullptr || cProxyData.subscribeId == nullptr) {
        return false;
    }
    formDataProxy.key = std::string(cProxyData.key);
    formDataProxy.subscribeId = std::string(cProxyData.subscribeId);
    return true;
}

} // namespace AbilityRuntime
} // namespace OHOS
