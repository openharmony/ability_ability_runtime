/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "application_context.h"
#include "context.h"
#include "hilog_tag_wrapper.h"
#include "hilog_wrapper.h"
#include "ui_extension_utils.h"

namespace OHOS {
namespace AbilityRuntime {
template<class C>
void ExtensionBase<C>::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application,
    std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    Extension::Init(record, application, handler, token);
    TAG_LOGD(AAFwkTag::EXT, "begin");
    context_ = CreateAndInitContext(record, application, handler, token);
}

template<class C>
std::shared_ptr<C> ExtensionBase<C>::CreateAndInitContext(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application,
    std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    TAG_LOGD(AAFwkTag::EXT, "begin");
    std::shared_ptr<C> context = std::make_shared<C>();
    auto appContext = Context::GetApplicationContext();
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "null appContext");
        return context;
    }
    context->SetApplicationInfo(appContext->GetApplicationInfo());
    context->SetResourceManager(appContext->GetResourceManager());
    context->SetParentContext(appContext);
    context->SetToken(token);
    context->SetProcessName(appContext->GetProcessName());
    if (record == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "null record");
        return context;
    }
    TAG_LOGD(AAFwkTag::EXT, "begin init abilityInfo");
    auto abilityInfo = record->GetAbilityInfo();
    context->SetAbilityInfo(abilityInfo);
    context->InitHapModuleInfo(abilityInfo);
    if (AAFwk::UIExtensionUtils::IsUIExtension(abilityInfo->extensionAbilityType) &&
        appContext->GetConfiguration() != nullptr) {
        auto appConfig = appContext->GetConfiguration();
        auto contextConfig = std::make_shared<AppExecFwk::Configuration>(*appConfig);
        context->SetConfiguration(contextConfig);
    } else {
        context->SetConfiguration(appContext->GetConfiguration());
    }
    if (abilityInfo->applicationInfo.multiProjects) {
        std::shared_ptr<Context> moduleContext = context->CreateModuleContext(abilityInfo->moduleName);
        if (moduleContext != nullptr) {
            auto rm = moduleContext->GetResourceManager();
            context->SetResourceManager(rm);
        }
    }
    return context;
}

template<class C>
std::shared_ptr<C> ExtensionBase<C>::GetContext()
{
    return context_;
}

template<class C>
void ExtensionBase<C>::OnConfigurationUpdated(const AppExecFwk::Configuration &configuration)
{
    Extension::OnConfigurationUpdated(configuration);
    TAG_LOGD(AAFwkTag::EXT, "called");

    if (!context_) {
        TAG_LOGE(AAFwkTag::EXT, "null context_");
        return;
    }

    auto fullConfig = context_->GetConfiguration();
    if (!fullConfig) {
        TAG_LOGE(AAFwkTag::EXT, "null config");
        return;
    }

    if (extensionCommon_) {
        extensionCommon_->OnConfigurationUpdated(fullConfig);
    }
}

template<class C>
void ExtensionBase<C>::OnMemoryLevel(int level)
{
    Extension::OnMemoryLevel(level);
    TAG_LOGD(AAFwkTag::EXT, "called");

    if (extensionCommon_) {
        extensionCommon_->OnMemoryLevel(level);
    }
}

template<class C>
void ExtensionBase<C>::SetExtensionCommon(const std::shared_ptr<ExtensionCommon> &common)
{
    extensionCommon_ = common;
}

template<class C>
void ExtensionBase<C>::OnExtensionAbilityRequestFailure(
    const std::string &requestId, const AppExecFwk::ElementName &element, const std::string &message)
{
    TAG_LOGD(AAFwkTag::EXT, "OnAbilityRequestFailure called");
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "null context_");
        return;
    }
    context_->OnRequestFailure(requestId, element, message);
}

template<class C>
void ExtensionBase<C>::OnExtensionAbilityRequestSuccess(
    const std::string &requestId, const AppExecFwk::ElementName &element, const std::string &message)
{
    TAG_LOGD(AAFwkTag::EXT, "OnAbilityRequestSuccess called");
    if (context_ == nullptr) {
        TAG_LOGE(AAFwkTag::EXT, "null context_");
        return;
    }
    context_->OnRequestSuccess(requestId, element, message);
}
}
}
