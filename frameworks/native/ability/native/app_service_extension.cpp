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

#include "app_service_extension.h"

#include "app_service_extension_context.h"
#include "configuration_utils.h"
#include "connection_manager.h"
#include "hilog_tag_wrapper.h"
#include "js_app_service_extension.h"
#include "runtime.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;

AppServiceExtension* AppServiceExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    if (!runtime) {
        return new AppServiceExtension();
    }

    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "called");
    switch (runtime->GetLanguage()) {
        case Runtime::Language::JS:
            return JsAppServiceExtension::Create(runtime);

        default:
            return new AppServiceExtension();
    }
}

void AppServiceExtension::Init(const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application,
    std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    ExtensionBase<AppServiceExtensionContext>::Init(record, application, handler, token);
    TAG_LOGD(AAFwkTag::APP_SERVICE_EXT, "begin init context");
}

std::shared_ptr<AppServiceExtensionContext> AppServiceExtension::CreateAndInitContext(
    const std::shared_ptr<AbilityLocalRecord> &record,
    const std::shared_ptr<OHOSApplication> &application,
    std::shared_ptr<AbilityHandler> &handler,
    const sptr<IRemoteObject> &token)
{
    std::shared_ptr<AppServiceExtensionContext> context =
        ExtensionBase<AppServiceExtensionContext>::CreateAndInitContext(record, application, handler, token);
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null context");
        return context;
    }
    return context;
}

void AppServiceExtension::OnConfigurationUpdated(const AppExecFwk::Configuration &configuration)
{
    Extension::OnConfigurationUpdated(configuration);

    auto context = GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::APP_SERVICE_EXT, "null context");
        return;
    }

    auto configUtils = std::make_shared<ConfigurationUtils>();
    configUtils->UpdateGlobalConfig(configuration, context->GetResourceManager());
}
} // namespace AbilityRuntime
} // namespace OHOS
