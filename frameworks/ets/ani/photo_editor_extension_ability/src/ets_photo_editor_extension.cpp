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
#include "ets_photo_editor_extension.h"
#include "ets_photo_editor_extension_context.h"
#include <sstream>
#include <vector>

#include "ability_info.h"
#include "ani_common_want.h"
#include "ets_runtime.h"
#include "photo_editor_extension.h"
#include "hilog_tag_wrapper.h"

#include "connection_manager.h"

namespace OHOS {
namespace AbilityRuntime {
using namespace OHOS::AppExecFwk;

EtsPhotoEditorExtension* EtsPhotoEditorExtension::Create(const std::unique_ptr<Runtime>& runtime)
{
    return new (std::nothrow) EtsPhotoEditorExtension(runtime);
}

EtsPhotoEditorExtension::EtsPhotoEditorExtension(const std::unique_ptr<Runtime> &eTSRuntime)
{
    impl_ = std::make_shared<EtsPhotoEditorExtensionImpl>(eTSRuntime);
    SetUIExtensionBaseImpl(impl_);
}

void EtsPhotoEditorExtension::Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
    const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
    std::shared_ptr<AppExecFwk::AbilityHandler> &handler, const sptr<IRemoteObject> &token)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "Begin init photo editor extension");
    std::shared_ptr<PhotoEditorExtensionContext> context = std::make_shared<PhotoEditorExtensionContext>();
    context->SetToken(token);
    auto appContext = Context::GetApplicationContext();
    if (appContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null appContext");
        return;
    }
    context->SetApplicationInfo(appContext->GetApplicationInfo());
    context->SetResourceManager(appContext->GetResourceManager());
    context->SetParentContext(appContext);

    if (record == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null record");
        return;
    }
    TAG_LOGD(AAFwkTag::UI_EXT, "Begin init abilityInfo");
    auto abilityInfo = record->GetAbilityInfo();
    context->SetAbilityInfo(abilityInfo);
    context->InitHapModuleInfo(abilityInfo);
    context->SetConfiguration(appContext->GetConfiguration());
    if (abilityInfo->applicationInfo.multiProjects) {
        std::shared_ptr<Context> moduleContext = context->CreateModuleContext(abilityInfo->moduleName);
        if (moduleContext != nullptr) {
            auto rm = moduleContext->GetResourceManager();
            context->SetResourceManager(rm);
        }
    }

    Extension::Init(record, application, handler, token);
    impl_->SetContext(context);
    // invoke the extensionBase base class here
    impl_->SetAbilityInfo(Extension::abilityInfo_);
    auto extensionCommon = impl_->Init(record, application, handler, token);
    ExtensionBase<PhotoEditorExtensionContext>::SetExtensionCommon(extensionCommon);
}
} // namespace AbilityRuntime
} // namespace OHOS

extern "C" __attribute__((visibility("default"))) OHOS::AbilityRuntime::PhotoEditorExtension *OHOS_ETS_Extension_Create(
    const std::unique_ptr<OHOS::AbilityRuntime::Runtime> &runtime)
{
    return OHOS::AbilityRuntime::EtsPhotoEditorExtension::Create(runtime);
}