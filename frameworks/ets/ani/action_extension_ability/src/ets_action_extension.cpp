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

#include "ets_action_extension.h"

#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "ets_ui_extension_base.h"

#ifdef WINDOWS_PLATFORM
#define ETS_EXPORT __declspec(dllexport)
#else
#define ETS_EXPORT __attribute__((visibility("default")))
#endif

namespace OHOS {
namespace AbilityRuntime {
EtsActionExtension *EtsActionExtension::Create(const std::unique_ptr<Runtime> &runtime)
{
    return new (std::nothrow) EtsActionExtension(runtime);
}

EtsActionExtension::EtsActionExtension(const std::unique_ptr<Runtime> &runtime)
{
    std::shared_ptr<UIExtensionBaseImpl> uiExtensionBaseImpl = std::make_shared<EtsUIExtensionBase>(runtime);
    SetUIExtensionBaseImpl(uiExtensionBaseImpl);
}

EtsActionExtension::~EtsActionExtension()
{
    TAG_LOGD(AAFwkTag::ACTION_EXT, "destructor");
}
} // namespace AbilityRuntime
} // namespace OHOS

ETS_EXPORT extern "C" OHOS::AbilityRuntime::ActionExtension *OHOS_ETS_ACTION_Extension_Create(
    const std::unique_ptr<OHOS::AbilityRuntime::Runtime> &runtime)
{
    return OHOS::AbilityRuntime::EtsActionExtension::Create(runtime);
}