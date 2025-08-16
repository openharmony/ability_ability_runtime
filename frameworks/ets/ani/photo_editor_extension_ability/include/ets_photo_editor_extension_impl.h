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

#ifndef OHOS_ABILITY_RUNTIME_ETS_PHOTO_EDITOR_EXTENSION_IMPL_H
#define OHOS_ABILITY_RUNTIME_ETS_PHOTO_EDITOR_EXTENSION_IMPL_H

#include <set>
#include "ani.h"
#include "ets_native_reference.h"
#include "ets_ui_extension.h"
#include "photo_editor_extension_context.h"
#include "ets_ui_extension_base.h"


namespace OHOS {
namespace AbilityRuntime {

class PhotoEditorExtensionContext;

class EtsPhotoEditorExtensionImpl : public EtsUIExtensionBase {
public:
    explicit EtsPhotoEditorExtensionImpl(const std::unique_ptr<Runtime> &etsRuntime);
    virtual ~EtsPhotoEditorExtensionImpl() override = default;

    void SetContext(const std::shared_ptr<PhotoEditorExtensionContext> &context)
    {
        context_ = context;
        EtsUIExtensionBase::SetContext(context);
    }

protected:
    void BindContext() override;
    void OnForeground(const Want &want, sptr<AAFwk::SessionInfo> sessionInfo) override;

private:
    void OnStartContentEditing(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo);
    ani_object CreateETSContext(ani_env *env, std::shared_ptr<PhotoEditorExtensionContext> context);
protected:
    std::shared_ptr<PhotoEditorExtensionContext> context_ = nullptr;
    std::set<uint64_t> uiExtensionComponentIdSet_;

private:
    using EtsUIExtensionBase::SetContext;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_ETS_PHOTO_EDITOR_EXTENSION_IMPL_H