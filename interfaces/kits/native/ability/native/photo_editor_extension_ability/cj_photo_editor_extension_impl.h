/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_ABILITY_RUNTIME_CJ_PHOTO_EDITOR_EXTENSION_IMPL_H
#define OHOS_ABILITY_RUNTIME_CJ_PHOTO_EDITOR_EXTENSION_IMPL_H

#include "cj_ui_extension_base.h"
#include "cj_photo_editor_extension_context.h"
#include <set>

namespace OHOS {
namespace AbilityRuntime {

class PhotoEditorExtensionContext;

class CJPhotoEditorExtensionImpl : public CJUIExtensionBase {
public:
    explicit CJPhotoEditorExtensionImpl(const std::unique_ptr<Runtime> &runtime);
    virtual ~CJPhotoEditorExtensionImpl() override = default;

    void SetContext(const std::shared_ptr<PhotoEditorExtensionContext> &context)
    {
        context_ = context;
        CJUIExtensionBase::SetContext(context);
    }

    std::shared_ptr<PhotoEditorExtensionContext> GetContext() const
    {
        return context_;
    }

    void SetCjContext(sptr<CJPhotoEditorExtensionContext> cjContext)
    {
        cjContext_ = cjContext;
    }

protected:
    void OnForeground(const Want &want, sptr<AAFwk::SessionInfo> sessionInfo) override;

private:
    void OnStartContentEditing(const AAFwk::Want &want, const sptr<AAFwk::SessionInfo> &sessionInfo);

protected:
    std::shared_ptr<PhotoEditorExtensionContext> context_ = nullptr;
    sptr<CJPhotoEditorExtensionContext> cjContext_;
    std::set<uint64_t> uiExtensionComponentIdSet_;
private:
    using CJUIExtensionBase::SetContext;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // OHOS_ABILITY_RUNTIME_CJ_PHOTO_EDITOR_EXTENSION_IMPL_H
