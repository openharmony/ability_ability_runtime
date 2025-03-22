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

#include "cj_photo_editor_extension_context.h"

#include "cj_ui_extension_object.h"
#include "cj_photo_editor_extension_impl.h"
#include "cj_common_ffi.h"
#include "pixel_map_impl.h"
#include "image_ffi.h"
#include "hilog_tag_wrapper.h"
#include "js_photo_editor_extension_context.h"

namespace OHOS {
namespace AbilityRuntime {
int32_t CJPhotoEditorExtensionContext::SaveEditedContentWithUri(const std::string& uri, AAFwk::Want& want)
{
    TAG_LOGD(AAFwkTag::UI_EXT, "SaveEditedContentWithUri begin");
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Context is released");
        return static_cast<int32_t>(PhotoEditorErrorCode::ERROR_CODE_INTERNAL_ERROR);
    }

    if (want_.lock() == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "PhotoEditorExtensionContext does not call SetWant");
        return static_cast<int32_t>(PhotoEditorErrorCode::ERROR_CODE_INTERNAL_ERROR);
    }

    PhotoEditorErrorCode errCode = context->SaveEditedContent(uri, want);
    return static_cast<int32_t>(errCode);
}

int32_t CJPhotoEditorExtensionContext::SaveEditedContentWithImage(std::shared_ptr<Media::PixelMap> image,
    const Media::PackOption& packOption, AAFwk::Want& want)
{
    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "Context is released");
        return static_cast<int32_t>(PhotoEditorErrorCode::ERROR_CODE_INTERNAL_ERROR);
    }

    if (want_.lock() == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "PhotoEditorExtensionContext does not call SetWant");
        return static_cast<int32_t>(PhotoEditorErrorCode::ERROR_CODE_INTERNAL_ERROR);
    }

    PhotoEditorErrorCode errCode = context->SaveEditedContent(image, packOption, want);
    return static_cast<int32_t>(errCode);
}

extern "C" {
CJ_EXPORT int32_t FFIPhotoExtAbilityGetContext(ExtAbilityHandle extAbility, int64_t* id)
{
    auto ability = static_cast<CJPhotoEditorExtensionImpl*>(extAbility);
    if (ability == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJPhotoEditorExtensionContext failed, extAbility is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    if (id == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJPhotoEditorExtensionContext failed, param id is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto context = ability->GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJPhotoEditorExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto cjContext = OHOS::FFI::FFIData::Create<CJPhotoEditorExtensionContext>(context);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJPhotoEditorExtensionContext failed, extAbilityContext is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    ability->SetCjContext(cjContext);
    *id = cjContext->GetID();
    return SUCCESS_CODE;
}

CJ_EXPORT int32_t FFIPhotoExtCtxSaveEditedContentWithUri(int64_t id, const char* uri, WantHandle want)
{
    if (uri == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param uri is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param want is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto cjContext = OHOS::FFI::FFIData::GetData<CJPhotoEditorExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJPhotoEditorExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);
    return cjContext->SaveEditedContentWithUri(std::string(uri), *actualWant);
}

static Media::PackOption ParseCPackOption(const CPackingOption& option)
{
    return Media::PackOption {
        .format = option.format,
        .quality = option.quality,
        .desiredDynamicRange = Media::EncodeDynamicRange(option.desiredDynamicRange),
        .needsPackProperties = option.needsPackProperties,
    };
}

CJ_EXPORT int32_t FFIPhotoExtCtxSaveEditedContentWithImage(int64_t id, int64_t imageId, CPackingOption option,
    WantHandle want)
{
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param want is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto cjContext = OHOS::FFI::FFIData::GetData<CJPhotoEditorExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJPhotoEditorExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto pixelMapImpl = OHOS::FFI::FFIData::GetData<Media::PixelMapImpl>(imageId);
    if (pixelMapImpl == nullptr || pixelMapImpl->GetRealPixelMap() == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetPixelMapImpl result is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);

    return cjContext->SaveEditedContentWithImage(pixelMapImpl->GetRealPixelMap(), ParseCPackOption(option),
        *actualWant);
}

CJ_EXPORT napi_value FfiConvertPhotoExtCtx2Napi(napi_env env, int64_t id)
{
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);
    auto cjPhotoExtCtx = OHOS::FFI::FFIData::GetData<CJPhotoEditorExtensionContext>(id);
    if (cjPhotoExtCtx == nullptr || cjPhotoExtCtx->GetContext() == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "cj context null ptr");
        return undefined;
    }

    napi_value result = JsPhotoEditorExtensionContext::CreateJsPhotoEditorExtensionContext(
        env, cjPhotoExtCtx->GetContext());
    if (result == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null object");
        return undefined;
    }
    auto workContext = new (std::nothrow) std::weak_ptr<PhotoEditorExtensionContext>(cjPhotoExtCtx->GetContext());
    napi_status status = napi_wrap(
        env, result, workContext,
        [](napi_env, void *data, void *) {
            TAG_LOGD(AAFwkTag::UI_EXT, "Finalizer called");
            if (data == nullptr) {
                TAG_LOGE(AAFwkTag::UI_EXT, "null data");
                return;
            }
            delete static_cast<std::weak_ptr<PhotoEditorExtensionContext> *>(data);
        },
        nullptr, nullptr);
    if (status != napi_ok && workContext != nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "napi_wrap Failed: %{public}d", status);
        delete workContext;
        return undefined;
    }
    napi_value falseValue = nullptr;
    napi_get_boolean((napi_env)env, true, &falseValue);
    napi_set_named_property((napi_env)env, result, "stageMode", falseValue);
    return result;
}

CJ_EXPORT int64_t FfiCreatePhotoExtCtxFromNapi(napi_env env, napi_value cjPhotoContext)
{
    if (env == nullptr || cjPhotoContext == nullptr) {
        return ERR_INVALID_INSTANCE_CODE;
    }

    napi_valuetype type;
    if (napi_typeof(env, cjPhotoContext, &type) || type != napi_object) {
        return ERR_INVALID_INSTANCE_CODE;
    }

    std::weak_ptr<PhotoEditorExtensionContext>* context = nullptr;
    napi_status status = napi_unwrap(env, cjPhotoContext, reinterpret_cast<void**>(&context));
    if (status != napi_ok) {
        return ERR_INVALID_INSTANCE_CODE;
    }

    if (context == nullptr || (*context).lock() == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null context");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto cjContext = OHOS::FFI::FFIData::Create<CJPhotoEditorExtensionContext>((*context).lock());
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::CONTEXT, "null cjContext");
        return ERR_INVALID_INSTANCE_CODE;
    }
    return cjContext->GetID();
}
}
} // namespace AbilityRuntime
} // namespace OHOS
