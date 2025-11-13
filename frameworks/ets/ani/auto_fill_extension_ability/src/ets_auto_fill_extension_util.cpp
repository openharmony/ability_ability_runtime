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

#include "ets_auto_fill_extension_util.h"

#include "ani_common_util.h"
#include "ani_common_want.h"
#include "ani_enum_convert.h"
#include "hilog_tag_wrapper.h"
#include "want_params_wrapper.h"

namespace OHOS {
namespace AbilityRuntime {
namespace {
constexpr const char *FILL_REQUEST_CLASS_NAME = "Lapplication/AutoFillRequest/FillRequestInner;";
constexpr const char *SAVE_REQUEST_CLASS_NAME = "Lapplication/AutoFillRequest/SaveRequestInner;";
constexpr const char *UPDATE_REQUEST_CLASS_NAME = "Lapplication/AutoFillRequest/UpdateRequestInner;";
constexpr const char *VIEW_DATA_CLASS_NAME = "Lapplication/ViewData/ViewDataImpl;";
constexpr const char *ARRAY_CLASS_NAME = "Lescompat/Array;";
constexpr const char *PAGE_NODE_INFO_CLASS_NAME = "Lapplication/PageNodeInfo/PageNodeInfoImpl;";
constexpr const char *AUTO_FILL_RECT_CLASS_NAME = "Lapplication/AutoFillRect/AutoFillRectImpl;";
constexpr const char *CUSTOM_DATA_CLASS_NAME = "Lapplication/CustomData/CustomDataInner;";
constexpr const char *AUTO_FILL_TYPE_ENUM_NAME = "Lapplication/AutoFillType/AutoFillType;";
constexpr const char *VIEW_DATA_BUNDLE_NAME = "bundleName";
constexpr const char *VIEW_DATA_MODULE_NAME = "moduleName";
constexpr const char *VIEW_DATA_ABILITY_NAME = "abilityName";
constexpr const char *VIEW_DATA_PAGEURL = "pageUrl";
constexpr const char *VIEW_DATA_USER_SELECTED = "isUserSelected";
constexpr const char *VIEW_DATA_OTHER_ACCOUNT = "isOtherAccount";
constexpr const char *VIEW_DATA_PAGE_NODE_INFOS = "pageNodeInfos";
constexpr const char *VIEW_DATA_VIEW_DATA = "viewData";
constexpr const char *VIEW_DATA_TYPE = "type";
constexpr const char *VIEW_DATA_PAGE_RECT = "pageRect";
constexpr const char *CUSTOM_DATA_CUSTOM_DATA = "customData";
constexpr const char *CUSTOM_DATA_DATA = "data";
constexpr const char *PAGE_INFO_ID = "id";
constexpr const char *PAGE_INFO_DEPTH = "depth";
constexpr const char *PAGE_INFO_AUTOFILLTYPE = "autoFillType";
constexpr const char *PAGE_INFO_TAG = "tag";
constexpr const char *PAGE_INFO_VALUE = "value";
constexpr const char *PAGE_INFO_PLACEHOLDER = "placeholder";
constexpr const char *PAGE_INFO_META_DATA = "metadata";
constexpr const char *PAGE_INFO_PASSWORDRULES = "passwordRules";
constexpr const char *PAGE_INFO_ENABLEAUTOFILL = "enableAutoFill";
constexpr const char *PAGE_INFO_IS_FOCUS = "isFocus";
constexpr const char *PAGE_INFO_PAGE_NODE_RECT = "rect";
constexpr const char *WANT_PARAMS_VIEW_DATA = "ohos.ability.params.viewData";
constexpr const char *WANT_PARAMS_CUSTOM_DATA = "ohos.ability.params.customData";
constexpr const char *WANT_PARAMS_AUTO_FILL_TYPE_KEY = "ability.want.params.AutoFillType";
constexpr const char *WANT_PARAMS_AUTO_FILL_POPUP_WINDOW_KEY = "ohos.ability.params.popupWindow";
constexpr const char *WANT_PARAMS_IS_POPUP = "isPopup";
constexpr const char *RECT_POSITION_LEFT = "left";
constexpr const char *RECT_POSITION_TOP = "top";
constexpr const char *RECT_WIDTH = "width";
constexpr const char *RECT_HEIGHT = "height";
constexpr uint32_t PAGE_NODE_COUNT_MAX = 100;
constexpr const char *WANT_PARAMS_AUTO_FILL_TRIGGER_TYPE_KEY = "ability.want.params.AutoFillTriggerType";
constexpr const char *TRIGGER_TYPE = "triggerType";
constexpr const char *AUTO_FILL_TRIGGER_TYPE_ENUM_NAME = "Lapplication/AutoFillTriggerType/AutoFillTriggerType;";
} // namespace

ani_object EtsAutoFillExtensionUtil::WrapFillRequest(ani_env *env, const AAFwk::Want &want)
{
    ani_object etsObject = nullptr;
    if (!CreateObject(env, etsObject, FILL_REQUEST_CLASS_NAME)) {
        return nullptr;
    }
    return SetFillRequest(env, etsObject, want);
}

ani_object EtsAutoFillExtensionUtil::WrapSaveRequest(ani_env *env, const AAFwk::Want &want)
{
    ani_object etsObject = nullptr;
    if (!CreateObject(env, etsObject, SAVE_REQUEST_CLASS_NAME)) {
        return nullptr;
    }
    return SetSaveRequest(env, etsObject, want);
}

ani_object EtsAutoFillExtensionUtil::WrapUpdateRequest(ani_env *env, const AAFwk::WantParams &wantParams)
{
    ani_object etsObject = nullptr;
    if (!CreateObject(env, etsObject, UPDATE_REQUEST_CLASS_NAME)) {
        return nullptr;
    }
    std::string viewDataString = wantParams.GetStringParam(WANT_PARAMS_VIEW_DATA);
    if (viewDataString.empty()) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "empty view data");
        return etsObject;
    }
    AbilityBase::ViewData viewData;
    viewData.FromJsonString(viewDataString);
    ani_object viewDataValue = WrapViewData(env, viewData);
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Ref(etsObject, VIEW_DATA_VIEW_DATA, viewDataValue)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
    }
    return etsObject;
}

ani_object EtsAutoFillExtensionUtil::WrapViewData(ani_env *env, const AbilityBase::ViewData &viewData)
{
    ani_object etsObject = nullptr;
    if (!CreateObject(env, etsObject, VIEW_DATA_CLASS_NAME)) {
        return nullptr;
    }
    return SetViewData(env, etsObject, viewData);
}

ani_object EtsAutoFillExtensionUtil::WrapPageNodeInfo(ani_env *env, const AbilityBase::PageNodeInfo &pageNodeInfo)
{
    ani_object etsObject = nullptr;
    if (!CreateObject(env, etsObject, PAGE_NODE_INFO_CLASS_NAME)) {
        return nullptr;
    }
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Int(etsObject, PAGE_INFO_ID,
        static_cast<ani_int>(pageNodeInfo.id))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return etsObject;
    }
    if ((status = env->Object_SetPropertyByName_Int(etsObject, PAGE_INFO_DEPTH,
        static_cast<ani_int>(pageNodeInfo.depth))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return etsObject;
    }
    ani_enum_item autoFillTypeItem = nullptr;
    AAFwk::AniEnumConvertUtil::EnumConvert_NativeToEts(env, AUTO_FILL_TYPE_ENUM_NAME, pageNodeInfo.autoFillType,
        autoFillTypeItem);
    if ((status = env->Object_SetPropertyByName_Ref(etsObject, PAGE_INFO_AUTOFILLTYPE, autoFillTypeItem)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return etsObject;
    }
    return SetPageNodeInfo(env, etsObject, pageNodeInfo);
}

ani_object EtsAutoFillExtensionUtil::WrapRectData(ani_env *env, const AbilityBase::Rect &rect)
{
    ani_object etsObject = nullptr;
    if (!CreateObject(env, etsObject, AUTO_FILL_RECT_CLASS_NAME)) {
        return nullptr;
    }
    return SetRectData(env, etsObject, rect);
}

ani_object EtsAutoFillExtensionUtil::WrapCustomData(ani_env *env, const AAFwk::WantParams &param)
{
    ani_object etsObject = nullptr;
    if (!CreateObject(env, etsObject, CUSTOM_DATA_CLASS_NAME)) {
        return nullptr;
    }
    ani_ref etsValue = AppExecFwk::WrapWantParams(env, param);
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Ref(etsObject, CUSTOM_DATA_DATA, etsValue)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
    }
    return etsObject;
}

void EtsAutoFillExtensionUtil::UnwrapViewData(ani_env *env, const ani_object object, AbilityBase::ViewData &viewData)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_ref etsViewData = nullptr;
    if ((status = env->Object_GetPropertyByName_Ref(object, VIEW_DATA_VIEW_DATA, &etsViewData)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "Object_GetPropertyByName_Ref failed, status: %{public}d", status);
        return;
    }
    if (etsViewData == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null etsViewData");
        return;
    }
    UnwrapViewDataString(env, static_cast<ani_object>(etsViewData), viewData);
    UnwrapViewDataBoolean(env, static_cast<ani_object>(etsViewData), viewData);
    ani_ref pageNode = nullptr;
    if ((status = env->Object_GetPropertyByName_Ref(static_cast<ani_object>(etsViewData), VIEW_DATA_PAGE_NODE_INFOS,
        &pageNode)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "Object_GetPropertyByName_Ref failed, status: %{public}d", status);
        return;
    }
    if (pageNode != nullptr) {
        ani_size length = 0;
        if ((status = env->Array_GetLength(reinterpret_cast<ani_array>(pageNode), &length)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "Array_GetLength failed, status: %{public}d", status);
            return;
        }
        for (ani_size index = 0; index < length && index < PAGE_NODE_COUNT_MAX; index++) {
            ani_ref etsNode = nullptr;
            if ((status = env->Array_Get_Ref(reinterpret_cast<ani_array_ref>(pageNode), index, &etsNode)) != ANI_OK) {
                TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "Array_Get_Ref failed, status: %{public}d", status);
                return;
            }
            AbilityBase::PageNodeInfo node;
            UnwrapPageNodeInfo(env, static_cast<ani_object>(etsNode), node);
            viewData.nodes.emplace_back(node);
        }
    }
    ani_ref etsPageRect = nullptr;
    if ((status = env->Object_GetPropertyByName_Ref(static_cast<ani_object>(etsViewData), VIEW_DATA_PAGE_RECT,
        &etsPageRect)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "Object_GetPropertyByName_Ref failed, status: %{public}d", status);
        return;
    }
    if (etsPageRect != nullptr) {
        UnwrapRectData(env, static_cast<ani_object>(etsPageRect), viewData.pageRect);
    }
}

void EtsAutoFillExtensionUtil::UnwrapPageNodeInfo(ani_env *env, const ani_object object,
    AbilityBase::PageNodeInfo &node)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_int id = 0;
    if ((status = env->Object_GetPropertyByName_Int(object, PAGE_INFO_ID, &id)) == ANI_OK) {
        TAG_LOGD(AAFwkTag::AUTOFILL_EXT, "id:%{public}d", id);
        node.id = id;
    }
    ani_int depth = 0;
    if ((status = env->Object_GetPropertyByName_Int(object, PAGE_INFO_DEPTH, &depth)) == ANI_OK) {
        TAG_LOGD(AAFwkTag::AUTOFILL_EXT, "depth:%{public}d", depth);
        node.depth = depth;
    }
    ani_ref etsAutoFillType = nullptr;
    if (AppExecFwk::GetRefProperty(env, object, PAGE_INFO_AUTOFILLTYPE, etsAutoFillType) && etsAutoFillType) {
        int32_t autoFillType = 0;
        AAFwk::AniEnumConvertUtil::EnumConvert_EtsToNative(env, static_cast<ani_enum_item>(etsAutoFillType),
            autoFillType);
        TAG_LOGD(AAFwkTag::AUTOFILL_EXT, "autoFillType:%{public}d", autoFillType);
        node.autoFillType = static_cast<AbilityBase::AutoFillType>(autoFillType);
    }
    UnwrapPageNodeInfoString(env, object, node);
    ani_boolean enableAutoFill = ANI_FALSE;
    if ((status = env->Object_GetPropertyByName_Boolean(object, PAGE_INFO_ENABLEAUTOFILL, &enableAutoFill)) ==
        ANI_OK) {
        node.enableAutoFill = static_cast<bool>(enableAutoFill);
    }
    ani_ref etsRect = nullptr;
    if ((status = env->Object_GetPropertyByName_Ref(object, PAGE_INFO_PAGE_NODE_RECT, &etsRect)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "Object_GetPropertyByName_Ref failed, status: %{public}d", status);
        return;
    }
    if (etsRect != nullptr) {
        UnwrapRectData(env, static_cast<ani_object>(etsRect), node.rect);
    }
    ani_boolean isFocus = ANI_FALSE;
    if ((status = env->Object_GetPropertyByName_Boolean(object, PAGE_INFO_IS_FOCUS, &isFocus)) == ANI_OK) {
        node.isFocus = static_cast<bool>(isFocus);
    }
}

void EtsAutoFillExtensionUtil::UnwrapRectData(ani_env *env, const ani_object object, AbilityBase::Rect &rect)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_double position = 0.0;
    if ((status = env->Object_GetPropertyByName_Double(object, RECT_POSITION_LEFT, &position)) == ANI_OK) {
        rect.left = position;
    }
    if ((status = env->Object_GetPropertyByName_Double(object, RECT_POSITION_TOP, &position)) == ANI_OK) {
        rect.top = position;
    }
    if ((status = env->Object_GetPropertyByName_Double(object, RECT_WIDTH, &position)) == ANI_OK) {
        rect.width = position;
    }
    if ((status = env->Object_GetPropertyByName_Double(object, RECT_HEIGHT, &position)) == ANI_OK) {
        rect.height = position;
    }
}

void EtsAutoFillExtensionUtil::UnwrapFillResponse(ani_env *env, const ani_object object, FillResponse &response)
{
    UnwrapViewData(env, object, response.viewData);
}

void EtsAutoFillExtensionUtil::UnwrapPopupSize(ani_env *env, const ani_object object, PopupSize &popupSize)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_double width = 0.0;
    if ((status = env->Object_GetPropertyByName_Double(object, RECT_WIDTH, &width)) == ANI_OK) {
        popupSize.width = width;
    }
    ani_double height = 0.0;
    if ((status = env->Object_GetPropertyByName_Double(object, RECT_HEIGHT, &height)) == ANI_OK) {
        popupSize.height = height;
    }
}

bool EtsAutoFillExtensionUtil::CreateObject(ani_env *env, ani_object &object, const std::string &className)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return false;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(className.c_str(), &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status : %{public}d", status);
        return false;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null cls");
        return false;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", ":V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status : %{public}d", status);
        return false;
    }
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null method");
        return false;
    }
    if ((status = env->Object_New(cls, method, &object)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status : %{public}d", status);
        return false;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null object");
        return false;
    }
    return true;
}

bool EtsAutoFillExtensionUtil::SetCustomDataParam(ani_env *env, ani_object object, const AAFwk::Want &want)
{
    if (env == nullptr || object == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "env or aniObject is null");
        return false;
    }
    if (want.HasParameter(WANT_PARAMS_CUSTOM_DATA)) {
        std::string customDataString = want.GetStringParam(WANT_PARAMS_CUSTOM_DATA);
        if (customDataString.empty()) {
            TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "empty custom data");
            return false;
        }
        if (!AAFwk::WantParamWrapper::ValidateStr(customDataString)) {
            TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "invalid Custom data string");
            return false;
        }
        AAFwk::WantParams param = AAFwk::WantParamWrapper::ParseWantParams(customDataString);
        ani_object customValue = WrapCustomData(env, param);
        ani_status status = ANI_ERROR;
        if ((status = env->Object_SetPropertyByName_Ref(object, CUSTOM_DATA_CUSTOM_DATA, customValue)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
            return false;
        }
    }
    return true;
}

ani_object EtsAutoFillExtensionUtil::SetFillRequest(ani_env *env, ani_object object, const AAFwk::Want &want)
{
    ani_status status = ANI_ERROR;
    if (want.HasParameter(WANT_PARAMS_AUTO_FILL_TYPE_KEY)) {
        auto type = want.GetIntParam(WANT_PARAMS_AUTO_FILL_TYPE_KEY, -1);
        ani_enum_item typeItem = nullptr;
        AAFwk::AniEnumConvertUtil::EnumConvert_NativeToEts(env, AUTO_FILL_TYPE_ENUM_NAME, type, typeItem);
        if ((status = env->Object_SetPropertyByName_Ref(object, VIEW_DATA_TYPE, typeItem)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
            return object;
        }
    }
    if (want.HasParameter(WANT_PARAMS_VIEW_DATA)) {
        std::string viewDataString = want.GetStringParam(WANT_PARAMS_VIEW_DATA);
        if (viewDataString.empty()) {
            TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "empty view data");
            return object;
        }
        AbilityBase::ViewData viewData;
        viewData.FromJsonString(viewDataString);
        ani_object viewDataValue = WrapViewData(env, viewData);
        if ((status = env->Object_SetPropertyByName_Ref(object, VIEW_DATA_VIEW_DATA, viewDataValue)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
            return object;
        }
    }
    if (want.HasParameter(WANT_PARAMS_AUTO_FILL_POPUP_WINDOW_KEY)) {
        auto isPopup = want.GetBoolParam(WANT_PARAMS_AUTO_FILL_POPUP_WINDOW_KEY, false);
        if ((status = env->Object_SetPropertyByName_Boolean(object, WANT_PARAMS_IS_POPUP, isPopup)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
            return object;
        }
    }
    if (!SetCustomDataParam(env, object, want)) {
        return object;
    }
    if (want.HasParameter(WANT_PARAMS_AUTO_FILL_TRIGGER_TYPE_KEY)) {
        auto type = want.GetIntParam(WANT_PARAMS_AUTO_FILL_TRIGGER_TYPE_KEY, -1);
        ani_enum_item typeItem = nullptr;
        AAFwk::AniEnumConvertUtil::EnumConvert_NativeToEts(env, AUTO_FILL_TRIGGER_TYPE_ENUM_NAME, type, typeItem);
        if ((status = env->Object_SetPropertyByName_Ref(object, TRIGGER_TYPE, typeItem)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
            return object;
        }
    }
    return object;
}

ani_object EtsAutoFillExtensionUtil::SetSaveRequest(ani_env *env, ani_object object, const AAFwk::Want &want)
{
    ani_status status = ANI_ERROR;
    if (want.HasParameter(WANT_PARAMS_VIEW_DATA)) {
        std::string viewDataString = want.GetStringParam(WANT_PARAMS_VIEW_DATA);
        if (viewDataString.empty()) {
            TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "empty view data");
            return object;
        }
        AbilityBase::ViewData viewData;
        viewData.FromJsonString(viewDataString);
        ani_object viewDataValue = WrapViewData(env, viewData);
        if ((status = env->Object_SetPropertyByName_Ref(object, VIEW_DATA_VIEW_DATA, viewDataValue)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
            return object;
        }
    }
    return object;
}

ani_object EtsAutoFillExtensionUtil::SetViewData(ani_env *env, ani_object object,
    const AbilityBase::ViewData &viewData)
{
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Ref(object, VIEW_DATA_BUNDLE_NAME,
        AppExecFwk::GetAniString(env, viewData.bundleName))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Ref(object, VIEW_DATA_ABILITY_NAME,
        AppExecFwk::GetAniString(env, viewData.abilityName))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Ref(object, VIEW_DATA_MODULE_NAME,
        AppExecFwk::GetAniString(env, viewData.moduleName))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Ref(object, VIEW_DATA_PAGEURL,
        AppExecFwk::GetAniString(env, viewData.pageUrl))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Boolean(object, VIEW_DATA_USER_SELECTED,
        viewData.isUserSelected)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Boolean(object, VIEW_DATA_OTHER_ACCOUNT,
        viewData.isOtherAccount)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    ani_object arrayObj = nullptr;
    SetViewDataArray(env, arrayObj, viewData);
    ani_object etsRectData = WrapRectData(env, viewData.pageRect);
    if ((status = env->Object_SetPropertyByName_Ref(object, VIEW_DATA_PAGE_RECT, etsRectData)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Ref(object, VIEW_DATA_PAGE_NODE_INFOS, arrayObj)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
    }
    return object;
}

void EtsAutoFillExtensionUtil::SetViewDataArray(ani_env *env, ani_object &object,
    const AbilityBase::ViewData &viewData)
{
    if (env == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null env");
        return;
    }
    ani_status status = ANI_ERROR;
    ani_class cls = nullptr;
    if ((status = env->FindClass(ARRAY_CLASS_NAME, &cls)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status : %{public}d", status);
        return;
    }
    if (cls == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null cls");
        return;
    }
    ani_method method = nullptr;
    if ((status = env->Class_FindMethod(cls, "<ctor>", "I:V", &method)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status : %{public}d", status);
        return;
    }
    if (method == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null method");
        return;
    }
    if ((status = env->Object_New(cls, method, &object, viewData.nodes.size())) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status : %{public}d", status);
        return;
    }
    if (object == nullptr) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null object");
        return;
    }
    ani_object etsSubValue = nullptr;
    ani_size index = 0;
    for (auto &element : viewData.nodes) {
        etsSubValue = WrapPageNodeInfo(env, element);
        if (etsSubValue == nullptr) {
            TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "null etsSubValue");
            break;
        }
        if ((status = env->Object_CallMethodByName_Void(object, "$_set", "ILstd/core/Object;:V", index,
            etsSubValue)) != ANI_OK) {
            TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status : %{public}d", status);
            break;
        }
        index++;
    }
}

ani_object EtsAutoFillExtensionUtil::SetPageNodeInfo(ani_env *env, ani_object object,
    const AbilityBase::PageNodeInfo &pageNodeInfo)
{
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Ref(object, PAGE_INFO_TAG,
        AppExecFwk::GetAniString(env, pageNodeInfo.tag))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Ref(object, PAGE_INFO_VALUE,
        AppExecFwk::GetAniString(env, pageNodeInfo.value))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Ref(object, PAGE_INFO_PASSWORDRULES,
        AppExecFwk::GetAniString(env, pageNodeInfo.passwordRules))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Ref(object, PAGE_INFO_PLACEHOLDER,
        AppExecFwk::GetAniString(env, pageNodeInfo.placeholder))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Ref(object, PAGE_INFO_META_DATA,
        AppExecFwk::GetAniString(env, pageNodeInfo.metadata))) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Boolean(object, PAGE_INFO_ENABLEAUTOFILL,
        pageNodeInfo.enableAutoFill)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    ani_object etsRectData = WrapRectData(env, pageNodeInfo.rect);
    if ((status = env->Object_SetPropertyByName_Ref(object, PAGE_INFO_PAGE_NODE_RECT, etsRectData)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Boolean(object, PAGE_INFO_IS_FOCUS,
        pageNodeInfo.isFocus)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
    }
    return object;
}

ani_object EtsAutoFillExtensionUtil::SetRectData(ani_env *env, ani_object object, const AbilityBase::Rect &rect)
{
    ani_status status = ANI_ERROR;
    if ((status = env->Object_SetPropertyByName_Double(object, RECT_POSITION_LEFT, rect.left)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Double(object, RECT_POSITION_TOP, rect.top)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Double(object, RECT_WIDTH, rect.width)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
        return object;
    }
    if ((status = env->Object_SetPropertyByName_Double(object, RECT_HEIGHT, rect.height)) != ANI_OK) {
        TAG_LOGE(AAFwkTag::AUTOFILL_EXT, "status: %{public}d", status);
    }
    return object;
}

void EtsAutoFillExtensionUtil::UnwrapViewDataString(ani_env *env, const ani_object object,
    AbilityBase::ViewData &viewData)
{
    std::string bundleName = "";
    if (AppExecFwk::GetStringProperty(env, object, VIEW_DATA_BUNDLE_NAME, bundleName)) {
        viewData.bundleName = bundleName;
    }
    std::string moduleName = "";
    if (AppExecFwk::GetStringProperty(env, object, VIEW_DATA_MODULE_NAME, moduleName)) {
        viewData.moduleName = moduleName;
    }
    std::string abilityName = "";
    if (AppExecFwk::GetStringProperty(env, object, VIEW_DATA_ABILITY_NAME, abilityName)) {
        viewData.abilityName = abilityName;
    }
    std::string pageUrl = "";
    if (AppExecFwk::GetStringProperty(env, object, VIEW_DATA_PAGEURL, pageUrl)) {
        viewData.pageUrl = pageUrl;
    }
}

void EtsAutoFillExtensionUtil::UnwrapViewDataBoolean(ani_env *env, const ani_object object,
    AbilityBase::ViewData &viewData)
{
    ani_status status = ANI_ERROR;
    ani_boolean isUserSelected = ANI_FALSE;
    if ((status = env->Object_GetPropertyByName_Boolean(object, VIEW_DATA_USER_SELECTED, &isUserSelected)) == ANI_OK) {
        viewData.isUserSelected = static_cast<bool>(isUserSelected);
    }
    ani_boolean isOtherAccount = ANI_FALSE;
    if ((status = env->Object_GetPropertyByName_Boolean(object, VIEW_DATA_OTHER_ACCOUNT, &isOtherAccount)) == ANI_OK) {
        viewData.isOtherAccount = static_cast<bool>(isOtherAccount);
    }
}

void EtsAutoFillExtensionUtil::UnwrapPageNodeInfoString(ani_env *env, const ani_object object,
    AbilityBase::PageNodeInfo &node)
{
    std::string tag = "";
    if (AppExecFwk::GetStringProperty(env, object, PAGE_INFO_TAG, tag)) {
        node.tag = tag;
    }
    std::string value = "";
    if (AppExecFwk::GetStringProperty(env, object, PAGE_INFO_VALUE, value)) {
        node.value = value;
    }
    std::string passwordRules = "";
    if (AppExecFwk::GetStringProperty(env, object, PAGE_INFO_PASSWORDRULES, passwordRules)) {
        node.passwordRules = passwordRules;
    }
    std::string placeholder = "";
    if (AppExecFwk::GetStringProperty(env, object, PAGE_INFO_PLACEHOLDER, placeholder)) {
        node.placeholder = placeholder;
    }
    std::string metadata = "";
    if (AppExecFwk::GetStringProperty(env, object, PAGE_INFO_META_DATA, metadata)) {
        node.metadata = metadata;
    }
}
} // namespace AbilityRuntime
} // namespace OHOS