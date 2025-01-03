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

#include "cj_ui_extension_context.h"

#include "ability_manager_client.h"
#include "ability_manager_errors.h"
#include "event_handler.h"
#include "hilog_tag_wrapper.h"
#include "hitrace_meter.h"
#include "open_link_options.h"
#include "start_options.h"
#include "uri.h"
#include "ui_extension_servicehost_stub_impl.h"
#include "ui_service_extension_connection_constants.h"
#include "cj_macro.h"
#include "cj_common_ffi.h"
#include "cj_utils_ffi.h"
#include "cj_ability_context_utils.h"
#include "cj_ability_connect_callback_object.h"
#include "cj_ui_extension_base.h"
#include "ability_business_error.h"

namespace OHOS {
namespace AbilityRuntime {
using CJAbilityResultCbFn = void (*)(int64_t, int32_t, CJAbilityResult*);
struct CJAbilityResultCbInfo {
    int64_t lambdaId;
    CJAbilityResultCbFn callback;
};

namespace {
static const std::string APP_LINKING_ONLY = "appLinkingOnly";
static const std::string ATOMIC_SERVICE_PREFIX = "com.atomicservice.";
} // namespace

class CJUIExtensionContextImpl {
public:
    explicit CJUIExtensionContextImpl(const std::shared_ptr<UIExtensionContext> &context)
        : context_(context) {}

    int32_t StartAbility(AAFwk::Want& want);
    int32_t StartAbility(AAFwk::Want& want, const AAFwk::StartOptions& option);
    int32_t StartAbilityForRes(AAFwk::Want& want, int32_t requestCode, const CJAbilityResultCbInfo& cbInfo);
    int32_t StartAbilityForRes(AAFwk::Want& want, const AAFwk::StartOptions& option, int32_t requestCode,
        const CJAbilityResultCbInfo& cbInfo);
    int32_t ConnectServiceExtensionAbility(AAFwk::Want& want, int64_t connectOptId, int64_t& connectionId);
    int32_t DisconnectServiceExtensionAbility(int64_t connectionId);
    int32_t TerminateSelf();
    int32_t TerminateSelfWithResult(AAFwk::Want& want, int32_t resultCode);
    int32_t ReportDrawnCompleted();
    int32_t OpenAtomicService(const std::string& appId, AAFwk::StartOptions& options,
        AAFwk::Want& want, int32_t requestCode, const CJAbilityResultCbInfo& cbInfo);
    int32_t OpenLink(const std::string& link, AAFwk::OpenLinkOptions& options, AAFwk::Want& want,
        int32_t requestCode, const CJAbilityResultCbInfo& cbInfo);

public:
    void CheckStartAbilityInputParam(AAFwk::Want& want);
    void InitDisplayId(AAFwk::Want& want);
    int32_t OpenLinkInner(const AAFwk::Want& want, int requestCode, const std::string& startTime,
        const std::string& link);
public:
    std::weak_ptr<UIExtensionContext> context_;
};

CJUIExtensionContext::CJUIExtensionContext(const std::shared_ptr<UIExtensionContext> &context)
    : CJExtensionContext(context, context->GetAbilityInfo())
{
    impl = std::make_shared<CJUIExtensionContextImpl>(context);
}

void CJUIExtensionContextImpl::CheckStartAbilityInputParam(AAFwk::Want& want)
{
    if (!want.HasParameter(AAFwk::Want::PARAM_BACK_TO_OTHER_MISSION_STACK)) {
        want.SetParam(AAFwk::Want::PARAM_BACK_TO_OTHER_MISSION_STACK, true);
    }
}

void CJUIExtensionContextImpl::InitDisplayId(AAFwk::Want& want)
{
#ifdef SUPPORT_SCREEN
    auto context = context_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return;
    }

    auto window = context->GetWindow();
    if (window == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null window");
        return;
    }

    want.SetParam(AAFwk::Want::PARAM_RESV_DISPLAY_ID, static_cast<int32_t>(window->GetDisplayId()));
#endif // SUPPORT_SCREEN
}

int32_t CJUIExtensionContextImpl::StartAbility(AAFwk::Want& want)
{
    CheckStartAbilityInputParam(want);

    InitDisplayId(want);
    auto context = context_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }

    return context->StartAbility(want);
}

int32_t CJUIExtensionContextImpl::StartAbility(AAFwk::Want& want, const AAFwk::StartOptions& option)
{
    CheckStartAbilityInputParam(want);

    InitDisplayId(want);
    auto context = context_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    return context->StartAbility(want, option);
}

static RuntimeTask WrapRuntimeTask(const CJAbilityResultCbInfo& cbInfo)
{
    RuntimeTask task = [cbInfo]
        (int32_t resultCode, const AAFwk::Want& want, bool isInner) {
        WantHandle wantHandle = const_cast<AAFwk::Want*>(&want);
        CJAbilityResult abilityResult = { resultCode, wantHandle };

        int32_t error;
        if (isInner) {
            error = static_cast<int32_t>(GetJsErrorCodeByNativeError(resultCode));
        } else {
            error = SUCCESS_CODE;
        }
        cbInfo.callback(cbInfo.lambdaId, error, &abilityResult);

        TAG_LOGD(AAFwkTag::CONTEXT, "resultCode: %{public}d", resultCode);
    };
    return task;
}

int32_t CJUIExtensionContextImpl::StartAbilityForRes(AAFwk::Want& want, int32_t requestCode,
    const CJAbilityResultCbInfo& cbInfo)
{
    CheckStartAbilityInputParam(want);

    InitDisplayId(want);
    auto context = context_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }

    RuntimeTask task = WrapRuntimeTask(cbInfo);
    want.SetParam(AAFwk::Want::PARAM_RESV_FOR_RESULT, true);
    return context->StartAbilityForResult(want, requestCode, std::move(task));
}

int32_t CJUIExtensionContextImpl::StartAbilityForRes(AAFwk::Want& want, const AAFwk::StartOptions& option,
    int32_t requestCode, const CJAbilityResultCbInfo& cbInfo)
{
    CheckStartAbilityInputParam(want);

    InitDisplayId(want);
    auto context = context_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }

    RuntimeTask task = WrapRuntimeTask(cbInfo);
    want.SetParam(AAFwk::Want::PARAM_RESV_FOR_RESULT, true);
    return context->StartAbilityForResult(want, option, requestCode, std::move(task));
}

int32_t CJUIExtensionContextImpl::ConnectServiceExtensionAbility(AAFwk::Want& want, int64_t connectOptId,
    int64_t& connectionId)
{
    auto connection = CJAbilityConnectCallback::Create(connectOptId, want);
    if (connection == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null connection");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }

    int64_t connectId = connection->GetConnectionId();

    auto context = context_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }

    auto innerErrCode = context->ConnectAbility(want, connection);
    if (innerErrCode == static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT)) {
        CJAbilityConnectCallback::Remove(connectId);
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    int32_t errCode = static_cast<int32_t>(AbilityRuntime::GetJsErrorCodeByNativeError(innerErrCode));
    if (errCode) {
        connection->OnFailed(errCode);
        CJAbilityConnectCallback::Remove(connectId);
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }
    connectionId = connectId;
    return static_cast<int32_t>(AbilityErrorCode::ERROR_OK);
}

int32_t CJUIExtensionContextImpl::DisconnectServiceExtensionAbility(int64_t connectionId)
{
    AAFwk::Want want;
    sptr<CJAbilityConnectCallback> connection = nullptr;
    CJAbilityConnectCallback::FindConnection(want, connection, connectionId);

    if (!connection) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null connection");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INNER);
    }

    auto context = context_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    auto innerErrCode = context->DisconnectAbility(want, connection);
    return static_cast<int32_t>(innerErrCode);
}

int32_t CJUIExtensionContextImpl::TerminateSelf()
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    return static_cast<int32_t>(context->TerminateSelf());
}

int32_t CJUIExtensionContextImpl::TerminateSelfWithResult(AAFwk::Want& want, int32_t resultCode)
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    auto token = context->GetToken();
    AAFwk::AbilityManagerClient::GetInstance()->TransferAbilityResultForExtension(token, resultCode, want);
    sptr<Rosen::Window> uiWindow = context->GetWindow();
    if (!uiWindow) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null uiWindow");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
    }
    auto ret = uiWindow->TransferAbilityResult(resultCode, want);
    if (ret != Rosen::WMError::WM_OK) {
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
    }
    return static_cast<int32_t>(GetJsErrorCodeByNativeError(context->TerminateSelf()));
}

int32_t CJUIExtensionContextImpl::ReportDrawnCompleted()
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }
    return static_cast<int32_t>(GetJsErrorCodeByNativeError(context->ReportDrawnCompleted()));
}

int32_t CJUIExtensionContextImpl::OpenAtomicService(const std::string& appId, AAFwk::StartOptions& options,
    AAFwk::Want& want, int32_t requestCode, const CJAbilityResultCbInfo& cbInfo)
{
    std::string bundleName = ATOMIC_SERVICE_PREFIX + appId;
    TAG_LOGD(AAFwkTag::UI_EXT, "bundleName: %{public}s", bundleName.c_str());
    want.SetBundle(bundleName);

#ifdef SUPPORT_SCREEN
    InitDisplayId(want);
#endif

    want.AddFlags(AAFwk::Want::FLAG_INSTALL_ON_DEMAND);
    std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
        system_clock::now().time_since_epoch()).count());
    want.SetParam(AAFwk::Want::PARAM_RESV_START_TIME, startTime);

    auto context = context_.lock();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }

    RuntimeTask task = WrapRuntimeTask(cbInfo);
    want.SetParam(AAFwk::Want::PARAM_RESV_FOR_RESULT, true);
    context->OpenAtomicService(want, options, requestCode, std::move(task));
    return SUCCESS_CODE;
}

static inline bool CheckUrl(const std::string &urlValue)
{
    if (urlValue.empty()) {
        return false;
    }
    Uri uri = Uri(urlValue);
    if (uri.GetScheme().empty() || uri.GetHost().empty()) {
        return false;
    }

    return true;
}

int32_t CJUIExtensionContextImpl::OpenLink(const std::string& link, AAFwk::OpenLinkOptions& options, AAFwk::Want& want,
    int32_t requestCode, const CJAbilityResultCbInfo& cbInfo)
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }

    if (!CheckUrl(link)) {
        TAG_LOGE(AAFwkTag::UI_EXT, "link parameter invalid");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_PARAM);
    }

    want.SetUri(link);
    std::string startTime = std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::
        system_clock::now().time_since_epoch()).count());
    want.SetParam(AAFwk::Want::PARAM_RESV_START_TIME, startTime);

    if (cbInfo.lambdaId > 0) {
        RuntimeTask task = WrapRuntimeTask(cbInfo);
        want.SetParam(AAFwk::Want::PARAM_RESV_FOR_RESULT, true);
        context->InsertResultCallbackTask(requestCode, std::move(task));
    }

#ifdef SUPPORT_SCREEN
    InitDisplayId(want);
#endif

    return OpenLinkInner(want, requestCode, startTime, link);
}

int32_t CJUIExtensionContextImpl::OpenLinkInner(const AAFwk::Want& want, int requestCode, const std::string& startTime,
    const std::string& link)
{
    auto context = context_.lock();
    if (!context) {
        TAG_LOGE(AAFwkTag::UI_EXT, "null context");
        return static_cast<int32_t>(AbilityErrorCode::ERROR_CODE_INVALID_CONTEXT);
    }

    auto innerErrCode = context->OpenLink(want, requestCode);
    if (innerErrCode == 0) {
        return SUCCESS_CODE;
    }

    if (innerErrCode == AAFwk::ERR_OPEN_LINK_START_ABILITY_DEFAULT_OK) {
        TAG_LOGI(AAFwkTag::UI_EXT, "start ability by default succeeded");
        return SUCCESS_CODE;
    }

    TAG_LOGI(AAFwkTag::UI_EXT, "OpenLink failed");
    context->RemoveResultCallbackTask(requestCode);
    return static_cast<int32_t>(innerErrCode);
}

extern "C" {
CJ_EXPORT int32_t FFICJUIExtAbilityGetContext(ExtAbilityHandle extAbility, int64_t* id)
{
    auto ability = static_cast<CJUIExtensionBase*>(extAbility);
    if (ability == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, extAbility is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    if (id == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, id is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto context = ability->GetContext();
    if (context == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    auto cjContext = OHOS::FFI::FFIData::Create<CJUIExtensionContext>(context);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, extAbilityContext is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }
    *id = cjContext->GetID();
    return SUCCESS_CODE;
}

CJ_EXPORT int32_t FFICJUIExtCtxStartAbility(int64_t id, WantHandle want)
{
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param want is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto cjContext = OHOS::FFI::FFIData::GetData<CJUIExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);
    return cjContext->impl->StartAbility(*actualWant);
}

static AAFwk::StartOptions UnWrapStartOption(CJNewStartOptions* paramOpt)
{
    AAFwk::StartOptions option;
    option.SetWindowMode(paramOpt->windowMode);
    option.SetDisplayID(paramOpt->displayId);
    option.SetWithAnimation(paramOpt->withAnimation);
    option.SetWindowLeft(paramOpt->windowLeft);
    option.windowLeftUsed_ = true;
    option.SetWindowTop(paramOpt->windowTop);
    option.windowTopUsed_ = true;
    option.SetWindowWidth(paramOpt->windowWidth);
    option.windowWidthUsed_ = true;
    option.SetWindowHeight(paramOpt->windowHeight);
    option.windowHeightUsed_ = true;
    return option;
}

CJ_EXPORT int32_t FFICJUIExtCtxStartAbilityWithOpt(int64_t id, WantHandle want, CJNewStartOptions* paramOpt)
{
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param want is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    if (paramOpt == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param paramOpt is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto cjContext = OHOS::FFI::FFIData::GetData<CJUIExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);

    AAFwk::StartOptions option = UnWrapStartOption(paramOpt);
    return cjContext->impl->StartAbility(*actualWant, option);
}

CJ_EXPORT int32_t FFICJUIExtCtxStartAbilityForRes(int64_t id, WantHandle want, int32_t requestCode,
    CJAbilityResultCbInfo* cbInfo)
{
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param want is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    if (cbInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param cbInfo is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto cjContext = OHOS::FFI::FFIData::GetData<CJUIExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);
    return cjContext->impl->StartAbilityForRes(*actualWant, requestCode, *cbInfo);
}

CJ_EXPORT int32_t FFICJUIExtCtxStartAbilityForResWithOpt(int64_t id, WantHandle want, CJNewStartOptions* paramOpt,
    int32_t requestCode, CJAbilityResultCbInfo* cbInfo)
{
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param want is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    if (paramOpt == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param paramOpt is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    if (cbInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param cbInfo is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto cjContext = OHOS::FFI::FFIData::GetData<CJUIExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);

    AAFwk::StartOptions option = UnWrapStartOption(paramOpt);
    return cjContext->impl->StartAbilityForRes(*actualWant, option, requestCode, *cbInfo);
}

CJ_EXPORT int32_t FFICJUIExtCtxConnectServiceExtensionAbility(int64_t id, WantHandle want, int64_t connectOptId,
    int64_t* connectionId)
{
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param want is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    if (connectionId == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param connectionId is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto cjContext = OHOS::FFI::FFIData::GetData<CJUIExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);

    return cjContext->impl->ConnectServiceExtensionAbility(*actualWant, connectOptId, *connectionId);
}

CJ_EXPORT int32_t FFICJUIExtCtxDisconnectServiceExtensionAbility(int64_t id, int64_t connectionId)
{
    auto cjContext = OHOS::FFI::FFIData::GetData<CJUIExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    return cjContext->impl->DisconnectServiceExtensionAbility(connectionId);
}

CJ_EXPORT int32_t FFICJUIExtCtxTerminateSelf(int64_t id)
{
    auto cjContext = OHOS::FFI::FFIData::GetData<CJUIExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    return cjContext->impl->TerminateSelf();
}

CJ_EXPORT int32_t FFICJUIExtCtxTerminateSelfWithResult(int64_t id, WantHandle want, int32_t resultCode)
{
    if (want == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param want is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto cjContext = OHOS::FFI::FFIData::GetData<CJUIExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto actualWant = reinterpret_cast<AAFwk::Want*>(want);

    return cjContext->impl->TerminateSelfWithResult(*actualWant, resultCode);
}

CJ_EXPORT int32_t FFICJUIExtCtxReportDrawnCompleted(int64_t id)
{
    auto cjContext = OHOS::FFI::FFIData::GetData<CJUIExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    return cjContext->impl->ReportDrawnCompleted();
}

CJ_EXPORT int32_t FFICJUIExtCtxOpenAtomicService(int64_t id, char* cAppId,
    CJAtomicServiceOptions* cAtomicServiceOptions, int32_t requestCode, CJAbilityResultCbInfo* cbInfo)
{
    if (cAppId == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param cAppId is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    if (cAtomicServiceOptions == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param cAtomicServiceOptions is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    if (cbInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param cbInfo is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto cjContext = OHOS::FFI::FFIData::GetData<CJUIExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    AAFwk::Want want;
    AAFwk::StartOptions options;
    if (cAtomicServiceOptions->hasValue) {
        AAFwk::WantParams wantParams =
            OHOS::AAFwk::WantParamWrapper::ParseWantParamsWithBrackets(cAtomicServiceOptions->parameters);
        want.SetParams(wantParams);
        if (cAtomicServiceOptions->flags != 0) {
            want.SetFlags(cAtomicServiceOptions->flags);
        }
        options = UnWrapStartOption(&cAtomicServiceOptions->startOptions);
    }

    return cjContext->impl->OpenAtomicService(std::string(cAppId), options, want, requestCode, *cbInfo);
}

static AAFwk::OpenLinkOptions UnwrapOpenLinkOptions(CJOpenLinkOptions* cOpenLinkOptions, AAFwk::Want& want)
{
    AAFwk::OpenLinkOptions options;

    want.SetParam(APP_LINKING_ONLY, false);
    if (cOpenLinkOptions->hasValue) {
        if (cOpenLinkOptions->parameters != nullptr) {
            AAFwk::WantParams wantParams = AAFwk::WantParamWrapper::ParseWantParamsWithBrackets(
                cOpenLinkOptions->parameters);
            want.SetParams(wantParams);
        }
        options.SetAppLinkingOnly(cOpenLinkOptions->appLinkingOnly);
        want.SetParam(APP_LINKING_ONLY, cOpenLinkOptions->appLinkingOnly);
    }

    return options;
}

CJ_EXPORT int32_t FFICJUIExtCtxOpenLink(int64_t id, char* cLink, CJOpenLinkOptions* cOpenLinkOptions,
    int32_t requestCode, CJAbilityResultCbInfo* cbInfo)
{
    if (cLink == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param cLink is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    if (cOpenLinkOptions == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param cOpenLinkOptions is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    if (cbInfo == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "input param cbInfo is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    auto cjContext = OHOS::FFI::FFIData::GetData<CJUIExtensionContext>(id);
    if (cjContext == nullptr) {
        TAG_LOGE(AAFwkTag::UI_EXT, "GetCJUIExtensionContext failed, context is nullptr");
        return ERR_INVALID_INSTANCE_CODE;
    }

    AAFwk::Want want;
    AAFwk::OpenLinkOptions options = UnwrapOpenLinkOptions(cOpenLinkOptions, want);
    return cjContext->impl->OpenLink(std::string(cLink), options, want, requestCode, *cbInfo);
}
}
}  // namespace AbilityRuntime
}  // namespace OHOS
