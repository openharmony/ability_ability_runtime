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

#ifndef MOCK_OHOS_ABILITY_BASE_WANT_H
#define MOCK_OHOS_ABILITY_BASE_WANT_H

#include <string>
#include <vector>

#include "iremote_object.h"
#include "uri.h"
#include "want_params.h"
#include "element_name.h"
#include "parcel.h"

namespace OHOS {
namespace AAFwk {
class Want final : public RefBase {
public:
    static constexpr unsigned int FLAG_ABILITY_CONTINUATION = 0x00000008;
    static constexpr unsigned int FLAG_INSTALL_ON_DEMAND = 0x00000800;
    static constexpr unsigned int FLAG_ABILITY_PREPARE_CONTINUATION = 0x00001000;

    Want() {}
    unsigned int GetFlags() const
    {
        return 0;
    }
    Want &AddFlags(unsigned int flags)
    {
        return *this;
    }
    Want &SetElementName(const std::string &bundleName, const std::string &abilityName)
    {
        return *this;
    }

    Want &SetElementName(const std::string &deviceId, const std::string &bundleName,
        const std::string &abilityName, const std::string &moduleName = "")
    {
        return *this;
    }
    Want &SetElement(const AppExecFwk::ElementName &element)
    {
        return *this;
    }

    AppExecFwk::ElementName GetElement() const
    {
        AppExecFwk::ElementName element;
        return element;
    }

    Uri GetUri() const
    {
        Uri uri;
        return uri;
    }

    std::string GetUriString() const
    {
        return "";
    }

    std::string GetAction() const
    {
        return "";
    }

    Want &SetAction(const std::string &action)
    {
        return *this;
    }
    
    std::string GetBundle() const
    {
        return "";
    }

    Want &SetBundle(const std::string &bundleName)
    {
        return *this;
    }

    Want &AddEntity(const std::string &entity)
    {
        return *this;
    }

    const WantParams &GetParams() const
    {
        return parameters_;
    }

    bool GetBoolParam(const std::string &key, bool defaultValue) const
    {
        return false;
    }

    int GetIntParam(const std::string &key, int defaultValue) const
    {
        return 0;
    }

    Want &SetParam(const std::string &key, int value)
    {
        return *this;
    }

    Want &SetParam(const std::string &key, bool value)
    {
        return *this;
    }

    Want &SetParam(const std::string &key, const std::string &value)
    {
        return *this;
    }

    Want &SetParam(const std::string& key, const sptr<IRemoteObject>& remoteObject)
    {
        return *this;
    }

    Want &SetParams(const WantParams &wantParams)
    {
        return *this;
    }

    std::string GetStringParam(const std::string &key) const
    {
        return "";
    }

    bool HasParameter(const std::string &key) const
    {
        return false;
    }

    void RemoveParam(const std::string &key) {}
    std::string ToString() const
    {
        return "";
    }
    Want &SetDeviceId(const std::string &deviceId)
    {
        return *this;
    }

    std::string GetDeviceId() const
    {
        return "";
    }

    Want &SetModuleName(const std::string &moduleName)
    {
        return *this;
    }

public:
    // reserved param definition
    inline static const std::string PARAM_RESV_DISPLAY_ID = "";
    inline static const std::string PARAM_RESV_WINDOW_FOCUSED = "";
    inline static const std::string PARAM_RESV_WINDOW_LEFT = "";
    inline static const std::string PARAM_RESV_WINDOW_TOP = "";
    inline static const std::string PARAM_RESV_WINDOW_WIDTH = "";
    inline static const std::string PARAM_RESV_WINDOW_HEIGHT = "";
    inline static const std::string PARAM_RESV_CALLER_TOKEN = "";
    inline static const std::string PARAM_RESV_CALLER_BUNDLE_NAME = "";
    inline static const std::string PARAM_RESV_CALLER_ABILITY_NAME = "";
    inline static const std::string PARAM_RESV_CALLER_NATIVE_NAME = "";
    inline static const std::string PARAM_RESV_CALLER_UID = "";
    inline static const std::string PARAM_RESV_FOR_RESULT = "";
    inline static const std::string PARAM_RESV_START_TIME = "";
    inline static const std::string PARAM_ABILITY_RECOVERY_RESTART = "";
    inline static const std::string PARAM_ASSERT_FAULT_SESSION_ID = "";
    inline static const std::string PARM_LAUNCH_REASON_MESSAGE = "";
    inline static const std::string PARAM_APP_AUTO_STARTUP_LAUNCH_REASON = "";
    inline static const std::string PARAM_APP_CLONE_INDEX_KEY = "";
    inline static const std::string APP_INSTANCE_KEY = "";
    inline static const std::string CREATE_APP_INSTANCE_KEY = "";

    WantParams parameters_;
};
}  // namespace AAFwk
}  // namespace OHOS
#endif