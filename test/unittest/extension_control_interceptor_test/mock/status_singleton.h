/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_ABILITY_ABILITY_RUNTIME_TEST_UNITTEST_EXTENSION_CONTROL_INTERCEPTOR_TEST_MOCK_STATUS_SINGLETON_H
#define FOUNDATION_ABILITY_ABILITY_RUNTIME_TEST_UNITTEST_EXTENSION_CONTROL_INTERCEPTOR_TEST_MOCK_STATUS_SINGLETON_H

#include <string>
#include <mutex>
#include <memory>

namespace OHOS {
namespace AAFwk {

/**
 * @class StatusSingleton
 * Singleton class that holds static member variables representing the status of extension configuration
 * for testing purposes.
 */
class StatusSingleton {
public:
    /**
     * Get the singleton instance.
     *
     * @return The singleton instance of StatusSingleton.
     */
    static StatusSingleton& GetInstance()
    {
        static StatusSingleton instance;
        return instance;
    }

    // Delete copy constructor and assignment operator
    StatusSingleton(const StatusSingleton&) = delete;
    StatusSingleton& operator=(const StatusSingleton&) = delete;

    // Static member variables corresponding to the boolean functions in mock_extension_config.cpp
    bool isExtensionStartThirdPartyAppEnable_;
    bool isExtensionStartServiceEnable_;
    bool isExtensionStartThirdPartyAppEnableNew_;
    bool isExtensionStartServiceEnableNew_;
    bool isExtensionStartDefaultEnable_;
    bool isExtensionNetworkEnable_;
    bool isExtensionSAEnable_;
    bool isExtensionAbilityAccessEnable_;
    bool checkExtensionUriValid_;
    bool findTargetUriInList_;
    bool readFileInfoJson_;
    bool hasAbilityAccess_;
    bool hasThridPartyAppAccessFlag_;
    bool hasServiceAccessFlag_;
    bool hasDefaultAccessFlag_;
    void SetExtensionStartThirdPartyAppEnable(bool value)
    {
        isExtensionStartThirdPartyAppEnable_ = value;
    }

    void SetExtensionStartServiceEnable(bool value)
    {
        isExtensionStartServiceEnable_ = value;
    }

    void SetExtensionStartThirdPartyAppEnableNew(bool value)
    {
        isExtensionStartThirdPartyAppEnableNew_ = value;
    }

    void SetExtensionStartServiceEnableNew(bool value)
    {
        isExtensionStartServiceEnableNew_ = value;
    }

    void SetExtensionStartDefaultEnable(bool value)
    {
        isExtensionStartDefaultEnable_ = value;
    }

    void SetExtensionNetworkEnable(bool value)
    {
        isExtensionNetworkEnable_ = value;
    }

    void SetExtensionSAEnable(bool value)
    {
        isExtensionSAEnable_ = value;
    }

    void SetExtensionAbilityAccessEnable(bool value)
    {
        isExtensionAbilityAccessEnable_ = value;
    }

    void SetCheckExtensionUriValid(bool value)
    {
        checkExtensionUriValid_ = value;
    }

    void SetFindTargetUriInList(bool value)
    {
        findTargetUriInList_ = value;
    }

    void SetReadFileInfoJson(bool value)
    {
        readFileInfoJson_ = value;
    }

    void SetHasAbilityAccess(bool value)
    {
        hasAbilityAccess_ = value;
    }

    void SetHasThridPartyAppAccessFlag(bool value)
    {
        hasThridPartyAppAccessFlag_ = value;
    }

    void SetHasServiceAccessFlag(bool value)
    {
        hasServiceAccessFlag_ = value;
    }

    void SetHasDefaultAccessFlag(bool value)
    {
        hasDefaultAccessFlag_ = value;
    }

    // Reset all static members to default values
    void Reset()
    {
        isExtensionStartThirdPartyAppEnable_ = false;
        isExtensionStartServiceEnable_ = false;
        isExtensionStartThirdPartyAppEnableNew_ = false;
        isExtensionStartServiceEnableNew_ = false;
        isExtensionStartDefaultEnable_ = false;
        isExtensionNetworkEnable_ = false;
        isExtensionSAEnable_ = false;
        isExtensionAbilityAccessEnable_ = false;
        checkExtensionUriValid_ = false;
        findTargetUriInList_ = false;
        readFileInfoJson_ = false;
        hasAbilityAccess_ = false;
        hasThridPartyAppAccessFlag_ = false;
        hasServiceAccessFlag_ = false;
        hasDefaultAccessFlag_ = false;
    }

private:
    // Private constructor to ensure singleton pattern
    StatusSingleton()
    {
        Reset();
    }
};
} // namespace AAFwk
} // namespace OHOS

#endif // FOUNDATION_ABILITY_ABILITY_RUNTIME_TEST_UNITTEST_EXTENSION_CONTROL_INTERCEPTOR_TEST_MOCK_STATUS_SINGLETON_H