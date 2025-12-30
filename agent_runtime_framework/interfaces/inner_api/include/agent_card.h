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

#ifndef OHOS_AGENT_RUNTIME_AGENT_CARD_H
#define OHOS_AGENT_RUNTIME_AGENT_CARD_H

#include <string>
#include <vector>

#include "parcel.h"

namespace OHOS {
namespace AgentRuntime {
struct Provider : public Parcelable {
    std::string organization;
    std::string url;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static Provider *Unmarshalling(Parcel &parcel);
};

struct Capabilities : public Parcelable {
    // optional param
    bool streaming;
    // optional param
    bool pushNotifications;
    // optional param
    bool stateTransitionHistory;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static Capabilities *Unmarshalling(Parcel &parcel);
};

struct Authentication : public Parcelable {
    std::vector<std::string> schemes;
    // optional param
    std::string credentials;
    bool ReadFromParcel(Parcel &parcel);

    virtual bool Marshalling(Parcel &parcel) const override;
    static Authentication *Unmarshalling(Parcel &parcel);
};

struct Skill : public Parcelable {
    std::string id;
    std::string name;
    std::string description;
    std::vector<std::string> tags;
    // optional param
    std::vector<std::string> examples;
    // optional param
    std::vector<std::string> inputModes;
    // optional param
    std::vector<std::string> outputModes;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static Skill *Unmarshalling(Parcel &parcel);
};

struct AgentCard : public Parcelable {
    std::string name;
    std::string description;
    std::string url;
    // optional param
    Provider provider;
    std::string version;
    // optional param
    std::string documentationUrl;
    Capabilities capabilities;
    Authentication authentication;
    std::vector<std::string> defaultInputModes;
    std::vector<std::string> defaultOutputModes;
    std::vector<Skill> skills;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static AgentCard *Unmarshalling(Parcel &parcel);
};
} // AgentRuntime
} // OHOS
#endif // OHOS_AGENT_RUNTIME_AGENT_CARD_H