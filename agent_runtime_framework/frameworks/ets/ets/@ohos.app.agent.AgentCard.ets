/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

export interface Provider {
  organization: string;
  url: string;
}

class ProviderImpl implements Provider {
  public organization: string = '';
  public url: string = '';
}

export interface Capabilities {
  streaming: boolean;
  pushNotifications?: boolean;
  stateTransitionHistory?: boolean;
}

class CapabilitiesImpl implements Capabilities {
  public streaming: boolean;
  public pushNotifications?: boolean;
  public stateTransitionHistory?: boolean;
}

export interface Skill {
  id: string;
  name: string;
  description: string;
  tags: Array<string>;
  examples?: Array<string>;
  inputModes?: Array<string>;
  outputModes?: Array<string>;
  extension?: string;
}

class SkillImpl implements Skill {
  public id: string = '';
  public name: string = '';
  public description: string = '';
  public tags: Array<string> = {};
  public examples?: Array<string>;
  public inputModes?: Array<string>;
  public outputModes?: Array<string>;
  public extension?: string;
}

export interface AgentCard {
  agentId: string;
  bundleName: string;
  moduleName: string;
  abilityName: string;
  appIndex: int;
  name: string;
  description: string;
  provider?: Provider;
  version: string;
  documentationUrl?: string;
  capabilities: Capabilities;
  defaultInputModes?: Array<string>;
  defaultOutputModes?: Array<string>;
  skills?: Array<Skill>;
  extension?: string;
  category?: string;
  iconUrl?: string;
}

class AgentCardImpl implements AgentCard {
  public agentId: string = '';
  public bundleName: string = '';
  public moduleName: string = '';
  public abilityName: string = '';
  public appIndex: int;
  public name: string = '';
  public description: string = '';
  public provider?: Provider;
  public version: string = '';
  public documentationUrl?: string;
  public capabilities: Capabilities = new CapabilitiesImpl() as Capabilities;
  public defaultInputModes?: Array<string>;
  public defaultOutputModes?: Array<string>;
  public skills?: Array<Skill>;
  public extension?: string;
  public category?: string;
  public iconUrl?: string;
}