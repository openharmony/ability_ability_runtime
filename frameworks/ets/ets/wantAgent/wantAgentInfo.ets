/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Want from '@ohos.app.ability.Want';
import wantAgent from '@ohos.app.ability.wantAgent';
import type abilityWantAgent from '@ohos.app.ability.wantAgent';

export interface WantAgentInfo {
  wants: Array<Want>;
  operationType?: wantAgent.OperationType;
  actionType?: abilityWantAgent.OperationType;
  requestCode: number;
  wantAgentFlags?: Array<wantAgent.WantAgentFlags>;
  actionFlags?: Array<abilityWantAgent.WantAgentFlags>;
  extraInfo?: Record<string,Object>;
  extraInfos?: Record<string, Object>;
}

class WantAgentInfoImpl implements WantAgentInfo {
  public wants: Array<Want>;
  public operationType?: wantAgent.OperationType;
  public actionType?: abilityWantAgent.OperationType;
  public requestCode: number;
  public wantAgentFlags?: Array<wantAgent.WantAgentFlags>;
  public actionFlags?: Array<abilityWantAgent.WantAgentFlags>;
  public extraInfo?: Record<string,Object>;
  public extraInfos?: Record<string, Object>;
}
