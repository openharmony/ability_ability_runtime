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
import { RecordData } from '@ohos.base';

export interface WantAgentInfo {
  wants: Array<Want>;
  actionType?: abilityWantAgent.OperationType;
  requestCode: int;
  actionFlags?: Array<abilityWantAgent.WantAgentFlags>;
  extraInfo?: Record<string, RecordData>;
  extraInfos?: Record<string, RecordData>;
}

class WantAgentInfoImpl implements WantAgentInfo {
  public wants: Array<Want>;
  public actionType?: abilityWantAgent.OperationType;
  public requestCode: int;
  public actionFlags?: Array<abilityWantAgent.WantAgentFlags>;
  public extraInfo?: Record<string, RecordData>;
  public extraInfos?: Record<string, RecordData>;

  constructor(wants: Array<Want>) {
    this.wants = wants;
  }
}

export interface LocalWantAgentInfo {
  wants: Array<Want>;
  operationType?: abilityWantAgent.OperationType;
  requestCode: int;
}
