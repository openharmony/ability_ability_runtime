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

import rpc from '@ohos.rpc';
import Want from '@ohos.app.ability.Want';
import AppServiceExtensionContext from 'application.AppServiceExtensionContext';
import ExtensionAbility from '@ohos.app.ability.ExtensionAbility';
import hilog from '@ohos.hilog';
import { AbilityUtils } from './utils/AbilityUtils';

class MyService extends rpc.RemoteObject {
  constructor(descriptor: string) {
    super(descriptor);
  }
}

export default class AppServiceExtensionAbility extends ExtensionAbility {

  public context: AppServiceExtensionContext = {};

  onCreate(want: Want): void{
  }

  onDestroy(): void{
  }

  onRequest(want: Want, startId: int): void{
  }

  onConnect(want: Want): rpc.RemoteObject{
    let myService: rpc.RemoteObject = new MyService('onConnect');
    return myService;
  }

  onDisconnect(want: Want): void{
  }
}